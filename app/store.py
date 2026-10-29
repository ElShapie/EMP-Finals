import base64
import hashlib
import json
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

ALLOWED_PERMISSIONS = {"consulta", "mantenimiento", "admin", "registros", "usuarios", "roles", "nfc", "respaldo"}
DEFAULT_ROLE_PERMISSIONS = {
    "superadmin": {"consulta", "mantenimiento", "admin", "registros", "usuarios", "roles", "nfc", "respaldo"},
    "admin": {"consulta", "mantenimiento", "admin", "registros", "usuarios", "roles", "nfc", "respaldo"},
    "mantenimiento": {"consulta", "mantenimiento"},
    "auditor": {"consulta", "registros"},
    "consulta": {"consulta"},
    "sin_acceso": set(),
}
# Permisos que se agregan una sola vez a los roles existentes al actualizar la app.
ROLE_PERMISSIONS_MIGRATIONS = {
    "admin": {"usuarios", "roles", "nfc", "respaldo"},
    "superadmin": {"respaldo"},
}
PERMISSIONS = DEFAULT_ROLE_PERMISSIONS
ROLES = set(PERMISSIONS)
PROTECTED_SUPERADMINS = {"emp-001@securityteam.com", "emp-004@securityteam.com", "emp-010@securityteam.com"}
USER_IMPORT_FIELDS = ("userName", "displayName", "department", "employeeNumber", "title", "active", "extraPermissions")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def normalize_uid(value):
    """Normaliza un UID de tarjeta a hexadecimal mayúsculo sin separadores."""
    if not isinstance(value, str):
        return ""
    cleaned = re.sub(r"[\s:\-_]", "", value).upper()
    if not cleaned or not re.fullmatch(r"[0-9A-F]+", cleaned) or len(cleaned) % 2:
        return ""
    return cleaned


def uid_variants(value):
    """Devuelve el UID normalizado y su orden inverso.

    Los lectores contactless entregan el UID en orden inverso (LSB primero) según
    el estándar ISO 14443-3, mientras que las herramientas suelen mostrarlo en
    orden natural. Aceptar ambos evita registrar dos veces la misma tarjeta.
    """
    cleaned = normalize_uid(value)
    if not cleaned:
        return []
    pairs = [cleaned[index:index + 2] for index in range(0, len(cleaned), 2)]
    reversed_uid = "".join(reversed(pairs))
    return [cleaned] if reversed_uid == cleaned else [cleaned, reversed_uid]


class Store:
    def __init__(self, path, secret=None):
        self.path = str(path)
        self.secret = secret or os.environ.get("APP_SECRET", "")
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, payload TEXT NOT NULL, oidc_sub TEXT UNIQUE)")
            db.execute("CREATE TABLE IF NOT EXISTS events (time TEXT NOT NULL, user TEXT NOT NULL, action TEXT NOT NULL, result TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS nfc_cards (uid TEXT PRIMARY KEY, username TEXT NOT NULL, label TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS nfc_taps (id INTEGER PRIMARY KEY AUTOINCREMENT, uid TEXT NOT NULL, username TEXT NOT NULL, source TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0)")
            db.execute("CREATE TABLE IF NOT EXISTS role_permissions (role TEXT PRIMARY KEY, permissions TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS user_credentials (username TEXT PRIMARY KEY, secret TEXT NOT NULL, updated_at TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS app_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            for role, permissions in DEFAULT_ROLE_PERMISSIONS.items():
                db.execute("INSERT OR IGNORE INTO role_permissions(role,permissions) VALUES(?,?)", (role, json.dumps(sorted(permissions))))
        self._migrate_role_permissions()

    def _migrate_role_permissions(self):
        """Agrega los permisos nuevos a instalaciones que ya tenían la matriz guardada."""
        with self.connect() as db:
            if db.execute("SELECT 1 FROM app_meta WHERE key='role_permissions_v2'").fetchone():
                return
            for role, extra in ROLE_PERMISSIONS_MIGRATIONS.items():
                row = db.execute("SELECT permissions FROM role_permissions WHERE role=?", (role,)).fetchone()
                if not row:
                    continue
                permissions = set(json.loads(row["permissions"])) | extra
                db.execute("UPDATE role_permissions SET permissions=? WHERE role=?", (json.dumps(sorted(permissions)), role))
            db.execute("INSERT OR REPLACE INTO app_meta(key,value) VALUES('role_permissions_v2','1')")


    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def resource(row):
        return json.loads(row["payload"]) if row else None

    def get(self, user_id):
        with self.connect() as db:
            return self.resource(db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone())

    def by_name(self, username):
        with self.connect() as db:
            return self.resource(db.execute("SELECT * FROM users WHERE username=?", (username.strip().lower(),)).fetchone())

    def all(self):
        with self.connect() as db:
            return [self.resource(row) for row in db.execute("SELECT * FROM users ORDER BY username")]

    def roles(self):
        with self.connect() as db:
            configured = {row["role"]: set(json.loads(row["permissions"])) for row in db.execute("SELECT role,permissions FROM role_permissions")}
        return {**DEFAULT_ROLE_PERMISSIONS, **configured}

    def set_role_permissions(self, role, permissions):
        if role not in DEFAULT_ROLE_PERMISSIONS or not isinstance(permissions, (list, set, tuple)):
            raise ValueError("Rol o permisos no válidos")
        allowed = ALLOWED_PERMISSIONS
        if not set(permissions).issubset(allowed):
            raise ValueError("Permisos desconocidos")
        if role == "superadmin" and not {"usuarios", "roles"}.issubset(set(permissions)):
            raise ValueError("El rol superadmin debe conservar los permisos de usuarios y roles")
        with self.connect() as db:
            db.execute("INSERT INTO role_permissions(role,permissions) VALUES(?,?) ON CONFLICT(role) DO UPDATE SET permissions=excluded.permissions", (role, json.dumps(sorted(set(permissions)))))
        self.event("sistema", "ROLE_PERMISSIONS_UPDATE:" + role, "OK")

    def _prepare(self, data):
        """Valida y normaliza un perfil; se usa al guardar y al validar respaldos."""
        username = str(data.get("userName", "")).strip().lower()
        if "@" not in username or username.startswith("@") or username.endswith("@"):
            raise ValueError("userName debe ser un correo")
        role = str(data.get("title", "sin_acceso"))
        if role not in self.roles():
            raise ValueError("title debe ser un rol conocido")
        if (role == "superadmin") != (username in PROTECTED_SUPERADMINS):
            raise ValueError("El rol superadmin se reserva para DPO, RRHH y Responsable de TI")
        active = data.get("active", True)
        if isinstance(active, str) and active.lower() in ("true", "false"):
            active = active.lower() == "true"
        if not isinstance(active, bool):
            raise ValueError("active debe ser true o false")
        extras = data.get("extraPermissions", [])
        if isinstance(extras, str):
            extras = [extras]
        if not isinstance(extras, (list, tuple, set)):
            raise ValueError("extraPermissions debe ser una lista de permisos")
        extras = {str(item).strip() for item in extras if str(item).strip()}
        if not extras.issubset(ALLOWED_PERMISSIONS):
            raise ValueError("Permisos adicionales desconocidos")
        data.update({"userName": username, "title": role, "active": active, "extraPermissions": sorted(extras)})
        return data

    def save(self, payload, user_id=None):
        if not isinstance(payload, dict):
            raise ValueError("El recurso debe ser un objeto JSON")
        previous = self.get(user_id) if user_id else None
        data = dict(previous or {})
        data.update(payload)
        data = self._prepare(data)
        data.update({"id": user_id or str(uuid.uuid4())})
        data.setdefault("schemas", ["urn:ietf:params:scim:schemas:core:2.0:User"])
        data["meta"] = {"resourceType": "User", "lastModified": utc_now()}
        with self.connect() as db:
            if previous:
                db.execute("UPDATE users SET username=?,payload=? WHERE id=?", (data["userName"], json.dumps(data), user_id))
            else:
                db.execute("INSERT INTO users(id,username,payload) VALUES(?,?,?)", (data["id"], data["userName"], json.dumps(data)))
        self.event(data["id"], "SCIM_CREATE" if previous is None else "SCIM_UPDATE", "OK")
        return data

    def deactivate(self, user_id):
        previous = self.get(user_id)
        if not previous:
            return False
        self.save({"active": False}, user_id)
        self.event(user_id, "SCIM_DEACTIVATE", "OK")
        return True

    def bind_identity(self, user_id, subject):
        with self.connect() as db:
            row = db.execute("SELECT oidc_sub FROM users WHERE id=?", (user_id,)).fetchone()
            if row is None or (row["oidc_sub"] and row["oidc_sub"] != subject):
                return False
            try:
                db.execute("UPDATE users SET oidc_sub=? WHERE id=?", (subject, user_id))
            except sqlite3.IntegrityError:
                return False
        return True

    def permissions_for(self, user):
        """Permisos efectivos: los del rol más los adicionales asignados a la persona."""
        if not user:
            return set()
        permissions = set(self.roles().get(user.get("title"), set()))
        permissions.update(str(item) for item in user.get("extraPermissions") or [])
        return permissions

    def permitted(self, user_id, action):
        user = self.get(user_id)
        return bool(user and user.get("active") is True and action in self.permissions_for(user))

    def event(self, user, action, result):
        with self.connect() as db:
            db.execute("INSERT INTO events VALUES(?,?,?,?)", (utc_now(), user, action, result))
            db.execute("DELETE FROM events WHERE rowid NOT IN (SELECT rowid FROM events ORDER BY rowid DESC LIMIT 500)")

    def events(self):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM events ORDER BY rowid DESC LIMIT 100")]

    # --- Credenciales NFC (badge de acceso) ---

    def register_card(self, uid, username, label=""):
        normalized = normalize_uid(uid)
        if not normalized:
            raise ValueError("UID de tarjeta inválido")
        username = str(username).strip().lower()
        if "@" not in username:
            raise ValueError("El usuario del badge debe ser un correo")
        with self.connect() as db:
            db.execute(
                "INSERT INTO nfc_cards(uid,username,label,created_at) VALUES(?,?,?,?) "
                "ON CONFLICT(uid) DO UPDATE SET username=excluded.username,label=excluded.label",
                (normalized, username, str(label or ""), utc_now()),
            )
        self.event("nfc:" + normalized, "NFC_CARD_REGISTER", "OK")
        return self.card(normalized)

    def card(self, uid):
        normalized = normalize_uid(uid)
        if not normalized:
            return None
        with self.connect() as db:
            for variant in uid_variants(normalized):
                row = db.execute("SELECT * FROM nfc_cards WHERE uid=?", (variant,)).fetchone()
                if row:
                    return dict(row)
        return None

    def cards(self):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM nfc_cards ORDER BY created_at, uid")]

    def remove_card(self, uid):
        normalized = normalize_uid(uid)
        if not normalized:
            return False
        with self.connect() as db:
            removed = db.execute("DELETE FROM nfc_cards WHERE uid=?", (normalized,)).rowcount > 0
        if removed:
            self.event("nfc:" + normalized, "NFC_CARD_REMOVE", "OK")
        return removed

    def record_tap(self, uid, username, source=""):
        """Deja un toque pendiente para que el navegador lo consuma al iniciar sesión."""
        with self.connect() as db:
            db.execute(
                "INSERT INTO nfc_taps(uid,username,source,created_at,consumed) VALUES(?,?,?,?,0)",
                (str(uid), str(username), str(source or ""), utc_now()),
            )
        return True

    def clear_taps(self):
        """Descarta los toques pendientes.

        Se usa al cerrar sesion: si no, un toque leido antes del cierre se quedaria
        guardado y la pantalla de acceso lo consumiria al volver a arrancar el polling,
        reabriendo la sesion sin que el usuario vuelva a pasar la tarjeta.
        """
        with self.connect() as db:
            removed = db.execute("DELETE FROM nfc_taps WHERE consumed=0").rowcount
        return removed

    def claim_tap(self, ttl_seconds=15):
        """Reserva el toque más antiguo dentro de la ventana TTL; lo consume una sola vez."""
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=int(ttl_seconds))).isoformat()
        with self.connect() as db:
            row = db.execute(
                "SELECT id FROM nfc_taps WHERE consumed=0 AND created_at>=? ORDER BY id LIMIT 1",
                (cutoff,),
            ).fetchone()
            if row is None:
                return None
            reserved = db.execute("UPDATE nfc_taps SET consumed=1 WHERE id=? AND consumed=0", (row["id"],)).rowcount
            if not reserved:
                return None
            tap = db.execute("SELECT * FROM nfc_taps WHERE id=?", (row["id"],)).fetchone()
            db.execute("DELETE FROM nfc_taps WHERE created_at<?", (cutoff,))
            return dict(tap) if tap else None

    # --- Credenciales de los usuarios (necesarias para abrir sesión por badge) ---

    def _fernet(self):
        if not self.secret:
            raise ValueError("Falta APP_SECRET para cifrar las credenciales")
        key = base64.urlsafe_b64encode(hashlib.sha256(self.secret.encode("utf-8")).digest())
        return Fernet(key)

    @staticmethod
    def _credential_name(username):
        name = str(username or "").strip().lower()
        if "@" not in name:
            raise ValueError("La credencial debe pertenecer a un correo")
        return name

    def set_credential(self, username, password):
        name = self._credential_name(username)
        if not isinstance(password, str) or len(password) < 8:
            raise ValueError("La contraseña debe tener al menos 8 caracteres")
        token = self._fernet().encrypt(password.encode("utf-8")).decode("ascii")
        with self.connect() as db:
            db.execute(
                "INSERT INTO user_credentials(username,secret,updated_at) VALUES(?,?,?) "
                "ON CONFLICT(username) DO UPDATE SET secret=excluded.secret, updated_at=excluded.updated_at",
                (name, token, utc_now()),
            )
        return True

    def credential(self, username):
        try:
            name = self._credential_name(username)
        except ValueError:
            return None
        with self.connect() as db:
            row = db.execute("SELECT secret FROM user_credentials WHERE username=?", (name,)).fetchone()
        if not row:
            return None
        try:
            return self._fernet().decrypt(row["secret"].encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError):
            return None

    def credential_usernames(self):
        with self.connect() as db:
            return {row["username"] for row in db.execute("SELECT username FROM user_credentials")}

    def remove_credential(self, username):
        try:
            name = self._credential_name(username)
        except ValueError:
            return False
        with self.connect() as db:
            return db.execute("DELETE FROM user_credentials WHERE username=?", (name,)).rowcount > 0

    def credentials(self):
        with self.connect() as db:
            rows = [dict(row) for row in db.execute("SELECT username,secret FROM user_credentials ORDER BY username")]
        exported = []
        for row in rows:
            try:
                password = self._fernet().decrypt(row["secret"].encode("ascii")).decode("utf-8")
            except (InvalidToken, ValueError):
                continue
            exported.append({"userName": row["username"], "password": password})
        return exported

    # --- Respaldo e importación de la base local ---

    def export_bundle(self):
        """Devuelve un respaldo portable con identidades, permisos, tarjetas y credenciales."""
        return {
            "app": "identity-access-lab",
            "version": 1,
            "exportedAt": utc_now(),
            "users": self.all(),
            "rolePermissions": {role: sorted(permissions) for role, permissions in self.roles().items()},
            "cards": self.cards(),
            "credentials": self.credentials(),
        }

    def validate_bundle(self, bundle):
        """Valida el respaldo completo antes de escribir nada en la base."""
        if not isinstance(bundle, dict):
            raise ValueError("El respaldo debe ser un objeto JSON")
        if bundle.get("app") != "identity-access-lab" or bundle.get("version") != 1:
            raise ValueError("El archivo no es un respaldo de Identity Access Lab versión 1")
        users = bundle.get("users")
        if not isinstance(users, list) or not users:
            raise ValueError("El respaldo no contiene usuarios")
        if len(users) > 5000:
            raise ValueError("El respaldo supera el máximo de 5000 usuarios")
        seen = set()
        for item in users:
            if not isinstance(item, dict):
                raise ValueError("Cada usuario del respaldo debe ser un objeto")
            name = str(item.get("userName", "")).strip().lower()
            if name in seen:
                raise ValueError("Hay correos duplicados en el respaldo: " + name)
            seen.add(name)
            current = self.by_name(name)
            data = dict(current or {})
            data.update({key: item[key] for key in USER_IMPORT_FIELDS if key in item})
            self._prepare(data)
        cards = bundle.get("cards", [])
        if not isinstance(cards, list):
            raise ValueError("La lista de tarjetas del respaldo no es válida")
        seen_uids = set()
        for card in cards:
            if not isinstance(card, dict):
                raise ValueError("Cada tarjeta del respaldo debe ser un objeto")
            uid = normalize_uid(card.get("uid", ""))
            if not uid or "@" not in str(card.get("username", "")):
                raise ValueError("Tarjeta inválida en el respaldo")
            if str(card.get("username", "")).strip().lower() not in seen:
                raise ValueError("La tarjeta " + uid + " no pertenece a ningún usuario del respaldo")
            if uid in seen_uids:
                raise ValueError("Hay UID duplicados en el respaldo: " + uid)
            seen_uids.add(uid)
        credentials = bundle.get("credentials", [])
        if not isinstance(credentials, list):
            raise ValueError("La lista de credenciales del respaldo no es válida")
        for credential in credentials:
            if not isinstance(credential, dict):
                raise ValueError("Credencial inválida en el respaldo")
            name = str(credential.get("userName", "")).strip().lower()
            if name not in seen:
                raise ValueError("La credencial " + name + " no pertenece a ningún usuario del respaldo")
            password = credential.get("password")
            if not isinstance(password, str) or len(password) < 8:
                raise ValueError("Contraseña inválida para " + name)
        matrix = bundle.get("rolePermissions", {})
        if not isinstance(matrix, dict):
            raise ValueError("La matriz de permisos del respaldo no es válida")
        for role, permissions in matrix.items():
            if role not in DEFAULT_ROLE_PERMISSIONS or not isinstance(permissions, list) or not set(permissions).issubset(ALLOWED_PERMISSIONS):
                raise ValueError("Rol o permisos inválidos en el respaldo: " + str(role))
        return True

    def import_bundle(self, bundle, mode="merge"):
        """Importa un respaldo validado. ``merge`` conserva lo existente; ``replace`` lo reemplaza."""
        self.validate_bundle(bundle)
        if mode not in ("merge", "replace"):
            raise ValueError("Modo de importación no válido")
        imported = set()
        for item in bundle["users"]:
            payload = {key: item[key] for key in USER_IMPORT_FIELDS if key in item}
            name = str(item["userName"]).strip().lower()
            current = self.by_name(name)
            self.save(payload, current["id"] if current else None)
            imported.add(name)
        if mode == "replace":
            for user in self.all():
                if user["userName"] not in imported and user.get("active"):
                    self.save({"active": False}, user["id"])
            with self.connect() as db:
                db.execute("DELETE FROM nfc_cards")
                db.execute("DELETE FROM user_credentials")
        for card in bundle.get("cards", []):
            self.register_card(card["uid"], card["username"], card.get("label", ""))
        credential_names = set()
        for credential in bundle.get("credentials", []):
            name = str(credential["userName"]).strip().lower()
            if not self.by_name(name):
                continue
            self.set_credential(name, credential["password"])
            credential_names.add(name)
        if mode == "replace":
            for name in self.credential_usernames() - credential_names:
                self.remove_credential(name)
        for role, permissions in bundle.get("rolePermissions", {}).items():
            self.set_role_permissions(role, permissions)
        self.event("sistema", "BACKUP_IMPORT:" + mode, "OK")
        return {"users": len(imported), "cards": len(bundle.get("cards", [])), "credentials": len(credential_names)}



import hmac
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import quote, urlparse

import requests
from authlib.integrations.flask_client import OAuth
from flask import Flask, abort, jsonify, redirect, render_template, request, session

from app.store import ALLOWED_PERMISSIONS, Store, normalize_uid

DEMO_PASSWORD_VARS = {
    "ingeniero@example.test": "DEMO_PASSWORD_ENGINEER",
    "auditor@example.test": "DEMO_PASSWORD_AUDITOR",
    "admin@example.test": "DEMO_PASSWORD_ADMIN",
    "rrhh@example.test": "DEMO_PASSWORD_RRHH",
    "ti@example.test": "DEMO_PASSWORD_TI",
    "iam@example.test": "DEMO_PASSWORD_IAM",
    "soc-auditoria@example.test": "DEMO_PASSWORD_SOC_AUDITORIA",
    "seguridad-fisica@example.test": "DEMO_PASSWORD_SEGURIDAD_FISICA",
}


def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ["APP_SECRET"]
    app.config.update(
        SESSION_COOKIE_NAME="identity_access_lab_session",
        SESSION_COOKIE_SECURE=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    )
    base = os.environ.get("APP_BASE_URL", "http://localhost:8000").rstrip("/")
    scim_token = os.environ["SCIM_TOKEN"]
    if len(app.secret_key) < 32 or len(scim_token) < 32 or not base.startswith(("http://localhost", "http://192.168.", "http://10.", "http://172.", "https://")):
        raise RuntimeError("Configura secretos de 32+ caracteres y APP_BASE_URL localhost HTTP o HTTPS")
    app.config["SESSION_COOKIE_SECURE"] = base.startswith("https://")
    store = Store(os.environ.get("APP_DB", "data/lab.sqlite"))
    oauth = OAuth(app)
    oauth.register(
        name="idp",
        client_id=os.environ["OIDC_CLIENT_ID"],
        client_secret=os.environ["OIDC_CLIENT_SECRET"],
        server_metadata_url=os.environ["OIDC_METADATA_URL"],
        client_kwargs={"scope": "openid profile email"},
    )

    @app.context_processor
    def inject_permissions():
        uid = session.get("uid")
        current = store.get(uid) if uid else None
        return {
            "role_permissions": store.roles(),
            "effective_permissions": store.permissions_for(current) if current else set(),
            "all_permissions": sorted(ALLOWED_PERMISSIONS),
        }

    # --- Acceso con badge NFC (opcional) ---
    nfc_enabled = os.environ.get("NFC_ENABLED", "false").lower() in ("1", "true", "yes", "on")
    nfc_token = os.environ.get("NFC_BRIDGE_TOKEN", "")
    nfc_login_username = os.environ.get("NFC_LOGIN_USERNAME", "").strip().lower()
    nfc_login_password = os.environ.get("NFC_LOGIN_PASSWORD", "")
    nfc_tap_ttl = max(5, int(os.environ.get("NFC_TAP_TTL_SECONDS", "15")))
    if nfc_enabled and len(nfc_token) < 32:
        raise RuntimeError("NFC_BRIDGE_TOKEN debe tener 32 caracteres o más para habilitar el acceso NFC")

    def badge_credentials(username):
        """Devuelve (usuario, contraseña) guardados en el entorno para el titular del badge."""
        username = str(username or "").strip().lower()
        if not username:
            return None
        if username == nfc_login_username and nfc_login_password:
            return username, nfc_login_password
        stored = store.credential(username)
        if stored:
            return username, stored
        directory_file = Path(os.environ.get("DIRECTORY_ACCOUNTS_FILE", "/srv/directory/accounts.json"))
        try:
            for account in json.loads(directory_file.read_text(encoding="utf-8")):
                if account.get("userName", "").strip().lower() == username and account.get("password"):
                    return username, account["password"]
        except (OSError, ValueError, TypeError):
            pass
        explicit = "NFC_PASSWORD_" + re.sub(r"[^A-Z0-9]+", "_", username.upper()).strip("_")
        if os.environ.get(explicit):
            return username, os.environ[explicit]
        demo_var = DEMO_PASSWORD_VARS.get(username)
        if demo_var and os.environ.get(demo_var):
            return username, os.environ[demo_var]
        return None

    def badge_sign_in(username):
        """Abre sesión en Keycloak con las credenciales guardadas del usuario del badge."""
        credentials = badge_credentials(username)
        if not credentials:
            return None, "No hay credenciales guardadas para " + username
        metadata_url = os.environ.get("OIDC_INTERNAL_METADATA_URL") or os.environ["OIDC_METADATA_URL"]
        metadata = {}
        try:
            metadata = requests.get(metadata_url, timeout=5).json()
        except (requests.RequestException, ValueError):
            metadata = {}
        # La metadata declara los endpoints con el host publico (localhost:8081), que no
        # resuelve dentro de la red de Compose. Se usan las direcciones internas, igual que
        # hace el proxy /oidc/metadata.
        internal_base = os.environ.get("OIDC_INTERNAL_BASE_URL", "").rstrip("/")
        token_endpoint = internal_base + "/token" if internal_base else metadata.get("token_endpoint")
        userinfo_endpoint = internal_base + "/userinfo" if internal_base else metadata.get("userinfo_endpoint")
        if not token_endpoint:
            return None, "El proveedor OIDC local no expone un endpoint de token"
        try:
            token_response = requests.post(
                token_endpoint,
                data={
                    "grant_type": "password",
                    "client_id": os.environ["OIDC_CLIENT_ID"],
                    "client_secret": os.environ["OIDC_CLIENT_SECRET"],
                    "username": credentials[0],
                    "password": credentials[1],
                    "scope": "openid profile email",
                },
                timeout=10,
            )
        except (requests.RequestException, ValueError, KeyError) as error:
            app.logger.warning("Fallo al pedir token del badge: %s", error)
            return None, "El proveedor OIDC local no está disponible"
        if not token_response.ok:
            return None, "El proveedor OIDC local rechazó el acceso del badge"
        payload = token_response.json()
        access_token = payload.get("access_token")
        if not access_token:
            return None, "El proveedor OIDC local no devolvió token"
        identity = payload.get("userinfo") or {}
        if not userinfo_endpoint:
            userinfo_endpoint = metadata.get("userinfo_endpoint")
        if userinfo_endpoint:
            try:
                userinfo = requests.get(userinfo_endpoint, headers={"Authorization": "Bearer " + access_token}, timeout=10)
                if userinfo.ok:
                    identity = userinfo.json()
            except (requests.RequestException, ValueError):
                identity = payload.get("userinfo") or {}
        subject = identity.get("sub")
        email = identity.get("email")
        if not subject or not email:
            return None, "El proveedor OIDC local devolvió una identidad incompleta"
        user = store.by_name(email)
        if not user or not user.get("active"):
            return None, "El usuario local no está disponible"
        if not store.bind_identity(user["id"], str(subject)):
            return None, "La identidad ya está vinculada a otra cuenta"
        session.clear()
        session["uid"] = user["id"]
        session["csrf"] = secrets.token_urlsafe(32)
        session.permanent = True
        store.event(user["id"], "LOGIN_NFC", "PERMITIDO")
        return user, None

    def scim_auth(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            expected = "Bearer " + scim_token
            if not hmac.compare_digest(request.headers.get("Authorization", ""), expected):
                return scim_error("No autorizado", 401)
            return fn(*args, **kwargs)
        return wrapped

    def _check_csrf():
        if request.method == "POST":
            body = request.get_json(silent=True) or {}
            supplied_csrf = request.form.get("csrf", "") or request.headers.get("X-CSRF-Token", "") or str(body.get("csrf", ""))
            if not hmac.compare_digest(supplied_csrf, session.get("csrf", "")):
                abort(400)

    def require(action):
        def decorate(fn):
            @wraps(fn)
            def wrapped(*args, **kwargs):
                uid = session.get("uid")
                if not uid:
                    return redirect("/login")
                required_action = "mantenimiento" if request.endpoint == "api_shift_change" and request.method == "POST" else action
                if not store.permitted(uid, required_action):
                    store.event(uid, required_action, "DENEGADO")
                    abort(403)
                _check_csrf()
                store.event(uid, required_action, "PERMITIDO")
                return fn(*args, **kwargs)
            return wrapped
        return decorate

    def require_any(*actions):
        """Exige al menos uno de los permisos indicados (por ejemplo, crear o asignar permisos)."""
        def decorate(fn):
            @wraps(fn)
            def wrapped(*args, **kwargs):
                uid = session.get("uid")
                if not uid:
                    return redirect("/login")
                if not any(store.permitted(uid, action) for action in actions):
                    store.event(uid, "|".join(actions), "DENEGADO")
                    abort(403)
                _check_csrf()
                store.event(uid, "|".join(actions), "PERMITIDO")
                return fn(*args, **kwargs)
            return wrapped
        return decorate

    def scim_error(detail, status):
        return jsonify({"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "detail": detail, "status": str(status)}), status

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.get("/oidc/metadata")
    def oidc_metadata():
        """Descubre Keycloak desde la red Docker y usa URL internas para llamadas del servidor."""
        url = os.environ.get("OIDC_INTERNAL_METADATA_URL")
        if not url:
            return scim_error("Proxy de metadata local no configurado", 404)
        try:
            data = requests.get(url, timeout=5).json()
        except requests.RequestException:
            return jsonify(error="Proveedor OIDC local no disponible"), 503
        internal = os.environ.get("OIDC_INTERNAL_BASE_URL", "").rstrip("/")
        for key, suffix in (("token_endpoint", "/token"), ("userinfo_endpoint", "/userinfo"), ("jwks_uri", "/certs")):
            data[key] = internal + suffix
        return jsonify(data)

    @app.get("/")
    def home():
        uid = session.get("uid")
        user = store.get(uid) if uid else None
        if user and not user.get("active"):
            session.clear()
            user = None
        if not user:
            session.setdefault("csrf", secrets.token_urlsafe(32))
            return render_template("dashboard.html", title="Acceso", page="login", user=None, users=[], csrf=session["csrf"], nfc_enabled=nfc_enabled)
        session.setdefault("csrf", secrets.token_urlsafe(32))
        return render_template("dashboard.html", title="Resumen", page="home", user=user, users=[], csrf=session["csrf"], nfc_enabled=nfc_enabled)

    @app.get("/login")
    def login():
        if request.host != urlparse(base).netloc:
            return redirect(base + "/login")
        return oauth.idp.authorize_redirect(base + "/auth/callback", prompt="login")

    @app.get("/auth/callback")
    def callback():
        try:
            token = oauth.idp.authorize_access_token()
            identity = token.get("userinfo") or oauth.idp.userinfo(token=token)
            if not identity or not identity.get("sub") or not identity.get("email"):
                abort(403)
            user = store.by_name(identity["email"])
            if not user or not user.get("active") or not store.bind_identity(user["id"], str(identity["sub"])):
                store.event("desconocido", "LOGIN", "DENEGADO")
                abort(403)
            session.clear()
            session["uid"] = user["id"]
            session["csrf"] = secrets.token_urlsafe(32)
            session.permanent = True
            store.event(user["id"], "LOGIN_OIDC", "PERMITIDO")
            return redirect("/")
        except Exception:
            app.logger.exception("Inicio OIDC rechazado o incompleto")
            abort(403)

    @app.get("/consulta")
    @require("consulta")
    def consultation():
        return render_template("dashboard.html", title="Consulta", page="consultation", user=store.get(session["uid"]), users=[], csrf=session.get("csrf"))

    @app.post("/mantenimiento")
    @require("mantenimiento")
    def maintenance():
        return render_template("dashboard.html", title="Mantenimiento", page="maintenance", user=store.get(session["uid"]), users=[], csrf=session.get("csrf"))

    @app.post("/admin")
    @require("admin")
    def administration():
        return render_template("dashboard.html", title="Administración", page="administration", user=store.get(session["uid"]), users=[], csrf=session.get("csrf"))

    @app.get("/registros")
    @require("registros")
    def records():
        return render_template("dashboard.html", title="Bitácora", page="events", user=store.get(session["uid"]), users=[], events=store.events(), csrf=session.get("csrf"))

    @app.get("/turno")
    @require("consulta")
    def shift_change():
        user = store.get(session["uid"]) if session.get("uid") else None
        return render_template(
            "cambio_turno.html",
            title="Cambio de Turno",
            page="turno",
            user=user,
            csrf=session.get("csrf"),
        )

    @app.route("/api/turno", methods=["GET", "POST"])
    @require("consulta")
    def api_shift_change():
        if request.method == "POST":
            payload = request.get_json(silent=True) or request.form.to_dict() or {}
            user = store.get(session["uid"])
            shift = str(payload.get("shift", "tarde")).strip().lower()
            status = str(payload.get("status", "success")).strip().lower()
            if shift not in {"mañana", "tarde", "noche"} or status not in {"success", "warning", "danger"}:
                return jsonify(error="Turno o estado no válido"), 400
            cams = payload.get("cams", [])
            if not isinstance(cams, list) or any(not isinstance(cam, str) for cam in cams):
                return jsonify(error="Lista de cámaras no válida"), 400
            action_desc = f"TURNO_{shift.upper()}"
            if cams:
                action_desc += " [CAMS: " + ", ".join(cams[:10]) + "]"
            result_label = "CONFORME" if status == "success" else ("ADVERTENCIA" if status == "warning" else "INCIDENCIA")
            store.event(user.get("userName", session["uid"]), action_desc, result_label)
            return jsonify(ok=True)
        return jsonify(events=store.events())

    @app.post("/nfc/tap")
    def nfc_tap():
        """El puente NFC del host envía el UID leído; la app decide si la tarjeta está autorizada."""
        if not nfc_enabled:
            return jsonify(error="El acceso NFC está deshabilitado"), 404
        if not hmac.compare_digest(request.headers.get("Authorization", ""), "Bearer " + nfc_token):
            return jsonify(error="No autorizado"), 401
        payload = request.get_json(silent=True) or {}
        uid = str(payload.get("uid", ""))
        card = store.card(uid)
        if not card:
            store.event("nfc:" + (uid or "?"), "NFC_TAP", "DENEGADO")
            return jsonify(error="Tarjeta no registrada"), 403
        user = store.by_name(card["username"])
        if not user or not user.get("active"):
            store.event("nfc:" + card["uid"], "NFC_TAP", "DENEGADO")
            return jsonify(error="Usuario no disponible"), 403
        store.record_tap(card["uid"], card["username"], str(payload.get("source", "bridge")))
        return jsonify(accepted=True, user=card["username"])

    @app.post("/nfc/poll")
    def nfc_poll():
        """El navegador pregunta si hay un toque pendiente y, si lo hay, abre sesión con el badge."""
        if not nfc_enabled:
            return jsonify(login=False)
        payload = request.get_json(silent=True) or {}
        csrf = str(payload.get("csrf", ""))
        if not hmac.compare_digest(csrf.encode("utf-8"), str(session.get("csrf", "")).encode("utf-8")):
            return jsonify(error="Token CSRF inválido"), 400
        tap = store.claim_tap(nfc_tap_ttl)
        if not tap:
            return jsonify(login=False)
        if session.get("uid"):
            # Ya hay una sesion abierta: el toque se descarta en lugar de guardarse, para
            # que no reabra el acceso por si solo cuando el usuario cierre la sesion.
            store.event("nfc:" + tap["uid"], "NFC_TAP_DESCARTADO", "OK")
            return jsonify(login=False)
        user, error = badge_sign_in(tap["username"])
        if not user:
            store.event("nfc:" + tap["uid"], "LOGIN_NFC", "DENEGADO")
            return jsonify(login=False, error=error), 401
        return jsonify(login=True, user=user["userName"])

    @app.get("/nfc")
    @require("nfc")
    def nfc_admin():
        return render_template(
            "dashboard.html",
            title="Badge NFC",
            page="nfc",
            user=store.get(session["uid"]),
            users=store.all(),
            cards=store.cards(),
            csrf=session.get("csrf"),
            nfc_enabled=nfc_enabled,
            nfc_ttl=nfc_tap_ttl,
        )

    @app.post("/nfc/tarjetas")
    @require("nfc")
    def nfc_card_create():
        try:
            store.register_card(request.form.get("uid", ""), request.form.get("username", ""), request.form.get("label", ""))
        except ValueError as error:
            return redirect("/nfc?error=" + quote(str(error)))
        return redirect("/nfc")

    @app.post("/nfc/tarjetas/eliminar")
    @require("nfc")
    def nfc_card_delete():
        store.remove_card(request.form.get("uid", ""))
        return redirect("/nfc")

    def _render_user_secret(created_user, password, card=None, title="Credencial temporal"):
        return render_template(
            "dashboard.html",
            title=title,
            page="new_user_secret",
            user=store.get(session["uid"]),
            created_user=created_user,
            initial_password=password,
            linked_card=card,
            csrf=session["csrf"],
        )

    @app.get("/admin/usuarios")
    @require_any("usuarios", "roles")
    def admin_users():
        uid = session["uid"]
        cards = store.cards()
        cards_by_user = {}
        for card in cards:
            cards_by_user.setdefault(card["username"], []).append(card)
        return render_template(
            "dashboard.html",
            title="Usuarios",
            page="users",
            user=store.get(uid),
            users=store.all(),
            roles=store.roles(),
            cards_by_user=cards_by_user,
            card_count=len(cards),
            credential_users=store.credential_usernames(),
            can_users=store.permitted(uid, "usuarios"),
            can_roles=store.permitted(uid, "roles"),
            can_nfc=store.permitted(uid, "nfc"),
            csrf=session["csrf"],
        )

    @app.post("/admin/usuarios")
    @require("usuarios")
    def admin_user_create():
        from app.provision_directory import create_keycloak_user, generate_password
        uid = session["uid"]
        can_roles = store.permitted(uid, "roles")
        payload = {key: request.form.get(key, "").strip() for key in ("userName", "displayName", "department", "employeeNumber")}
        payload["active"] = request.form.get("active", "true") == "true"
        payload["title"] = request.form.get("title", "consulta") if can_roles else "consulta"
        payload["extraPermissions"] = request.form.getlist("extraPermissions") if can_roles else []
        nfc_uid = request.form.get("nfc_uid", "").strip()
        nfc_label = request.form.get("nfc_label", "").strip()
        password = request.form.get("password", "")
        if not password:
            password = generate_password()
        try:
            if not payload["userName"] or not payload["displayName"]:
                raise ValueError("Nombre y correo son obligatorios")
            if len(password) < 8:
                raise ValueError("La contraseña debe tener al menos 8 caracteres")
            if nfc_uid and not normalize_uid(nfc_uid):
                raise ValueError("El UID de la tarjeta no es válido")
            if store.by_name(payload["userName"]):
                raise ValueError("Ya existe una cuenta con ese correo")
            create_keycloak_user(payload, password)
            user = store.save(payload)
            store.set_credential(user["userName"], password)
            card = store.register_card(nfc_uid, user["userName"], nfc_label) if nfc_uid else None
        except ValueError as error:
            return redirect("/admin/usuarios?error=" + quote(str(error)))
        except RuntimeError as error:
            return redirect("/admin/usuarios?error=" + quote(str(error)))
        except requests.RequestException:
            return "Keycloak no está disponible para crear la identidad", 503
        store.event(uid, "USER_CREATE:" + user["userName"], "OK")
        return _render_user_secret(user, password, card)

    @app.post("/admin/usuarios/<user_id>/rol")
    @require("roles")
    def admin_user_role(user_id):
        target = store.get(user_id)
        if not target:
            abort(404)
        try:
            store.save(
                {"title": request.form.get("title", ""), "extraPermissions": request.form.getlist("extraPermissions")},
                user_id,
            )
        except ValueError:
            abort(400)
        store.event(session["uid"], "USER_ROLE_CHANGE:" + target["userName"], "OK")
        return redirect("/admin/usuarios")

    @app.post("/admin/usuarios/<user_id>/estado")
    @require("usuarios")
    def admin_user_status(user_id):
        target = store.get(user_id)
        if not target:
            abort(404)
        active = request.form.get("active") == "true"
        if target["id"] == session["uid"] and not active:
            return redirect("/admin/usuarios?error=" + quote("No puedes dar de baja tu propia cuenta"))
        store.save({"active": active}, user_id)
        store.event(session["uid"], "USER_STATUS_CHANGE:" + target["userName"], "OK")
        return redirect("/admin/usuarios")

    @app.post("/admin/usuarios/<user_id>/credencial")
    @require("usuarios")
    def admin_user_credential(user_id):
        from app.provision_directory import create_keycloak_user, generate_password
        target = store.get(user_id)
        if not target:
            abort(404)
        password = request.form.get("password", "")
        if not password:
            password = generate_password()
        try:
            if len(password) < 8:
                raise ValueError("La contraseña debe tener al menos 8 caracteres")
            create_keycloak_user(target, password)
            store.set_credential(target["userName"], password)
        except ValueError as error:
            return redirect("/admin/usuarios?error=" + quote(str(error)))
        except RuntimeError as error:
            return redirect("/admin/usuarios?error=" + quote(str(error)))
        except requests.RequestException:
            return "Keycloak no está disponible para actualizar la credencial", 503
        store.event(session["uid"], "USER_CREDENTIAL_RESET:" + target["userName"], "OK")
        return _render_user_secret(target, password, title="Credencial actualizada")

    @app.post("/admin/usuarios/<user_id>/tarjeta")
    @require("nfc")
    def admin_user_card(user_id):
        target = store.get(user_id)
        if not target:
            abort(404)
        uid = request.form.get("uid", "")
        try:
            if request.form.get("action") == "remove":
                store.remove_card(uid)
            else:
                store.register_card(uid, target["userName"], request.form.get("label", ""))
        except ValueError as error:
            return redirect("/admin/usuarios?error=" + quote(str(error)))
        store.event(session["uid"], "USER_CARD_CHANGE:" + target["userName"], "OK")
        return redirect("/admin/usuarios")

    @app.get("/admin/roles")
    @require("roles")
    def admin_roles():
        return render_template("dashboard.html", title="Permisos por rol", page="roles", user=store.get(session["uid"]), roles=store.roles(), csrf=session["csrf"])

    @app.post("/admin/roles/<role>")
    @require("roles")
    def admin_role_permissions(role):
        try:
            permissions = request.form.getlist("permissions")
            if role == "superadmin":
                raise ValueError("Los permisos superadmin son fijos y no se pueden reducir desde la aplicación")
            store.set_role_permissions(role, permissions)
        except ValueError:
            abort(400)
        store.event(session["uid"], "ROLE_CONFIG_CHANGE:" + role, "OK")
        return redirect("/admin/roles")

    @app.get("/admin/respaldo")
    @require("respaldo")
    def admin_backup():
        return render_template(
            "dashboard.html",
            title="Respaldo",
            page="backup",
            user=store.get(session["uid"]),
            counts={
                "users": len(store.all()),
                "cards": len(store.cards()),
                "credentials": len(store.credential_usernames()),
            },
            csrf=session["csrf"],
        )

    @app.post("/admin/respaldo/exportar")
    @require("respaldo")
    def admin_backup_export():
        payload = json.dumps(store.export_bundle(), ensure_ascii=False, indent=2)
        filename = "identity-access-respaldo-" + datetime.now().strftime("%Y%m%d-%H%M%S") + ".json"
        response = app.response_class(payload, mimetype="application/json")
        response.headers["Content-Disposition"] = 'attachment; filename="' + filename + '"'
        store.event(session["uid"], "BACKUP_EXPORT", "OK")
        return response

    @app.post("/admin/respaldo/importar")
    @require("respaldo")
    def admin_backup_import():
        from app.provision_directory import create_keycloak_user
        upload = request.files.get("file")
        mode = request.form.get("mode", "merge")
        if not upload or not upload.filename:
            return redirect("/admin/respaldo?error=" + quote("Selecciona un archivo de respaldo JSON"))
        try:
            bundle = json.loads(upload.read().decode("utf-8"))
            store.validate_bundle(bundle)
        except (ValueError, UnicodeDecodeError) as error:
            return redirect("/admin/respaldo?error=" + quote(str(error)))
        credentials = {str(item["userName"]).strip().lower(): item["password"] for item in bundle.get("credentials", [])}
        try:
            for item in bundle["users"]:
                password = credentials.get(str(item.get("userName", "")).strip().lower())
                if password:
                    create_keycloak_user(item, password)
            result = store.import_bundle(bundle, mode)
        except (ValueError, RuntimeError) as error:
            return redirect("/admin/respaldo?error=" + quote(str(error)))
        except requests.RequestException:
            return redirect("/admin/respaldo?error=" + quote("Keycloak no está disponible; no se importó nada"))
        store.event(session["uid"], "BACKUP_IMPORT:" + mode, "OK")
        message = "Importados {users} usuarios, {cards} tarjetas y {credentials} credenciales"
        return redirect("/admin/respaldo?ok=" + quote(message.format(**result)))

    @app.post("/logout")
    def logout():
        if not session.get("uid") or not hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", "")):
            abort(400)
        store.event(session["uid"], "LOGOUT_APP", "OK")
        # Los toques leidos antes del cierre se descartan: si no quedaran guardados, la
        # pantalla de acceso los consumiria al reiniciar el polling y volveria a abrir
        # sesion sin que el usuario pase la tarjeta de nuevo.
        store.clear_taps()
        session.clear()
        return redirect("/")

    @app.route("/scim/v2/Users", methods=["GET", "POST"])
    @scim_auth
    def scim_users():
        if request.method == "GET":
            query = request.args.get("filter", "")
            if query:
                match = re.fullmatch(r'userName\s+eq\s+"([^"]+)"', query, re.IGNORECASE)
                if not match:
                    return scim_error('Solo se admite userName eq "correo"', 400)
                found = store.by_name(match.group(1))
                resources = [found] if found else []
            else:
                resources = store.all()
            start = max(1, request.args.get("startIndex", 1, type=int))
            count = max(0, min(100, request.args.get("count", 100, type=int)))
            page = resources[start - 1:start - 1 + count]
            return jsonify(schemas=["urn:ietf:params:scim:api:messages:2.0:ListResponse"], totalResults=len(resources), startIndex=start, itemsPerPage=len(page), Resources=page)
        try:
            result = store.save(request.get_json(force=True))
            response = jsonify(result)
            response.status_code = 201
            response.headers["Location"] = base + "/scim/v2/Users/" + result["id"]
            return response
        except sqlite3.IntegrityError:
            return scim_error("Usuario duplicado", 409)
        except (ValueError, TypeError):
            return scim_error("Datos no válidos", 400)

    @app.route("/scim/v2/Users/<user_id>", methods=["GET", "PUT", "PATCH", "DELETE"])
    @scim_auth
    def scim_user(user_id):
        current = store.get(user_id)
        if not current:
            return scim_error("Usuario no encontrado", 404)
        if request.method == "GET":
            return jsonify(current)
        if request.method == "DELETE":
            store.deactivate(user_id)
            return "", 204
        try:
            payload = request.get_json(force=True)
            if request.method == "PATCH":
                changes = {}
                if not isinstance(payload, dict) or not isinstance(payload.get("Operations"), list):
                    return scim_error("PATCH requiere Operations", 400)
                for operation in payload["Operations"]:
                    if not isinstance(operation, dict) or operation.get("op", "").lower() not in ("replace", "add"):
                        return scim_error("Operación PATCH no admitida", 400)
                    path = operation.get("path")
                    value = operation.get("value")
                    if path in ("active", "title", "userName"):
                        changes[path] = value
                    elif path is None and isinstance(value, dict):
                        changes.update(value)
                    else:
                        return scim_error("Ruta PATCH no admitida", 400)
                payload = changes
            return jsonify(store.save(payload, user_id))
        except sqlite3.IntegrityError:
            return scim_error("Usuario duplicado", 409)
        except (ValueError, TypeError):
            return scim_error("Datos no válidos", 400)

    @app.get("/scim/v2/Groups")
    @scim_auth
    def scim_groups():
        return jsonify(schemas=["urn:ietf:params:scim:api:messages:2.0:ListResponse"], totalResults=0, startIndex=1, itemsPerPage=0, Resources=[])

    return app


app = create_app()


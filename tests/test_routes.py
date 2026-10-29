import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

TEST_ROOT = Path(__file__).resolve().parent
os.environ.setdefault("APP_SECRET", "unit-test-secret-that-is-long-enough-123456")
os.environ.setdefault("SCIM_TOKEN", "unit-test-scim-token-that-is-long-enough-123456")
os.environ.setdefault("APP_BASE_URL", "http://localhost:8000")
os.environ.setdefault("OIDC_CLIENT_ID", "identity-access-app")
os.environ.setdefault("OIDC_CLIENT_SECRET", "unit-test-oidc-client-secret")
os.environ.setdefault("OIDC_METADATA_URL", "http://127.0.0.1:8000/oidc/metadata")
os.environ.setdefault("APP_DB", str(TEST_ROOT / ".import-test.sqlite"))

from app.store import Store
from app.wsgi import create_app

BRIDGE_TOKEN = "unit-test-nfc-bridge-token-long-enough-1234"


def fake_response(payload, ok=True):
    response = MagicMock()
    response.ok = ok
    response.status_code = 200 if ok else 401
    response.json.return_value = payload
    return response


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=TEST_ROOT)
        self.db_path = str(Path(self.temp.name) / "app.sqlite")
        self.previous_db = os.environ.get("APP_DB")
        os.environ["APP_DB"] = self.db_path
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.store = Store(self.db_path)
        self.user = self.store.save({"userName": "ingeniero@example.test", "title": "mantenimiento"})

    def tearDown(self):
        if self.previous_db is None:
            os.environ.pop("APP_DB", None)
        else:
            os.environ["APP_DB"] = self.previous_db
        self.temp.cleanup()

    def test_health_is_available(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"status": "ok"})

    def test_scim_requires_bearer_token(self):
        self.assertEqual(self.client.get("/scim/v2/Users").status_code, 401)

    def test_scim_list_and_patch_update_local_access(self):
        headers = {"Authorization": "Bearer " + os.environ["SCIM_TOKEN"]}
        listed = self.client.get("/scim/v2/Users", headers=headers)
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.json["totalResults"], 1)
        response = self.client.patch(
            "/scim/v2/Users/" + self.user["id"],
            headers=headers,
            json={"Operations": [{"op": "replace", "path": "active", "value": False}]},
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.store.permitted(self.user["id"], "consulta"))

    def test_protected_page_redirects_when_anonymous(self):
        response = self.client.get("/consulta")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_admin_role_manages_users_permissions_and_backups(self):
        admin = self.store.save({"userName": "iam@example.test", "title": "admin"})
        with self.client.session_transaction() as session:
            session["uid"] = admin["id"]
            session["csrf"] = "csrf-test"
        self.assertEqual(self.client.get("/admin/usuarios").status_code, 200)
        self.assertEqual(self.client.get("/admin/roles").status_code, 200)
        self.assertEqual(self.client.get("/admin/respaldo").status_code, 200)

    def test_rrhh_creates_and_deactivates_but_cannot_assign_permissions(self):
        rrhh = self.store.save({"userName": "rrhh@example.test", "title": "consulta", "extraPermissions": ["usuarios", "nfc"]})
        target = self.store.save({"userName": "nuevo@example.test", "title": "consulta"})
        with self.client.session_transaction() as session:
            session["uid"] = rrhh["id"]
            session["csrf"] = "csrf-test"
        self.assertEqual(self.client.get("/admin/usuarios").status_code, 200)
        self.assertEqual(self.client.get("/admin/roles").status_code, 403)
        denied = self.client.post(
            "/admin/usuarios/" + target["id"] + "/rol",
            data={"csrf": "csrf-test", "title": "admin"},
        )
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(self.store.get(target["id"])["title"], "consulta")
        changed = self.client.post(
            "/admin/usuarios/" + target["id"] + "/estado",
            data={"csrf": "csrf-test", "active": "false"},
        )
        self.assertEqual(changed.status_code, 302)
        self.assertFalse(self.store.get(target["id"])["active"])

    @patch("app.provision_directory.create_keycloak_user")
    def test_rrhh_created_user_ignores_privileged_fields_and_links_card(self, keycloak):
        rrhh = self.store.save({"userName": "rrhh@example.test", "title": "consulta", "extraPermissions": ["usuarios", "nfc"]})
        with self.client.session_transaction() as session:
            session["uid"] = rrhh["id"]
            session["csrf"] = "csrf-test"
        response = self.client.post(
            "/admin/usuarios",
            data={
                "csrf": "csrf-test",
                "displayName": "Nueva Persona",
                "userName": "nueva@example.test",
                "department": "Operaciones",
                "employeeNumber": "EMP-200",
                "password": "Clave-Nueva-2026!",
                "active": "true",
                "title": "admin",
                "extraPermissions": ["roles", "respaldo"],
                "nfc_uid": "0F:C7:28:C9",
                "nfc_label": "Badge de acceso",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Clave-Nueva-2026!", response.get_data(as_text=True))
        created = self.store.by_name("nueva@example.test")
        self.assertEqual(created["title"], "consulta")
        self.assertEqual(created["extraPermissions"], [])
        self.assertEqual(self.store.credential("nueva@example.test"), "Clave-Nueva-2026!")
        self.assertEqual(self.store.card("0FC728C9")["username"], "nueva@example.test")
        keycloak.assert_called_once()

    def test_soc_changes_roles_and_extra_permissions_but_cannot_create_users(self):
        soc = self.store.save({"userName": "soc-auditoria@example.test", "title": "auditor", "extraPermissions": ["roles"]})
        target = self.store.save({"userName": "objetivo@example.test", "title": "consulta"})
        with self.client.session_transaction() as session:
            session["uid"] = soc["id"]
            session["csrf"] = "csrf-test"
        self.assertEqual(self.client.get("/admin/usuarios").status_code, 200)
        self.assertEqual(self.client.get("/admin/roles").status_code, 200)
        changed = self.client.post(
            "/admin/usuarios/" + target["id"] + "/rol",
            data={"csrf": "csrf-test", "title": "mantenimiento", "extraPermissions": ["nfc"]},
        )
        self.assertEqual(changed.status_code, 302)
        updated = self.store.get(target["id"])
        self.assertEqual(updated["title"], "mantenimiento")
        self.assertEqual(updated["extraPermissions"], ["nfc"])
        denied = self.client.post(
            "/admin/usuarios",
            data={"csrf": "csrf-test", "displayName": "Otra", "userName": "otra@example.test", "title": "consulta"},
        )
        self.assertEqual(denied.status_code, 403)

    @patch("app.provision_directory.create_keycloak_user")
    def test_backup_export_and_import_round_trip(self, keycloak):
        admin = self.store.save({"userName": "iam@example.test", "title": "admin"})
        self.store.set_credential("iam@example.test", "Clave-Admin-2026!")
        self.store.register_card("0FC728C9", "iam@example.test", "Badge IAM")
        with self.client.session_transaction() as session:
            session["uid"] = admin["id"]
            session["csrf"] = "csrf-test"
        exported = self.client.post("/admin/respaldo/exportar", data={"csrf": "csrf-test"})
        self.assertEqual(exported.status_code, 200)
        self.assertEqual(exported.mimetype, "application/json")
        self.assertIn("attachment", exported.headers["Content-Disposition"])
        bundle = json.loads(exported.get_data(as_text=True))
        self.assertEqual(bundle["app"], "identity-access-lab")
        self.assertEqual(bundle["credentials"][0]["password"], "Clave-Admin-2026!")
        exported_iam = next(item for item in bundle["users"] if item["userName"] == "iam@example.test")
        exported_iam["displayName"] = "Nombre restaurado"
        imported = self.client.post(
            "/admin/respaldo/importar",
            data={
                "csrf": "csrf-test",
                "mode": "merge",
                "file": (io.BytesIO(json.dumps(bundle).encode("utf-8")), "respaldo.json"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(imported.status_code, 302)
        self.assertIn("ok=", imported.headers["Location"])
        self.assertEqual(self.store.by_name("iam@example.test")["displayName"], "Nombre restaurado")
        self.assertEqual(self.store.credential("iam@example.test"), "Clave-Admin-2026!")
        self.assertEqual(self.store.card("0FC728C9")["username"], "iam@example.test")


class NfcRouteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=TEST_ROOT)
        self.db_path = str(Path(self.temp.name) / "app.sqlite")
        self.previous_db = os.environ.get("APP_DB")
        self.previous_env = {key: os.environ.get(key) for key in ("NFC_ENABLED", "NFC_BRIDGE_TOKEN", "NFC_LOGIN_USERNAME", "NFC_LOGIN_PASSWORD")}
        os.environ["APP_DB"] = self.db_path
        os.environ["NFC_ENABLED"] = "true"
        os.environ["NFC_BRIDGE_TOKEN"] = BRIDGE_TOKEN
        os.environ["NFC_LOGIN_USERNAME"] = "EMP-010@securityteam.com"
        os.environ["NFC_LOGIN_PASSWORD"] = "unit-test-badge-password"
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.store = Store(self.db_path)
        self.admin = self.store.save({"userName": "EMP-010@securityteam.com", "title": "superadmin"})
        self.legacy_admin = self.store.save({"userName": "admin@example.test", "title": "auditor"})
        self.headers = {"Authorization": "Bearer " + BRIDGE_TOKEN}

    def tearDown(self):
        for key, value in self.previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        if self.previous_db is None:
            os.environ.pop("APP_DB", None)
        else:
            os.environ["APP_DB"] = self.previous_db
        self.temp.cleanup()

    def test_tap_requires_the_bridge_token(self):
        response = self.client.post("/nfc/tap", json={"uid": "0FC728C9"})
        self.assertEqual(response.status_code, 401)

    def test_unregistered_card_is_rejected(self):
        response = self.client.post("/nfc/tap", headers=self.headers, json={"uid": "AABBCCDD"})
        self.assertEqual(response.status_code, 403)

    def test_inactive_user_card_is_rejected(self):
        self.store.save({"active": False}, self.admin["id"])
        self.store.register_card("0FC728C9", self.admin["userName"])
        response = self.client.post("/nfc/tap", headers=self.headers, json={"uid": "0FC728C9"})
        self.assertEqual(response.status_code, 403)

    def test_registered_card_leaves_a_pending_tap(self):
        self.store.register_card("0FC728C9", "admin@example.test", "Tarjeta admin")
        response = self.client.post("/nfc/tap", headers=self.headers, json={"uid": "0FC728C9"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["accepted"])
        tap = self.store.claim_tap(15)
        self.assertEqual(tap["username"], "admin@example.test")

    def test_poll_without_csrf_is_rejected(self):
        response = self.client.post("/nfc/poll", json={"csrf": "inventado"})
        self.assertEqual(response.status_code, 400)

    def test_poll_without_tap_does_not_log_in(self):
        with self.client.session_transaction() as session:
            session["csrf"] = "csrf-de-prueba"
        response = self.client.post("/nfc/poll", json={"csrf": "csrf-de-prueba"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json["login"])

    def test_poll_opens_session_with_the_stored_badge_credentials(self):
        self.store.register_card("0FC728C9", self.admin["userName"], "Tarjeta Rodrigo")
        self.client.post("/nfc/tap", headers=self.headers, json={"uid": "0FC728C9"})
        with self.client.session_transaction() as session:
            session["csrf"] = "csrf-de-prueba"
        metadata = fake_response({"token_endpoint": "http://keycloak/token", "userinfo_endpoint": "http://keycloak/userinfo"})
        token = fake_response({"access_token": "token-de-prueba"})
        identity = fake_response({"sub": "sub-rodrigo", "email": "EMP-010@securityteam.com"})
        with patch("app.wsgi.requests.get", side_effect=[metadata, identity]), patch("app.wsgi.requests.post", return_value=token) as posted:
            response = self.client.post("/nfc/poll", json={"csrf": "csrf-de-prueba"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["login"])
        self.assertEqual(posted.call_args.kwargs["data"]["grant_type"], "password")
        self.assertEqual(posted.call_args.kwargs["data"]["username"], self.admin["userName"])
        with self.client.session_transaction() as session:
            self.assertEqual(session["uid"], self.admin["id"])

    def test_poll_is_denied_when_the_idp_refuses_the_badge(self):
        self.store.register_card("0FC728C9", "admin@example.test")
        self.client.post("/nfc/tap", headers=self.headers, json={"uid": "0FC728C9"})
        with self.client.session_transaction() as session:
            session["csrf"] = "csrf-de-prueba"
        metadata = fake_response({"token_endpoint": "http://keycloak/token"})
        denied = fake_response({"error": "invalid_grant"}, ok=False)
        with patch("app.wsgi.requests.get", return_value=metadata), patch("app.wsgi.requests.post", return_value=denied):
            response = self.client.post("/nfc/poll", json={"csrf": "csrf-de-prueba"})
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.json["login"])

    def test_nfc_is_disabled_when_the_flag_is_off(self):
        os.environ["NFC_ENABLED"] = "false"
        app = create_app()
        client = app.test_client()
        response = client.post("/nfc/tap", headers=self.headers, json={"uid": "0FC728C9"})
        self.assertEqual(response.status_code, 404)

    def test_badge_page_requires_an_admin_session(self):
        response = self.client.get("/nfc")
        self.assertEqual(response.status_code, 302)

    def test_admin_can_open_the_badge_page_and_register_a_card(self):
        with self.client.session_transaction() as session:
            session["uid"] = self.admin["id"]
            session["csrf"] = "csrf-de-prueba"
        page = self.client.get("/nfc")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Badge NFC", page.get_data(as_text=True))
        created = self.client.post(
            "/nfc/tarjetas",
            data={"csrf": "csrf-de-prueba", "uid": "0F:C7:28:C9", "username": "admin@example.test", "label": "Tarjeta del admin"},
        )
        self.assertEqual(created.status_code, 302)
        card = self.store.card("0FC728C9")
        self.assertIsNotNone(card)
        self.assertEqual(card["username"], "admin@example.test")

    def test_admin_form_rejects_an_invalid_uid(self):
        with self.client.session_transaction() as session:
            session["uid"] = self.admin["id"]
            session["csrf"] = "csrf-de-prueba"
        response = self.client.post(
            "/nfc/tarjetas",
            data={"csrf": "csrf-de-prueba", "uid": "no-es-hex", "username": "admin@example.test"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=", response.headers["Location"])
        self.assertEqual(self.store.cards(), [])

    def test_poll_with_an_open_session_discards_the_tap_instead_of_saving_it(self):
        self.store.register_card("0FC728C9", "admin@example.test", "Tarjeta admin")
        self.client.post("/nfc/tap", headers=self.headers, json={"uid": "0FC728C9"})
        with self.client.session_transaction() as session:
            session["uid"] = self.admin["id"]
            session["csrf"] = "csrf-de-prueba"
        with patch("app.wsgi.requests.post") as posted:
            response = self.client.post("/nfc/poll", json={"csrf": "csrf-de-prueba"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json["login"])
        posted.assert_not_called()
        self.assertIsNone(self.store.claim_tap(15))

    def test_logout_discards_the_pending_taps(self):
        self.store.register_card("0FC728C9", "admin@example.test", "Tarjeta admin")
        self.client.post("/nfc/tap", headers=self.headers, json={"uid": "0FC728C9"})
        with self.client.session_transaction() as session:
            session["uid"] = self.admin["id"]
            session["csrf"] = "csrf-de-prueba"
        response = self.client.post("/logout", data={"csrf": "csrf-de-prueba"})
        self.assertEqual(response.status_code, 302)
        self.assertIsNone(self.store.claim_tap(15))

    def test_a_tap_read_before_logout_does_not_reopen_the_session(self):
        """Regresion: al cerrar sesion la tarjeta no debe volver a entrar sola."""
        self.store.register_card("0FC728C9", "admin@example.test", "Tarjeta admin")
        self.client.post("/nfc/tap", headers=self.headers, json={"uid": "0FC728C9"})
        with self.client.session_transaction() as session:
            session["uid"] = self.admin["id"]
            session["csrf"] = "csrf-de-prueba"
        self.client.post("/logout", data={"csrf": "csrf-de-prueba"})
        access = self.client.get("/")
        self.assertIn("Acceso al laboratorio", access.get_data(as_text=True))
        with self.client.session_transaction() as session:
            csrf = session["csrf"]
        with patch("app.wsgi.requests.post") as posted:
            response = self.client.post("/nfc/poll", json={"csrf": csrf})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json["login"])
        posted.assert_not_called()
        with self.client.session_transaction() as session:
            self.assertNotIn("uid", session)

    def test_shift_change_page_and_api(self):
        """Verifica que la vista de cambio de turno y su API de auditoria funcionen."""
        operator = self.store.save({"userName": "turno@example.test", "title": "mantenimiento"})
        with self.client.session_transaction() as session:
            session["uid"] = operator["id"]
            session["csrf"] = "csrf-turno"
        response = self.client.get("/turno")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Hub de Seguridad", response.get_data(as_text=True))

        api_response = self.client.post("/api/turno", headers={"X-CSRF-Token": "csrf-turno"}, json={
            "operator": "Este nombre se ignora",
            "shift": "tarde",
            "status": "success",
            "cams": ["Cámara 1", "Cámara 2"]
        })
        self.assertEqual(api_response.status_code, 200)
        self.assertTrue(api_response.json["ok"])
        events = self.store.events()
        self.assertTrue(any("TURNO_TARDE" in e["action"] for e in events))


if __name__ == "__main__":
    unittest.main()


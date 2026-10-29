import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.store import Store


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.store = Store(Path(self.temp.name) / "lab.sqlite", secret="unit-test-store-secret-123456")
        self.user = self.store.save({"userName": "ingeniero@example.test", "title": "mantenimiento"})

    def tearDown(self):
        self.temp.cleanup()

    def test_role_permissions_are_least_privilege(self):
        self.assertTrue(self.store.permitted(self.user["id"], "mantenimiento"))
        self.assertFalse(self.store.permitted(self.user["id"], "admin"))

    def test_role_change_applies_to_existing_session_id(self):
        self.store.save({"title": "auditor"}, self.user["id"])
        self.assertFalse(self.store.permitted(self.user["id"], "mantenimiento"))
        self.assertTrue(self.store.permitted(self.user["id"], "registros"))

    def test_deactivation_blocks_existing_session_id(self):
        self.store.save({"active": False}, self.user["id"])
        self.assertFalse(self.store.permitted(self.user["id"], "consulta"))

    def test_unknown_role_is_rejected(self):
        with self.assertRaises(ValueError):
            self.store.save({"title": "superuser"}, self.user["id"])

    def test_identity_cannot_be_rebound(self):
        self.assertTrue(self.store.bind_identity(self.user["id"], "subject-a"))
        self.assertFalse(self.store.bind_identity(self.user["id"], "subject-b"))

    def test_delete_deactivates_instead_of_erasing_audit_identity(self):
        self.assertTrue(self.store.deactivate(self.user["id"]))
        self.assertFalse(self.store.permitted(self.user["id"], "consulta"))
        self.assertEqual(self.store.get(self.user["id"])["active"], False)

    def test_card_is_registered_with_normalized_uid(self):
        card = self.store.register_card("0f:c7:28:c9", "ingeniero@example.test", "Tarjeta de prueba")
        self.assertEqual(card["uid"], "0FC728C9")
        self.assertEqual(card["username"], "ingeniero@example.test")
        self.assertEqual(len(self.store.cards()), 1)

    def test_card_is_found_in_both_byte_orders(self):
        self.store.register_card("0FC728C9", "ingeniero@example.test")
        self.assertIsNotNone(self.store.card("0FC728C9"))
        self.assertIsNotNone(self.store.card("C928C70F"))

    def test_invalid_card_is_rejected(self):
        with self.assertRaises(ValueError):
            self.store.register_card("no-es-hex", "ingeniero@example.test")
        with self.assertRaises(ValueError):
            self.store.register_card("0FC728C9", "sin-correo")

    def test_tap_is_claimed_only_once(self):
        self.store.record_tap("0FC728C9", "ingeniero@example.test")
        tap = self.store.claim_tap(15)
        self.assertIsNotNone(tap)
        self.assertEqual(tap["username"], "ingeniero@example.test")
        self.assertIsNone(self.store.claim_tap(15))

    def test_tap_outside_the_window_is_ignored(self):
        self.store.record_tap("0FC728C9", "ingeniero@example.test")
        self.assertIsNone(self.store.claim_tap(0))

    def test_removed_card_no_longer_matches(self):
        self.store.register_card("0FC728C9", "ingeniero@example.test")
        self.assertTrue(self.store.remove_card("0FC728C9"))
        self.assertIsNone(self.store.card("0FC728C9"))

    def test_superadmin_is_reserved_for_the_three_roster_owners(self):
        owner = self.store.save({"userName": "emp-001@securityteam.com", "title": "superadmin"})
        self.assertTrue(self.store.permitted(owner["id"], "usuarios"))
        with self.assertRaises(ValueError):
            self.store.save({"userName": "other@example.test", "title": "superadmin"})
        with self.assertRaises(ValueError):
            self.store.save({"title": "auditor"}, owner["id"])

    def test_role_permission_changes_apply_to_existing_users(self):
        self.store.set_role_permissions("mantenimiento", ["consulta"])
        self.assertTrue(self.store.permitted(self.user["id"], "consulta"))
        self.assertFalse(self.store.permitted(self.user["id"], "mantenimiento"))

    def test_admin_role_can_manage_users_permissions_and_backups(self):
        admin = self.store.save({"userName": "iam@example.test", "title": "admin"})
        self.assertTrue(self.store.permitted(admin["id"], "admin"))
        self.assertTrue(self.store.permitted(admin["id"], "usuarios"))
        self.assertTrue(self.store.permitted(admin["id"], "roles"))
        self.assertTrue(self.store.permitted(admin["id"], "nfc"))
        self.assertTrue(self.store.permitted(admin["id"], "respaldo"))

    def test_extra_permissions_extend_the_role_without_granting_everything(self):
        soc = self.store.save({"userName": "soc@example.test", "title": "auditor", "extraPermissions": ["roles"]})
        self.assertTrue(self.store.permitted(soc["id"], "roles"))
        self.assertTrue(self.store.permitted(soc["id"], "registros"))
        self.assertFalse(self.store.permitted(soc["id"], "usuarios"))
        self.assertFalse(self.store.permitted(soc["id"], "respaldo"))
        with self.assertRaises(ValueError):
            self.store.save({"extraPermissions": ["inventado"]}, soc["id"])

    def test_credentials_are_encrypted_at_rest(self):
        self.store.set_credential("ingeniero@example.test", "Clave-Engineer-2026!")
        self.assertEqual(self.store.credential("ingeniero@example.test"), "Clave-Engineer-2026!")
        with sqlite3.connect(self.store.path) as db:
            raw = db.execute("SELECT secret FROM user_credentials WHERE username=?", ("ingeniero@example.test",)).fetchone()[0]
        self.assertNotIn("Clave-Engineer-2026!", raw)
        self.assertIn("ingeniero@example.test", self.store.credential_usernames())

    def test_credentials_cannot_be_created_for_non_emails_or_weak_passwords(self):
        with self.assertRaises(ValueError):
            self.store.set_credential("sin-correo", "Clave-Segura-2026!")
        with self.assertRaises(ValueError):
            self.store.set_credential("ingeniero@example.test", "corta")

    def test_export_and_import_round_trip(self):
        self.store.set_credential("ingeniero@example.test", "Clave-Engineer-2026!")
        self.store.register_card("0FC728C9", "ingeniero@example.test", "Badge de prueba")
        bundle = self.store.export_bundle()
        self.assertEqual(bundle["version"], 1)
        self.assertEqual(bundle["cards"][0]["uid"], "0FC728C9")
        self.store.save({"active": False}, self.user["id"])
        self.store.remove_card("0FC728C9")
        self.store.remove_credential("ingeniero@example.test")
        result = self.store.import_bundle(bundle, "merge")
        self.assertEqual(result["users"], 1)
        self.assertTrue(self.store.get(self.user["id"])["active"])
        self.assertEqual(self.store.credential("ingeniero@example.test"), "Clave-Engineer-2026!")
        self.assertEqual(self.store.card("0FC728C9")["username"], "ingeniero@example.test")

    def test_replace_import_deactivates_users_missing_from_the_bundle(self):
        bundle = self.store.export_bundle()
        late = self.store.save({"userName": "tarde@example.test", "title": "consulta"})
        self.store.import_bundle(bundle, "replace")
        self.assertFalse(self.store.get(late["id"])["active"])
        self.assertTrue(self.store.get(self.user["id"])["active"])

    def test_invalid_backup_is_rejected_before_writing(self):
        with self.assertRaises(ValueError):
            self.store.import_bundle({"app": "otra-app", "version": 1, "users": []})
        with self.assertRaises(ValueError):
            self.store.import_bundle({"app": "identity-access-lab", "version": 1, "users": [{"userName": "otra@example.test", "title": "inventado"}]})
        self.assertIsNone(self.store.by_name("otra@example.test"))

    def test_superadmin_must_keep_user_and_role_management(self):
        self.store.save({"userName": "emp-010@securityteam.com", "title": "superadmin"})
        with self.assertRaises(ValueError):
            self.store.set_role_permissions("superadmin", ["consulta", "admin"])


if __name__ == "__main__":
    unittest.main()


"""Provisión de identidades del directorio local en Keycloak."""
import json
import os
import secrets
import string
from pathlib import Path

import requests

ADMIN_URL = os.environ.get("KEYCLOAK_ADMIN_URL", "http://keycloak:8080").rstrip("/")
REALM = os.environ.get("KEYCLOAK_REALM", "identity-access")


def generate_password(length=18):
    alphabet = string.ascii_letters + string.digits + "!@#$%_-"
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in value) and any(c.isupper() for c in value)
                and any(c.isdigit() for c in value) and any(c in "!@#$%_-" for c in value)):
            return value


def _admin_headers():
    username = os.environ.get("KEYCLOAK_ADMIN", "")
    password = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "")
    if not username or not password:
        raise RuntimeError("Configura KEYCLOAK_ADMIN y KEYCLOAK_ADMIN_PASSWORD para aprovisionar Keycloak")
    response = requests.post(
        f"{ADMIN_URL}/realms/master/protocol/openid-connect/token",
        data={"client_id": "admin-cli", "grant_type": "password", "username": username, "password": password}, timeout=15,
    )
    response.raise_for_status()
    return {"Authorization": "Bearer " + response.json()["access_token"], "Content-Type": "application/json"}


def create_keycloak_user(user, password):
    headers = _admin_headers()
    base = f"{ADMIN_URL}/admin/realms/{REALM}/users"
    email = user["userName"].strip().lower()
    found = requests.get(base, headers=headers, params={"username": email, "exact": "true"}, timeout=15)
    found.raise_for_status()
    employee = str(user.get("employeeNumber", ""))
    parts = user.get("displayName", email).split(" ", 1)
    payload = {
        "username": email, "email": email, "emailVerified": True,
        "firstName": parts[0], "lastName": parts[1] if len(parts) > 1 else "",
        "enabled": bool(user.get("active", True)),
        "attributes": {"lab_role": [user.get("title", "consulta")], "department": [user.get("department", "")], "employeeNumber": [employee]},
        "credentials": [{"type": "password", "value": password, "temporary": False}],
    }
    if found.json():
        user_id = found.json()[0]["id"]
        response = requests.put(f"{base}/{user_id}", headers=headers, json=payload, timeout=15)
        response.raise_for_status()
        # Ensure the password is explicitly set on an existing identity too.
        reset = requests.put(f"{base}/{user_id}/reset-password", headers=headers, json=payload["credentials"][0], timeout=15)
        reset.raise_for_status()
    else:
        response = requests.post(base, headers=headers, json=payload, timeout=15)
        if response.status_code not in (201, 204):
            response.raise_for_status()
    return True


def provision_all(path="/srv/directory/accounts.json"):
    directory_path = Path(path)
    if not directory_path.is_file():
        print("No hay padrón privado en .directory; se omite la provisión de empleados")
        return 0
    records = json.loads(directory_path.read_text(encoding="utf-8"))
    for user in records:
        create_keycloak_user(user, user["password"])
    legacy_password = os.environ.get("DEMO_PASSWORD_ADMIN")
    if legacy_password:
        create_keycloak_user({"userName": "admin@example.test", "displayName": "Administrador legado", "department": "IAM", "title": "auditor", "active": True}, legacy_password)
    return len(records) + (1 if legacy_password else 0)


if __name__ == "__main__":
    print(f"Identidades sincronizadas: {provision_all()}")


"""Importa el CSV privado de credenciales a .directory/accounts.json (ignorado por Git)."""
import argparse
import csv
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("csv_file", type=Path, help="CSV privado de credenciales entregado fuera de Git")
parser.add_argument("--output", type=Path, default=ROOT / ".directory" / "accounts.json")
args = parser.parse_args()

records = []
with args.csv_file.open(encoding="utf-8-sig", newline="") as source:
    for row in csv.DictReader(source):
        if not row.get("Correo") or not row.get("Contraseña inicial"):
            raise SystemExit("El CSV necesita las columnas Correo y Contraseña inicial")
        records.append({
            "employeeNumber": row.get("ID", "").strip(),
            "displayName": row.get("Nombre", "").strip(),
            "jobTitle": row.get("Puesto", "").strip(),
            "department": row.get("Departamento", "").strip(),
            "sourceStatus": row.get("Estado", "").strip(),
            "userName": row["Correo"].strip().lower(),
            "title": row.get("Rol demo", "consulta").strip(),
            "active": row.get("Estado", "").strip().lower() == "activo",
            "password": row["Contraseña inicial"],
        })
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
try:
    os.chmod(args.output, 0o600)
except OSError:
    pass
print(f"Importadas {len(records)} cuentas en {args.output}. El archivo contiene contraseñas; no lo compartas ni lo subas a Git.")


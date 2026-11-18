"""Crea en el indexador el usuario de SOLO consulta que usa SARA (RNF-02).

Es una tarea de administración del laboratorio: usa `admin` UNA vez para crear
  - el rol   `sara_solo_alertas`: lectura sobre `wazuh-alerts-*` y nada más;
  - el usuario WAZUH_INDEXER_USER con la clave WAZUH_INDEXER_PASS de .env;
  - la asignación del usuario a ese rol.
SARA nunca usa `admin`; este script vive en lab/, no en backend/.

Usa la API de seguridad del indexador (`_plugins/_security/api`). La documentación
oficial de Wazuh describe la misma operación desde el panel web (rol con permiso
`read` sobre `wazuh-alerts*`); hacerlo por API es una SUPOSICIÓN hasta probarlo.

Uso (desde la raíz del repositorio, con el laboratorio levantado):
    python lab/wazuh/crear_lector.py
Después: cd backend && python -m pytest -m integracion -q    # PR-10
"""
from __future__ import annotations

import base64
import json
import ssl
import sys
import urllib.error
import urllib.request

from _comun import RAIZ, exigir, leer_env

sys.path.insert(0, str(RAIZ / "backend"))
from sara.adaptadores.wazuh.tls import abridor  # noqa: E402  (misma verificación TLS que SARA)

ROL = "sara_solo_alertas"
DEFINICION_ROL = {
    "description": "SARA: solo consulta de alertas (RNF-02)",
    "cluster_permissions": [],
    "index_permissions": [
        {"index_patterns": ["wazuh-alerts-*"], "allowed_actions": ["read"]}
    ],
    "tenant_permissions": [],
}


def main() -> None:
    env = leer_env()
    exigir(env, "WAZUH_ADMIN_PASS", "WAZUH_INDEXER_URL", "WAZUH_INDEXER_USER",
           "WAZUH_INDEXER_PASS", "WAZUH_CA_CERT")
    usuario = env["WAZUH_INDEXER_USER"]
    if usuario == "admin":
        raise SystemExit("WAZUH_INDEXER_USER no puede ser `admin`.")

    url = env["WAZUH_INDEXER_URL"].rstrip("/")
    ca = (RAIZ / env["WAZUH_CA_CERT"]).resolve()
    abrir = abridor(ssl.create_default_context(cafile=str(ca)), env.get("WAZUH_INDEXER_TLS_NOMBRE"))
    auth = "Basic " + base64.b64encode(f"admin:{env['WAZUH_ADMIN_PASS']}".encode()).decode()

    def put(ruta: str, cuerpo: dict) -> None:
        req = urllib.request.Request(
            f"{url}/_plugins/_security/api/{ruta}", data=json.dumps(cuerpo).encode(),
            headers={"Content-Type": "application/json", "Authorization": auth}, method="PUT")
        try:
            with abrir(req, timeout=15) as r:
                print(f"[ok] {ruta}: HTTP {r.status}")
        except urllib.error.HTTPError as e:
            raise SystemExit(f"[error] {ruta}: HTTP {e.code} {e.read().decode(errors='replace')}")

    put(f"roles/{ROL}", DEFINICION_ROL)
    put(f"internalusers/{usuario}", {
        "password": env["WAZUH_INDEXER_PASS"],
        "backend_roles": [],
        "description": "SARA: usuario de solo consulta",
    })
    put(f"rolesmapping/{ROL}", {"users": [usuario]})
    print("Ahora ejecuta la prueba PR-10: cd backend && python -m pytest -m integracion -q")


if __name__ == "__main__":
    sys.exit(main())

"""Pruebas de integración: necesitan el laboratorio de lab/wazuh levantado.

Se ejecutan aparte:  cd backend && python -m pytest -m integracion -q
Si falta la configuración o el indexador no responde, se OMITEN con el motivo a la
vista: una prueba omitida no es una prueba aprobada.
"""
from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

import pytest

from sara.adaptadores.wazuh.tls import abridor

RAIZ_REPO = Path(__file__).resolve().parents[3]
VARIABLES = ("WAZUH_INDEXER_URL", "WAZUH_INDEXER_USER", "WAZUH_INDEXER_PASS", "WAZUH_CA_CERT")
OPCIONALES = ("WAZUH_INDEXER_TLS_NOMBRE",)


def _cargar_env() -> dict[str, str]:
    valores: dict[str, str] = {}
    ruta = RAIZ_REPO / ".env"
    if ruta.exists():
        for linea in ruta.read_text(encoding="utf-8").splitlines():
            linea = linea.strip()
            if linea and not linea.startswith("#") and "=" in linea:
                clave, _, valor = linea.partition("=")
                valores[clave.strip()] = valor.strip().strip('"').strip("'")
    for v in VARIABLES + OPCIONALES:
        if os.environ.get(v):
            valores[v] = os.environ[v]
    return valores


class ClienteLector:
    """Cliente HTTP mínimo con las credenciales del usuario de solo consulta."""

    def __init__(self, url: str, usuario: str, clave: str, ca: Path,
                 nombre_tls: Optional[str] = None) -> None:
        self.url = url.rstrip("/")
        self.usuario = usuario
        self._auth = "Basic " + base64.b64encode(f"{usuario}:{clave}".encode()).decode()
        self._abrir = abridor(ssl.create_default_context(cafile=str(ca)), nombre_tls)

    def pedir(self, metodo: str, ruta: str, cuerpo: Optional[Any] = None,
              ndjson: Optional[str] = None) -> tuple[int, str]:
        """Devuelve (código HTTP, cuerpo). No lanza por 4xx/5xx."""
        datos = None
        tipo = "application/json"
        if ndjson is not None:
            datos, tipo = ndjson.encode(), "application/x-ndjson"
        elif cuerpo is not None:
            datos = json.dumps(cuerpo).encode()
        req = urllib.request.Request(
            f"{self.url}/{ruta.lstrip('/')}", data=datos, method=metodo,
            headers={"Content-Type": tipo, "Authorization": self._auth})
        try:
            with self._abrir(req, timeout=10) as r:
                return r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace")


@pytest.fixture(scope="session")
def lector() -> ClienteLector:
    env = _cargar_env()
    faltan = [v for v in VARIABLES if not env.get(v) or env[v].startswith("cambia-")]
    if faltan:
        pytest.skip("Sin configuración del laboratorio en .env: " + ", ".join(faltan))
    ca = (RAIZ_REPO / env["WAZUH_CA_CERT"]).resolve()
    if not ca.exists():
        pytest.skip(f"No existe el certificado de la CA: {ca}")
    cliente = ClienteLector(env["WAZUH_INDEXER_URL"], env["WAZUH_INDEXER_USER"],
                            env["WAZUH_INDEXER_PASS"], ca, env.get("WAZUH_INDEXER_TLS_NOMBRE"))
    try:
        cliente.pedir("GET", "/")
    except (urllib.error.URLError, OSError) as e:
        pytest.skip(f"El indexador no responde en {cliente.url}: {e}")
    return cliente

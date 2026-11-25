"""Pruebas de integración: necesitan el laboratorio de lab/wazuh levantado.

Se ejecutan aparte:  cd backend && python -m pytest -m integracion -q
Si falta la configuración o el indexador no responde, se OMITEN con el motivo a la
vista: una prueba omitida no es una prueba aprobada.
"""
from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

import pytest

from sara.adaptadores.wazuh.tls import abridor, contexto_tls

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
        self._abrir = abridor(contexto_tls(str(ca)), nombre_tls)

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


@pytest.fixture(scope="session")
def indexador(lector):
    """El adaptador real de SARA con el usuario de solo consulta (no el administrador)."""
    from sara.adaptadores.wazuh.indexador import IndexadorWazuh

    env = _cargar_env()
    return IndexadorWazuh(env["WAZUH_INDEXER_URL"], env["WAZUH_INDEXER_USER"],
                          env["WAZUH_INDEXER_PASS"],
                          str((RAIZ_REPO / env["WAZUH_CA_CERT"]).resolve()),
                          nombre_tls=env.get("WAZUH_INDEXER_TLS_NOMBRE"))


@pytest.fixture(scope="session")
def conectar_pg():
    """Conexión a la base de SARA (docker-compose.yml raíz). Se omite si no responde."""
    from sara.adaptadores.postgres import conexion

    env = _cargar_env()
    for v in ("POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB", "POSTGRES_HOST",
              "POSTGRES_PORT"):
        if os.environ.get(v):
            env[v] = os.environ[v]
    try:
        conexion.conectar(env).close()
    except Exception as e:  # sin contenedor, sin credenciales...
        pytest.skip(f"PostgreSQL de SARA no responde: {e}")
    return _ConectarPG(env)


class _ConectarPG:
    """Llama a conexion.conectar con el entorno, sin mostrar las claves en los
    informes de pytest (un partial con el dict las imprimía al fallar)."""

    def __init__(self, env: dict[str, str]) -> None:
        self.__env = env

    def __call__(self):
        from sara.adaptadores.postgres import conexion
        return conexion.conectar(self.__env)

    def __repr__(self) -> str:
        return "<conexión PostgreSQL de SARA (credenciales ocultas)>"

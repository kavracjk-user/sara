"""Punto de composición ÚNICO: aquí, y solo aquí, se crean los adaptadores reales y se
entregan a la API y al flujo. Credenciales solo por entorno (RNF-04).

Ejecutar la API (desde backend/, con las variables de entorno cargadas):
    .venv/Scripts/python -m sara.interfaces.composicion
Escucha en 127.0.0.1:8000 salvo SARA_API_HOST / SARA_API_PORT.

Variables: API_KEY_SARA (obligatoria para atender), SARA_CORS_ORIGEN,
WAZUH_INDEXER_URL/USER/PASS, WAZUH_CA_CERT, WAZUH_INDEXER_TLS_NOMBRE, POSTGRES_*.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Mapping, Optional

from fastapi import FastAPI

from sara.interfaces.api import ORIGEN_CORS_POR_DEFECTO, ConfiguracionAPI, crear_app

# Variables cuyo valor nunca puede aparecer en una respuesta.
VARIABLES_SECRETAS = ("API_KEY_SARA", "POSTGRES_PASSWORD", "WAZUH_INDEXER_PASS",
                      "WAZUH_ADMIN_PASS", "WAZUH_API_PASS", "WAZUH_DASHBOARD_PASS")
OCULTO = "[oculto]"


def ocultador(secretos: Iterable[Optional[str]]):
    """Devuelve una función que reemplaza cualquier secreto conocido por «[oculto]»."""
    valores = sorted({s for s in secretos if s and len(s) >= 4}, key=len, reverse=True)

    def ocultar(texto: str) -> str:
        for s in valores:
            texto = texto.replace(s, OCULTO)
        return texto

    return ocultar


RAIZ_REPO = Path(__file__).resolve().parents[3]


def ruta_ca(valor: Optional[str]) -> Optional[str]:
    """Una ruta relativa de la CA se interpreta desde la raíz del repositorio (como en
    lab/wazuh), no desde la carpeta en que se arrancó la API."""
    if not valor:
        return None
    ruta = Path(valor)
    return str(ruta if ruta.is_absolute() else (RAIZ_REPO / ruta).resolve())


def dependencias_desde_entorno(env: Optional[Mapping[str, str]] = None):
    """Arma los adaptadores reales y los entrega al flujo. Devuelve (dependencias,
    función que comprueba la base). Único lugar donde se crean adaptadores."""
    env = os.environ if env is None else env
    from sara.adaptadores.postgres.catalogo import CatalogoPostgres
    from sara.adaptadores.postgres.conexion import conectar
    from sara.adaptadores.postgres.marcas import MarcasPostgres
    from sara.adaptadores.postgres.repositorio import RepositorioPostgres
    from sara.adaptadores.wazuh.indexador import IndexadorWazuh
    from sara.adaptadores.wazuh.normalizer import normalizar
    from sara.interfaces import flows

    def conectar_pg():
        return conectar(env)

    def base_disponible() -> bool:
        with conectar_pg() as con:
            return con.execute("SELECT 1").fetchone() == (1,)

    indexador = IndexadorWazuh(env["WAZUH_INDEXER_URL"], env["WAZUH_INDEXER_USER"],
                               env["WAZUH_INDEXER_PASS"], ruta_ca(env.get("WAZUH_CA_CERT")),
                               nombre_tls=env.get("WAZUH_INDEXER_TLS_NOMBRE"))
    deps = flows.Dependencias(
        indexador, CatalogoPostgres(conectar_pg), RepositorioPostgres(conectar_pg), normalizar,
        marcas=MarcasPostgres(conectar_pg),
        ocultar=ocultador(env.get(v) for v in VARIABLES_SECRETAS))
    flows.configurar_dependencias(deps)
    return deps, base_disponible


def tiempo_maximo(env: Mapping[str, str]) -> float:
    """SARA_TIMEOUT_INVESTIGACION en segundos (por defecto 90)."""
    from sara.aplicacion.casos import TIEMPO_MAXIMO_INVESTIGACION_S
    valor = float(env.get("SARA_TIMEOUT_INVESTIGACION") or TIEMPO_MAXIMO_INVESTIGACION_S)
    if valor <= 0:
        raise ValueError("SARA_TIMEOUT_INVESTIGACION debe ser positivo.")
    return valor


def crear_app_desde_entorno(env: Optional[Mapping[str, str]] = None) -> FastAPI:
    env = os.environ if env is None else env
    from sara.adaptadores.wazuh.normalizer import OBLIGATORIOS
    from sara.aplicacion.casos import ServicioCasos
    from sara.interfaces import flows

    deps, base_disponible = dependencias_desde_entorno(env)
    servicio = ServicioCasos(deps.repositorio, flows.investigacion_inicial,  # type: ignore[arg-type]
                             lambda tipo: OBLIGATORIOS[tipo],
                             tiempo_maximo_s=tiempo_maximo(env))
    return crear_app(ConfiguracionAPI(
        servicio=servicio,
        clave_api=env.get("API_KEY_SARA") or None,
        salud={"indexador": deps.fuente.disponible,  # type: ignore[attr-defined]
               "base_de_datos": base_disponible},
        origen_cors=env.get("SARA_CORS_ORIGEN", ORIGEN_CORS_POR_DEFECTO),
        ocultar=deps.ocultar,
    ))


def main() -> None:
    import uvicorn

    uvicorn.run(crear_app_desde_entorno(), host=os.environ.get("SARA_API_HOST", "127.0.0.1"),
                port=int(os.environ.get("SARA_API_PORT", "8000")))


if __name__ == "__main__":
    main()

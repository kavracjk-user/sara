"""Conexión a PostgreSQL con credenciales de entorno (RNF-04): nunca en el código."""
from __future__ import annotations

import os
from typing import Mapping, Optional

import psycopg

VARIABLES = ("POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB")


def parametros(env: Optional[Mapping[str, str]] = None) -> dict[str, str]:
    env = os.environ if env is None else env
    faltan = [v for v in VARIABLES if not env.get(v)]
    if faltan:
        raise RuntimeError("Faltan variables de entorno de PostgreSQL: " + ", ".join(faltan))
    return {
        "host": env.get("POSTGRES_HOST", "127.0.0.1"),
        "port": env.get("POSTGRES_PORT", "5432"),
        "dbname": env["POSTGRES_DB"],
        "user": env["POSTGRES_USER"],
        "password": env["POSTGRES_PASSWORD"],
    }


def conectar(env: Optional[Mapping[str, str]] = None, **kw) -> psycopg.Connection:
    return psycopg.connect(**parametros(env), connect_timeout=10, **kw)

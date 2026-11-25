"""Base nueva (schema.sql) frente a base migrada (esquema de la fase 4 + migraciones).

Crea dos bases TEMPORALES en el mismo servidor, compara su estructura y las borra al
terminar. No toca la base de SARA. El esquema de partida sale de Git (commit 253f547,
cierre de la fase 4); si Git no está disponible, la prueba se omite.
"""
import secrets
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.integracion

RAIZ = Path(__file__).resolve().parents[3]
SQL = RAIZ / "backend" / "sql"
COMMIT_BASE = "253f547"


def _esquema_anterior() -> str:
    try:
        r = subprocess.run(["git", "-C", str(RAIZ), "show",
                            f"{COMMIT_BASE}:backend/sql/schema.sql"],
                           capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("No se pudo leer el esquema de la fase 4 desde Git.")
    return r.stdout.decode("utf-8")


def _estructura(con) -> dict:
    columnas = con.execute("""
        SELECT table_name, column_name, data_type, is_nullable,
               coalesce(column_default, '')
        FROM information_schema.columns WHERE table_schema = 'public'""").fetchall()
    restricciones = con.execute("""
        SELECT tc.table_name, tc.constraint_type,
               string_agg(kcu.column_name, ',' ORDER BY kcu.column_name)
        FROM information_schema.table_constraints tc
        LEFT JOIN information_schema.key_column_usage kcu
          ON kcu.constraint_name = tc.constraint_name AND kcu.table_name = tc.table_name
        WHERE tc.table_schema = 'public' AND tc.constraint_type <> 'CHECK'
        GROUP BY tc.table_name, tc.constraint_name, tc.constraint_type""").fetchall()
    secuencias = con.execute("""SELECT sequence_name FROM information_schema.sequences
                                WHERE sequence_schema = 'public'""").fetchall()
    vistas = con.execute("""SELECT table_name FROM information_schema.views
                            WHERE table_schema = 'public'""").fetchall()
    return {"columnas": set(columnas), "restricciones": sorted(restricciones),
            "secuencias": set(secuencias), "vistas": set(vistas)}


@pytest.fixture
def dos_bases(conectar_pg):
    sufijo = secrets.token_hex(4)
    nombres = {"nueva": f"sara_prueba_nueva_{sufijo}", "migrada": f"sara_prueba_migrada_{sufijo}"}
    with conectar_pg(autocommit=True) as con:
        for n in nombres.values():
            con.execute(f'CREATE DATABASE "{n}"')
    try:
        yield {k: conectar_pg.a_base(n) for k, n in nombres.items()}
    finally:
        with conectar_pg(autocommit=True) as con:
            for n in nombres.values():
                con.execute(f'DROP DATABASE IF EXISTS "{n}" WITH (FORCE)')


def test_base_nueva_y_base_migrada_tienen_la_misma_estructura(dos_bases):
    semilla = (SQL / "seed_catalogo_anexo_c.sql").read_text(encoding="utf-8")
    migraciones = sorted((SQL / "migraciones").glob("*.sql"))
    assert migraciones, "no hay migraciones"

    with dos_bases["nueva"](autocommit=True) as con:
        con.execute((SQL / "schema.sql").read_text(encoding="utf-8"))
        con.execute(semilla)
        nueva = _estructura(con)

    with dos_bases["migrada"](autocommit=True) as con:
        con.execute(_esquema_anterior())
        con.execute(semilla)
        for _ in range(2):                         # idempotentes: dos veces sin error
            for m in migraciones:
                con.execute(m.read_text(encoding="utf-8"))
        migrada = _estructura(con)

    for parte in ("columnas", "restricciones", "secuencias", "vistas"):
        assert nueva[parte] == migrada[parte], parte

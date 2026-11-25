"""Marca de avance de la ingesta (tabla ingesta_marca, fase 4b)."""
from __future__ import annotations

from typing import Callable, Optional

import psycopg
from psycopg.types.json import Jsonb

from sara.puertos import MarcaIngesta

Conectar = Callable[[], psycopg.Connection]


class MarcasPostgres:
    def __init__(self, conectar: Conectar) -> None:
        self._conectar = conectar

    def leer_marca(self, nombre: str) -> Optional[MarcaIngesta]:
        with self._conectar() as con:
            fila = con.execute("SELECT orden, marca_tiempo FROM ingesta_marca WHERE nombre = %s",
                               (nombre,)).fetchone()
        if fila is None:
            return None
        return MarcaIngesta(tuple(fila[0]), fila[1].isoformat() if fila[1] else None)

    def guardar_marca(self, nombre: str, marca: MarcaIngesta) -> None:
        with self._conectar() as con:
            con.execute(
                """INSERT INTO ingesta_marca (nombre, orden, marca_tiempo, actualizada_en)
                   VALUES (%s, %s, %s, now())
                   ON CONFLICT (nombre) DO UPDATE SET orden = EXCLUDED.orden,
                       marca_tiempo = EXCLUDED.marca_tiempo, actualizada_en = now()""",
                (nombre, Jsonb(list(marca.orden)), marca.marca_tiempo))

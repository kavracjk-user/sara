"""Puerto CatalogoActivos sobre la tabla `activo` (Sec. 3.3.2)."""
from __future__ import annotations

from typing import Callable, Optional

import psycopg

from sara.dominio.models import Activo, Importancia

Conectar = Callable[[], psycopg.Connection]


class CatalogoPostgres:
    def __init__(self, conectar: Conectar) -> None:
        self._conectar = conectar

    def obtener(self, id_agente: str) -> Optional[Activo]:
        with self._conectar() as con:
            fila = con.execute(
                "SELECT id_agente, nombre, funcion, importancia FROM activo WHERE id_agente = %s",
                (id_agente,)).fetchone()
        return _activo(fila) if fila else None

    def todos(self) -> dict[str, Activo]:
        """Para el pipeline, que recibe el catálogo como diccionario."""
        with self._conectar() as con:
            filas = con.execute(
                "SELECT id_agente, nombre, funcion, importancia FROM activo ORDER BY id_agente"
            ).fetchall()
        return {f[0]: _activo(f) for f in filas}


def _activo(fila) -> Activo:
    return Activo(fila[0], fila[1], fila[2], Importancia(fila[3]))

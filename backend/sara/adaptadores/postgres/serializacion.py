"""Convierte resultados de pasos a JSON para la columna JSONB `resultado`.

Los pasos guardan objetos del dominio (VistaComun, Activo, listas de Indicador). Se
almacenan como JSON plano y al releer quedan como dict/list: el expediente conserva el
dato, no el tipo de Python. No se pierde ni se inventa ningún valor.
"""
from __future__ import annotations

import dataclasses
from datetime import datetime
from enum import Enum
from typing import Any


def a_json(valor: Any) -> Any:
    if dataclasses.is_dataclass(valor) and not isinstance(valor, type):
        return {f.name: a_json(getattr(valor, f.name)) for f in dataclasses.fields(valor)}
    if isinstance(valor, Enum):
        return valor.value
    if isinstance(valor, datetime):
        return valor.isoformat()
    if isinstance(valor, dict):
        return {str(k): a_json(v) for k, v in valor.items()}
    if isinstance(valor, (list, tuple, set)):
        return [a_json(v) for v in valor]
    if valor is None or isinstance(valor, (str, int, float, bool)):
        return valor
    raise TypeError(f"No se sabe guardar {type(valor).__name__} como JSON.")

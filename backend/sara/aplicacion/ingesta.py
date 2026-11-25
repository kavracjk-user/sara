"""Ingesta de alertas nuevas (fase 4b): lee el índice (solo consulta) desde la última
marca y abre una investigación por cada alerta de las reglas elegidas.

Reglas:
- Orden ascendente por marca de tiempo; como máximo `lote` alertas por ejecución.
- Solo las reglas de `reglas`; las demás se OMITEN y se cuentan (no se descartan en
  silencio).
- Idempotente: una alerta que ya tiene caso se omite sin error.
- Si una alerta falla, se registra su error (filtrado con `ocultar`) y se sigue con las
  demás. La marca avanza solo hasta la última alerta ANTERIOR al primer fallo: la
  siguiente ejecución vuelve a intentarlo (las ya creadas se omiten por idempotencia).
  Costo: una alerta que falle siempre detiene el avance de la marca.
- No cambia t0: lo fija la investigación (hoy, el momento en que se investiga).
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from sara.aplicacion.pipeline import PASO_LECTURA
from sara.dominio.models import Caso, Estado
from sara.puertos import (FuenteIngesta, MarcaIngesta, RepositorioExpedientes,
                          RepositorioMarcas)

NOMBRE_MARCA = "wazuh-alertas"
LOTE_POR_DEFECTO = 100
MAX_ERROR = 300


@dataclass
class ResumenIngesta:
    leidas: int = 0
    creadas: int = 0
    omitidas_por_regla: int = 0
    ya_existentes: int = 0
    con_error: int = 0
    omitidas_por_regla_detalle: dict[str, int] = field(default_factory=dict)
    creados: list[str] = field(default_factory=list)
    errores: list[dict[str, str]] = field(default_factory=list)
    marca_inicial: Optional[str] = None
    marca_final: Optional[str] = None


def ingerir(fuente: FuenteIngesta, marcas: RepositorioMarcas,
            repositorio: RepositorioExpedientes, investigar: Callable[[str], Caso],
            reglas: Iterable[str], lote: int = LOTE_POR_DEFECTO,
            nombre: str = NOMBRE_MARCA,
            ocultar: Callable[[str], str] = lambda t: t) -> ResumenIngesta:
    if lote < 1:
        raise ValueError("El lote debe ser al menos 1.")
    reglas = frozenset(str(r) for r in reglas)
    marca = marcas.leer_marca(nombre)
    resumen = ResumenIngesta(marca_inicial=marca.marca_tiempo if marca else None)
    omitidas: Counter[str] = Counter()
    avance: Optional[MarcaIngesta] = None
    bloqueada = False

    for alerta in fuente.alertas_despues_de(marca, lote):
        resumen.leidas += 1
        if alerta.regla_id not in reglas:
            resumen.omitidas_por_regla += 1
            omitidas[alerta.regla_id or "(sin regla)"] += 1
        elif repositorio.numero_caso(alerta.id) is not None:
            resumen.ya_existentes += 1
        else:
            error = _investigar(alerta.id, investigar)
            if error is None:
                resumen.creadas += 1
                resumen.creados.append(alerta.id)
            else:
                resumen.con_error += 1
                resumen.errores.append({"id": alerta.id, "error": ocultar(error)[:MAX_ERROR]})
                bloqueada = True
        if not bloqueada:
            avance = MarcaIngesta(tuple(alerta.orden), alerta.marca_tiempo)

    if avance is not None:
        marcas.guardar_marca(nombre, avance)
    resumen.omitidas_por_regla_detalle = dict(sorted(omitidas.items()))
    resumen.marca_final = (avance or marca).marca_tiempo if (avance or marca) else None
    return resumen


def _investigar(id_alerta: str, investigar: Callable[[str], Caso]) -> Optional[str]:
    """None si se creó el caso; si no, el motivo (sin trazas)."""
    try:
        caso = investigar(id_alerta)
    except Exception as e:
        return f"{type(e).__name__}: {e}"
    lectura = next((p for p in caso.pasos if p.paso == PASO_LECTURA), None)
    if lectura is not None and lectura.estado is Estado.SIN_RESULTADO:
        return "La alerta ya no está en el índice."
    if lectura is not None and lectura.estado is Estado.FALLIDO:
        return f"No se pudo leer la alerta: {lectura.error}"
    return None

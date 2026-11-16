"""Flujo de Prefect (Figura 4.1). NO PROBADO en esta sesión: requiere `pip install prefect`.

Prefect solo orquesta: la lógica vive en pipeline.py, que sí tiene pruebas.
Los reintentos y tiempos máximos propios de Prefect se usan para la lectura del
indexador; los de las consultas de contexto los maneja steps.ejecutar_paso para
poder registrar el estado exacto (con_resultado / sin_resultado / fallido).
"""
from __future__ import annotations

from prefect import flow, task  # noqa: E402  (dependencia opcional)

from .models import Activo, Caso
from .pipeline import investigar
from .wazuh_client import IndexadorWazuh


@task(retries=2, retry_delay_seconds=5, timeout_seconds=30)
def leer_alerta(id_alerta: str) -> dict:
    doc = IndexadorWazuh().alerta_por_id(id_alerta)
    if doc is None:
        raise LookupError(f"Alerta {id_alerta} no encontrada en el indexador.")
    return doc


@task
def investigar_alerta(doc: dict, catalogo: dict[str, Activo], id_alerta: str) -> Caso:
    indexador = IndexadorWazuh()
    return investigar(doc, catalogo, buscar_relacionadas=indexador.relacionadas,
                      id_alerta=id_alerta)


@flow(name="sara-investigacion-inicial")
def investigacion_inicial(id_alerta: str, catalogo: dict[str, Activo]) -> Caso:
    """P1 -> P5. El caso queda listo para que el analista lo revise (P6)."""
    doc = leer_alerta(id_alerta)
    return investigar_alerta(doc, catalogo, id_alerta)

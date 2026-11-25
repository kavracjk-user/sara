"""Flujo de Prefect de la investigación inicial (Figura 4.1), fase 3.

P1 leer la alerta del índice (usuario de SOLO consulta, RNF-02) -> P2-P5 investigar
(pipeline.py) -> guardar el expediente en PostgreSQL -> releerlo.

Prefect solo orquesta. La lógica de orden y estados está en `flujo_investigacion`,
una función normal que recibe sus dependencias y se prueba sin Prefect. Cada paso usa
`steps.ejecutar_paso` (reintentos, tiempo máximo y estado exacto, RNF-07); las tareas
de Prefect no reintentan por su cuenta para no duplicar esa regla.

Modo de ejecución (comprobado con Prefect 3.9.5): sin PREFECT_API_URL, Prefect abre un
servidor TEMPORAL en 127.0.0.1 mientras dura el proceso y guarda las corridas en
SQLite bajo PREFECT_HOME. Aquí se fija, salvo que el entorno diga otra cosa:
  - PREFECT_HOME = backend/.prefect (fuera de Git);
  - sin envío de datos anónimos a Prefect (PREFECT_SERVER_ANALYTICS_ENABLED=false);
  - sin interfaz web ni métricas de recursos.
El flujo solo recibe el `_id` de la alerta como parámetro: ningún objeto con
credenciales se guarda en la base de Prefect.

SARA no ejecuta bloqueos, aislamiento ni contención (RNF-01).
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Iterator, Optional, Protocol

_AJUSTES_PREFECT = {
    "PREFECT_HOME": str(Path(__file__).resolve().parents[2] / ".prefect"),
    "PREFECT_SERVER_ANALYTICS_ENABLED": "false",
    "PREFECT_SERVER_UI_ENABLED": "false",
    "PREFECT_TELEMETRY_ENABLE_RESOURCE_METRICS": "false",
    "PREFECT_CLOUD_ENABLE_ORCHESTRATION_TELEMETRY": "false",
}
for _clave, _valor in _AJUSTES_PREFECT.items():
    os.environ.setdefault(_clave, _valor)

from prefect import flow, task  # noqa: E402  (después de fijar el entorno)
from prefect.cache_policies import NO_CACHE  # noqa: E402

from sara.aplicacion.pipeline import investigar  # noqa: E402
from sara.aplicacion.steps import ejecutar_paso  # noqa: E402
from sara.dominio.models import (Activo, Caso, Estado, Importancia, Nivel,  # noqa: E402
                                 PrioridadSugerida, RegistroPaso, VistaComun)
from sara.puertos import CatalogoActivos, FuenteAlertas, RepositorioCasos  # noqa: E402

PASO_LECTURA = "P1_lectura_alerta"
PASO_GUARDADO = "P_guardado_caso"


@dataclass
class Dependencias:
    fuente: FuenteAlertas
    catalogo: CatalogoActivos
    repositorio: RepositorioCasos
    normalizar: Callable[[dict[str, Any], Optional[str]], VistaComun]


class _CatalogoComoDiccionario:
    """El pipeline consulta el catálogo con `.get(id)`. Si la base falla, la excepción
    llega a ejecutar_paso y el paso P4_catalogo_activos queda «fallido», no «sin
    resultado» (RNF-07)."""

    def __init__(self, catalogo: CatalogoActivos) -> None:
        self._catalogo = catalogo

    def get(self, id_agente: str, defecto: Optional[Activo] = None) -> Optional[Activo]:
        activo = self._catalogo.obtener(id_agente) if id_agente else None
        return activo if activo is not None else defecto


# ---------- pasos (funciones normales, sin Prefect) ----------
def leer_alerta(id_alerta: str, deps: Dependencias) -> RegistroPaso:
    """Alerta inexistente = «sin resultado»; error de conexión = «fallido»."""
    return ejecutar_paso(PASO_LECTURA, lambda: deps.fuente.alerta_por_id(id_alerta),
                         fuente="wazuh_indexer", procedencia="consulta de solo lectura")


def investigar_alerta(doc: dict[str, Any], id_alerta: str, deps: Dependencias) -> Caso:
    return investigar(doc, _CatalogoComoDiccionario(deps.catalogo),  # type: ignore[arg-type]
                      deps.normalizar, buscar_relacionadas=deps.fuente.relacionadas,
                      id_alerta=id_alerta)


def guardar_caso(caso: Caso, deps: Dependencias) -> RegistroPaso:
    def _guardar() -> str:
        deps.repositorio.guardar(caso)
        return caso.vista.id_alerta or ""

    return ejecutar_paso(PASO_GUARDADO, _guardar, fuente="postgresql",
                         es_vacio=lambda _r: False)


def releer_caso(id_alerta: str, deps: Dependencias) -> Optional[Caso]:
    return deps.repositorio.obtener(id_alerta)


def caso_sin_alerta(id_alerta: str, lectura: RegistroPaso) -> Caso:
    """Sin documento no hay nada que investigar. El caso NO se guarda (no hay
    evidencia); se devuelve para que quien llamó vea el estado exacto de P1."""
    motivo = ("La alerta no existe en el índice." if lectura.estado is Estado.SIN_RESULTADO
              else f"No se pudo leer la alerta: {lectura.error}.")
    caso = Caso(vista=VistaComun(id_alerta=id_alerta))
    caso.pasos.append(lectura)
    caso.prioridad = PrioridadSugerida(
        Nivel.INSUFICIENTE,
        [motivo, "Resultado: información insuficiente (no equivale a riesgo bajo)."],
        None, Importancia.NO_CATALOGADO, False)
    return caso


def flujo_investigacion(
    id_alerta: str, deps: Dependencias,
    leer: Callable[..., RegistroPaso] = leer_alerta,
    investigar_: Callable[..., Caso] = investigar_alerta,
    guardar: Callable[..., RegistroPaso] = guardar_caso,
    releer: Callable[..., Optional[Caso]] = releer_caso,
) -> Caso:
    """Orden y reglas del flujo. El flujo de Prefect la llama con sus tareas."""
    lectura = leer(id_alerta, deps)
    if lectura.estado is not Estado.CON_RESULTADO:
        return caso_sin_alerta(id_alerta, lectura)

    caso = investigar_(lectura.resultado, id_alerta, deps)
    # El documento completo no se guarda en el registro del paso (Sec. 3.4.5: solo
    # lo necesario); la evidencia mínima ya está en la vista común.
    caso.pasos.insert(0, replace(lectura, resultado={"_id": id_alerta}))

    guardado = guardar(caso, deps)
    if guardado.estado is not Estado.CON_RESULTADO:
        raise RuntimeError(f"El caso {id_alerta} NO se guardó: {guardado.error}")
    releido = releer(id_alerta, deps)
    if releido is None:
        raise RuntimeError(f"El caso {id_alerta} se guardó pero no se pudo releer.")
    return releido


# ---------- Prefect ----------
def dependencias_desde_entorno() -> Dependencias:
    """Adaptadores reales con credenciales de entorno (RNF-04)."""
    from sara.adaptadores.postgres.catalogo import CatalogoPostgres
    from sara.adaptadores.postgres.conexion import conectar
    from sara.adaptadores.postgres.repositorio import RepositorioPostgres
    from sara.adaptadores.wazuh.indexador import IndexadorWazuh
    from sara.adaptadores.wazuh.normalizer import normalizar

    return Dependencias(IndexadorWazuh(), CatalogoPostgres(conectar),
                        RepositorioPostgres(conectar), normalizar)


class _Proveedor(Protocol):
    def __call__(self) -> Dependencias: ...


_proveedor: _Proveedor = dependencias_desde_entorno


def configurar_dependencias(deps: Dependencias) -> None:
    """Punto de composición (composicion.py): el flujo usa estas dependencias."""
    global _proveedor
    _proveedor = lambda: deps  # noqa: E731


@contextmanager
def usar_dependencias(deps: Dependencias) -> Iterator[None]:
    """Para pruebas: el flujo usa estas dependencias en lugar de las del entorno."""
    global _proveedor
    anterior = _proveedor
    _proveedor = lambda: deps  # noqa: E731
    try:
        yield
    finally:
        _proveedor = anterior


_tarea = dict(retries=0, cache_policy=NO_CACHE, persist_result=False)
leer_alerta_t = task(leer_alerta, name=PASO_LECTURA, **_tarea)
investigar_alerta_t = task(investigar_alerta, name="P2_P5_investigacion", **_tarea)
guardar_caso_t = task(guardar_caso, name=PASO_GUARDADO, **_tarea)
releer_caso_t = task(releer_caso, name="releer_caso", **_tarea)


@flow(name="sara-investigacion-inicial", persist_result=False)
def investigacion_inicial(id_alerta: str) -> Caso:
    """P1 -> P5 -> guardar -> releer. El caso queda listo para el analista (P6)."""
    return flujo_investigacion(id_alerta, _proveedor(), leer=leer_alerta_t,
                               investigar_=investigar_alerta_t, guardar=guardar_caso_t,
                               releer=releer_caso_t)

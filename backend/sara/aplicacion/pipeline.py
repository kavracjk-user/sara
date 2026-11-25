"""Investigación inicial de una alerta: P2 a P5 (sin dependencias de Prefect).

El flujo de Prefect (flows.py) solo envuelve estas funciones como tareas, de modo
que la lógica se prueba aquí sin orquestador. SARA NO ejecuta bloqueos, aislamiento
ni contención (RNF-01); no existe ninguna función de ese tipo en el paquete.
"""
from __future__ import annotations

from typing import Any, Callable, Iterable, Optional

from sara.aplicacion.steps import SinDatoAplicable, ejecutar_paso
from sara.dominio.indicators import extraer_indicadores
from sara.dominio.models import (Activo, Caso, Estado, Importancia, Nivel,
                                 PrioridadSugerida, RegistroPaso, TipoAlerta, VistaComun,
                                 ahora)
from sara.dominio.priority import Umbrales, sugerir_prioridad

BuscarRelacionadas = Callable[[VistaComun], list[str]]
# Paso que lee la alerta del índice (lo agrega el flujo antes de P2). Su hora de fin es
# la hora en que SARA obtuvo los datos de la alerta (RNF-05).
PASO_LECTURA = "P1_lectura_alerta"
# El normalizador es de cada fuente (Wazuh, FortiSIEM...): se inyecta, no se importa.
Normalizador = Callable[[dict[str, Any], Optional[str]], VistaComun]
DECISIONES = ("escalar", "descartar", "solicitar_mas_informacion")


def investigar(
    doc: dict[str, Any],
    catalogo: dict[str, Activo],
    normalizar: Normalizador,
    buscar_relacionadas: Optional[BuscarRelacionadas] = None,
    umbrales: Umbrales = Umbrales(),
    id_alerta: Optional[str] = None,
) -> Caso:
    """Devuelve el expediente con la sugerencia y el registro de cada paso.
    t0 es el momento en que la alerta queda disponible para el analista."""
    caso = Caso(vista=VistaComun(), t0=ahora())

    # P2. Normalización
    paso = ejecutar_paso("P2_normalizacion", lambda: normalizar(doc, id_alerta),
                         fuente="wazuh_indexer", reintentos=0)
    caso.pasos.append(paso)
    if paso.estado is not Estado.CON_RESULTADO:
        return caso  # sin vista común no hay nada más que investigar
    caso.vista = paso.resultado
    if caso.vista.campos_ausentes:
        caso.pasos.append(RegistroPaso(
            "P2_validacion", Estado.FALLIDO, ahora(), ahora(),
            error="Campos obligatorios ausentes: " + ", ".join(caso.vista.campos_ausentes),
            fuente="wazuh_indexer"))

    # P3. Extracción de indicadores
    def _extraer() -> list:
        inds = extraer_indicadores(caso.vista)
        if not inds:
            raise SinDatoAplicable("La alerta no contiene IP, dominio ni hash.")
        return inds

    p3 = ejecutar_paso("P3_indicadores", _extraer, reintentos=0)
    caso.pasos.append(p3)
    if p3.estado is Estado.CON_RESULTADO:
        caso.indicadores = p3.resultado

    # P4. Contexto: catálogo local de activos
    def _activo() -> Activo:
        a = catalogo.get(caso.vista.agente_id or "")
        if a is None:
            return None  # type: ignore[return-value]
        return a

    p4a = ejecutar_paso("P4_catalogo_activos", _activo, fuente="catalogo_local",
                        procedencia="tabla activos", reintentos=0)
    caso.pasos.append(p4a)
    if p4a.estado is Estado.CON_RESULTADO:
        caso.activo = p4a.resultado

    # P4. Contexto: alertas relacionadas de Wazuh (con reintentos y tiempo máximo)
    if buscar_relacionadas is not None:
        p4b = ejecutar_paso("P4_alertas_relacionadas",
                            lambda: buscar_relacionadas(caso.vista),
                            fuente="wazuh_indexer", procedencia="consulta de solo lectura")
        caso.pasos.append(p4b)
        if p4b.estado is Estado.CON_RESULTADO:
            caso.alertas_relacionadas = list(p4b.resultado)

    # P5. Prioridad sugerida
    importancia = caso.activo.importancia if caso.activo else Importancia.NO_CATALOGADO
    if caso.vista.tipo_alerta is TipoAlerta.DESCONOCIDO:
        # La clasificación solo cubre reglas catalogadas: lo no clasificado no entra
        # en la matriz y nunca se lee como prioridad baja.
        caso.prioridad = PrioridadSugerida(
            Nivel.INSUFICIENTE,
            [f"La regla {caso.vista.regla_id or '(sin id)'} no está catalogada: no se "
             "pudo determinar el tipo de alerta.",
             "Resultado: información insuficiente (no equivale a riesgo bajo)."],
            None, importancia, False)
    else:
        caso.prioridad = sugerir_prioridad(
            caso.vista.regla_nivel, importancia, len(caso.alertas_relacionadas), umbrales)

    fallidos = [p for p in caso.pasos if p.estado is Estado.FALLIDO]
    if fallidos:
        caso.prioridad.motivos.append(
            "Atención: hubo pasos fallidos (" + ", ".join(p.paso for p in fallidos)
            + "); la ausencia de contexto no implica riesgo bajo.")
    return caso


def registrar_decision(caso: Caso, decision: str, justificacion: str,
                       prioridad_considerada: Nivel) -> Caso:
    """P6/P7. La decisión es SIEMPRE del analista (RNF-06). t1 = primera decisión."""
    if decision not in DECISIONES:
        raise ValueError(f"Decisión inválida: {decision!r}. Use una de {DECISIONES}.")
    if not justificacion or not justificacion.strip():
        raise ValueError("La justificación es obligatoria.")
    caso.decision = decision
    caso.justificacion = justificacion.strip()
    caso.prioridad_considerada = prioridad_considerada
    if caso.t1 is None:  # solo la primera decisión cuenta para el tiempo
        caso.t1 = ahora()
    return caso


def minutos_hasta_decision(caso: Caso) -> Optional[float]:
    if caso.t1 is None:
        return None
    return (caso.t1 - caso.t0).total_seconds() / 60.0


def completitud(campos_obligatorios_aplicables: Iterable[str],
                campos_registrados: Iterable[str]) -> float:
    """Indicador del perfil: obligatorios aplicables registrados / aplicables x 100.
    Los 'no aplicables' deben excluirse ANTES de llamar a esta función."""
    aplicables = set(campos_obligatorios_aplicables)
    if not aplicables:
        return 100.0
    return 100.0 * len(aplicables & set(campos_registrados)) / len(aplicables)

"""Casos de uso de la API (fase 4): investigar, consultar, decidir y exportar.

No conoce FastAPI, Prefect, Wazuh ni PostgreSQL: recibe el repositorio (puerto) y la
función que investiga una alerta. Lo único que escribe es lo que escriben esos dos:
casos (por la investigación) y decisiones del analista. Nada se escribe en Wazuh.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Iterable, Optional

from sara.aplicacion.pipeline import (PASO_LECTURA, completitud, minutos_hasta_decision,
                                      registrar_decision)
from sara.dominio.models import Caso, Estado, Nivel, TipoAlerta, ahora
from sara.puertos import DecisionRegistrada, RepositorioExpedientes

MAX_JUSTIFICACION = 2000
MAX_ANALISTA = 100


class ErrorCaso(Exception):
    """Base de los errores de los casos de uso; el mensaje es apto para el usuario."""


class CasoNoEncontrado(ErrorCaso):
    pass


class AlertaNoEncontrada(ErrorCaso):
    pass


class Conflicto(ErrorCaso):
    pass


class DatosInvalidos(ErrorCaso):
    def __init__(self, mensaje: str, campo: Optional[str] = None) -> None:
        super().__init__(mensaje)
        self.campo = campo


class DependenciaNoDisponible(ErrorCaso):
    pass


@dataclass
class Expediente:
    caso: Caso
    decisiones: list[DecisionRegistrada]

    @property
    def minutos_hasta_decision(self) -> Optional[float]:
        return minutos_hasta_decision(self.caso)

    @property
    def obtenida_en(self) -> Optional[datetime]:
        """Hora (UTC) en que SARA obtuvo los datos de la alerta: fin del paso P1. Vale
        para toda la evidencia, también para los datos «no disponibles» (RNF-05). None
        solo si el caso no pasó por P1 (no ocurre con casos creados por el flujo)."""
        lectura = next((p for p in self.caso.pasos if p.paso == PASO_LECTURA), None)
        return lectura.fin.astimezone(timezone.utc) if lectura else None


@dataclass
class Pagina:
    pagina: int
    tamano: int
    total: int
    expedientes: list[Expediente]


Investigar = Callable[[str], Caso]
Obligatorios = Callable[[TipoAlerta], Iterable[str]]


class ServicioCasos:
    def __init__(self, repositorio: RepositorioExpedientes, investigar: Investigar,
                 obligatorios: Obligatorios) -> None:
        self._repo = repositorio
        self._investigar = investigar
        self._obligatorios = obligatorios

    # ---------- investigar ----------
    def investigar(self, id_alerta: str) -> Expediente:
        if self._repo.obtener(id_alerta) is not None:
            raise Conflicto("Ya existe un caso para esa alerta.")
        try:
            caso = self._investigar(id_alerta)
        except Exception as e:  # el flujo no pudo guardar o falló algo externo
            raise DependenciaNoDisponible("No se pudo completar la investigación.") from e
        lectura = caso.pasos[0] if caso.pasos else None
        if lectura is not None and lectura.estado is Estado.SIN_RESULTADO:
            raise AlertaNoEncontrada("La alerta no existe en el índice.")
        if lectura is not None and lectura.estado is Estado.FALLIDO:
            raise DependenciaNoDisponible("No se pudo leer la alerta del índice.")
        return self.expediente(id_alerta)

    # ---------- consultar ----------
    def expediente(self, id_alerta: str) -> Expediente:
        caso = self._repo.obtener(id_alerta)
        if caso is None:
            raise CasoNoEncontrado("No existe un caso con ese id.")
        return Expediente(caso, self._repo.decisiones(id_alerta))

    def listar(self, pagina: int = 1, tamano: int = 20, prioridad: Optional[Nivel] = None,
               con_decision: Optional[bool] = None) -> Pagina:
        if pagina < 1 or not 1 <= tamano <= 100:
            raise DatosInvalidos("Paginación fuera de rango.", "pagina")
        expedientes = [Expediente(c, self._repo.decisiones(c.vista.id_alerta or ""))
                       for c in self._repo.listar()]
        if prioridad is not None:
            expedientes = [e for e in expedientes
                           if e.caso.prioridad and e.caso.prioridad.nivel is prioridad]
        if con_decision is not None:
            expedientes = [e for e in expedientes if bool(e.decisiones) is con_decision]
        expedientes.sort(key=lambda e: e.caso.t0, reverse=True)
        inicio = (pagina - 1) * tamano
        return Pagina(pagina, tamano, len(expedientes), expedientes[inicio:inicio + tamano])

    # ---------- decidir (RF-11) ----------
    def decidir(self, id_alerta: str, decision: str, justificacion: str,
                prioridad_considerada: str, analista: str) -> Expediente:
        caso = self._repo.obtener(id_alerta)
        if caso is None:
            raise CasoNoEncontrado("No existe un caso con ese id.")
        analista = (analista or "").strip()
        if not analista:
            raise DatosInvalidos("El nombre del analista es obligatorio.", "analista")
        if len(analista) > MAX_ANALISTA:
            raise DatosInvalidos("El nombre del analista es demasiado largo.", "analista")
        if len(justificacion or "") > MAX_JUSTIFICACION:
            raise DatosInvalidos("La justificación es demasiado larga.", "justificacion")
        try:
            nivel = Nivel(prioridad_considerada)
        except ValueError:
            raise DatosInvalidos("Prioridad considerada no válida.", "prioridad_considerada")
        try:  # reglas del dominio: decisión válida, justificación no vacía, t1 = primera
            registrar_decision(caso, decision, justificacion, nivel)
        except ValueError as e:
            campo = "decision" if "Decisión" in str(e) else "justificacion"
            mensaje = ("Decisión no válida." if campo == "decision"
                       else "La justificación es obligatoria.")
            raise DatosInvalidos(mensaje, campo) from e

        nueva = DecisionRegistrada(decision, caso.justificacion or "", nivel, analista, ahora())
        anteriores = self._repo.decisiones(id_alerta)
        if anteriores and _misma(anteriores[-1], nueva):
            raise Conflicto("La decisión es idéntica a la última registrada.")
        assert caso.t1 is not None
        self._repo.registrar_decision(id_alerta, nueva, caso.t1)
        return self.expediente(id_alerta)

    # ---------- exportar (RF-14) ----------
    def exportar(self) -> list[dict]:
        filas = []
        for caso in sorted(self._repo.listar(), key=lambda c: c.t0):
            id_alerta = caso.vista.id_alerta or ""
            decisiones = self._repo.decisiones(id_alerta)
            primera = decisiones[0] if decisiones else None
            obligatorios = set(self._obligatorios(caso.vista.tipo_alerta))
            registrados = obligatorios - set(caso.vista.campos_ausentes)
            filas.append({
                "id": id_alerta,
                "tipo_alerta": caso.vista.tipo_alerta.value,
                "procedimiento": self._repo.procedimiento(id_alerta),
                "t0": _iso(caso.t0),
                "t1": _iso(caso.t1),
                "minutos_hasta_decision": minutos_hasta_decision(caso),
                "prioridad_sugerida": caso.prioridad.nivel.value if caso.prioridad else None,
                "decision": primera.decision if primera else None,
                "prioridad_considerada": (primera.prioridad_considerada.value
                                          if primera else None),
                "completitud": round(completitud(obligatorios, registrados), 1),
            })
        return filas


def _misma(a: DecisionRegistrada, b: DecisionRegistrada) -> bool:
    return (a.decision, a.justificacion.strip(), a.prioridad_considerada,
            (a.analista or "").strip()) == (b.decision, b.justificacion.strip(),
                                            b.prioridad_considerada, (b.analista or "").strip())


def _iso(momento: Optional[datetime]) -> Optional[str]:
    return momento.isoformat() if momento else None

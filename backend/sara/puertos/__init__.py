"""Puertos: contratos que el núcleo necesita y los adaptadores cumplen.

El dominio y la aplicación dependen solo de estas interfaces; nunca de Wazuh,
PostgreSQL, Prefect ni de un proveedor externo concreto.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional, Protocol

from sara.dominio.models import Activo, Caso, Indicador, Nivel, VistaComun


class FuenteAlertas(Protocol):
    """Origen de alertas (Wazuh hoy; FortiSIEM opcional). SOLO LECTURA."""

    def alerta_por_id(self, id_alerta: str) -> Optional[dict[str, Any]]: ...
    def relacionadas(self, vista: VistaComun) -> list[str]: ...


class ProveedorContexto(Protocol):
    """Fuente externa opcional de contexto sobre un indicador.

    Debe devolver el resultado COMPLETO y su procedencia. Una respuesta vacía
    significa «sin resultado»; un error debe lanzarse (el paso quedará «fallido»).
    Nunca debe recibir evidencia del laboratorio, solo el indicador.
    """

    nombre: str

    def consultar(self, indicador: Indicador) -> dict[str, Any]: ...


class CatalogoActivos(Protocol):
    def obtener(self, id_agente: str) -> Optional[Activo]: ...


class RepositorioCasos(Protocol):
    def guardar(self, caso: Caso) -> None: ...
    def obtener(self, id_alerta: str) -> Optional[Caso]: ...
    def listar(self) -> list[Caso]: ...


@dataclass(frozen=True)
class DecisionRegistrada:
    """Una decisión del analista tal como queda en el expediente (RF-11). El dominio
    guarda solo la última decisión en `Caso`; el historial con el analista vive aquí."""

    decision: str
    justificacion: str
    prioridad_considerada: Nivel
    analista: Optional[str]
    registrada_en: datetime


class RepositorioExpedientes(RepositorioCasos, Protocol):
    """Repositorio de casos con historial de decisiones (fase 4)."""

    def decisiones(self, id_alerta: str) -> list[DecisionRegistrada]: ...

    def registrar_decision(self, id_alerta: str, decision: DecisionRegistrada,
                           t1: datetime) -> None:
        """Agrega la decisión y fija t1 solo si aún no tenía valor."""
        ...

    def procedimiento(self, id_alerta: str) -> Optional[str]: ...

"""Modelos de datos de SARA (perfil, secciones 2.4.2, 3.3.2 y 3.4.3).

Solo biblioteca estándar, para poder probar el núcleo sin dependencias externas.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


def ahora() -> datetime:
    return datetime.now(timezone.utc)


class Estado(str, Enum):
    """Estados de un paso o consulta (Tabla 3.4). Nunca se mezclan entre sí."""

    CON_RESULTADO = "con_resultado"
    SIN_RESULTADO = "sin_resultado"  # consulta correcta, nada encontrado: NO es inocuidad
    FALLIDO = "fallido"  # error de conexión, permisos o tiempo agotado
    NO_APLICABLE = "no_aplicable"  # el dato requerido no existe en la alerta


class TipoAlerta(str, Enum):
    AUTENTICACION = "autenticacion"
    CAMBIO_ARCHIVOS = "cambio_archivos"
    ACTIVIDAD_RED = "actividad_red"
    DESCONOCIDO = "desconocido"


class Nivel(str, Enum):
    ALTA = "Alta"
    MEDIA = "Media"
    BAJA = "Baja"
    INSUFICIENTE = "Información insuficiente"


class NivelAlerta(str, Enum):
    ALTO = "Alto"
    MEDIO = "Medio"
    BAJO = "Bajo"


class Importancia(str, Enum):
    ALTA = "Alta"
    MEDIA = "Media"
    BAJA = "Baja"
    NO_CATALOGADO = "No catalogado"


class TipoIndicador(str, Enum):
    IP = "ip"
    DOMINIO = "dominio"
    HASH = "hash"


@dataclass
class VistaComun:
    """Vista común del caso (Tabla 4.14). Un campo ausente queda en None y su
    nombre se registra en `campos_ausentes`; nunca se rellena ni se supone."""

    id_alerta: Optional[str] = None
    marca_tiempo: Optional[str] = None
    regla_id: Optional[str] = None
    regla_nivel: Optional[int] = None
    regla_descripcion: Optional[str] = None
    agente_id: Optional[str] = None
    agente_nombre: Optional[str] = None
    tipo_alerta: TipoAlerta = TipoAlerta.DESCONOCIDO
    ip_origen: Optional[str] = None
    ip_destino: Optional[str] = None
    usuario: Optional[str] = None
    dominio: Optional[str] = None
    archivo_ruta: Optional[str] = None
    archivo_hash: Optional[str] = None
    evento: Optional[str] = None
    evidencia_minima: dict[str, Any] = field(default_factory=dict)
    campos_ausentes: list[str] = field(default_factory=list)


@dataclass
class Indicador:
    tipo: TipoIndicador
    valor: str
    origen_campo: str


@dataclass
class RegistroPaso:
    """Registro de ejecución de un paso (Tabla 4.15)."""

    paso: str
    estado: Estado
    inicio: datetime
    fin: datetime
    resultado: Any = None
    error: Optional[str] = None
    reintentos: int = 0
    fuente: Optional[str] = None
    procedencia: Optional[str] = None

    @property
    def duracion_s(self) -> float:
        return (self.fin - self.inicio).total_seconds()


@dataclass
class Activo:
    id_agente: str
    nombre: str
    funcion: str
    importancia: Importancia


@dataclass
class PrioridadSugerida:
    nivel: Nivel
    motivos: list[str]
    nivel_alerta: Optional[NivelAlerta] = None
    importancia: Optional[Importancia] = None
    corroborada: bool = False


@dataclass
class Caso:
    """Expediente (Tabla 3.7). La decisión humana la agrega el analista."""

    vista: VistaComun
    indicadores: list[Indicador] = field(default_factory=list)
    pasos: list[RegistroPaso] = field(default_factory=list)
    activo: Optional[Activo] = None
    alertas_relacionadas: list[str] = field(default_factory=list)
    prioridad: Optional[PrioridadSugerida] = None
    t0: datetime = field(default_factory=ahora)  # alerta disponible para el analista
    t1: Optional[datetime] = None  # primera decisión humana
    decision: Optional[str] = None  # escalar | descartar | solicitar_mas_informacion
    justificacion: Optional[str] = None
    prioridad_considerada: Optional[Nivel] = None

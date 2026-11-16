"""P5. Prioridad sugerida (Tabla 3.5 y reglas de la sección 3.3.3).

Es una SUGERENCIA de prioridad de atención, no una evaluación de riesgo
(NIST SP 800-30). Los umbrales son una propuesta inicial: deben ser fijados con
el Product Owner antes de las pruebas (Tabla 4.16) y ya no cambiarse.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .models import Importancia, Nivel, NivelAlerta, PrioridadSugerida


@dataclass(frozen=True)
class Umbrales:
    """Niveles de regla de Wazuh (0-15). PROPUESTA: confirmar con el tutor."""

    medio_desde: int = 7
    alto_desde: int = 12

    def clasificar(self, nivel_regla: Optional[int]) -> Optional[NivelAlerta]:
        if nivel_regla is None:
            return None
        if nivel_regla >= self.alto_desde:
            return NivelAlerta.ALTO
        if nivel_regla >= self.medio_desde:
            return NivelAlerta.MEDIO
        return NivelAlerta.BAJO


# Tabla 3.5. Filas: nivel de alerta. Columnas: importancia del activo.
MATRIZ: dict[NivelAlerta, dict[Importancia, Nivel]] = {
    NivelAlerta.ALTO: {
        Importancia.ALTA: Nivel.ALTA, Importancia.MEDIA: Nivel.ALTA,
        Importancia.BAJA: Nivel.MEDIA, Importancia.NO_CATALOGADO: Nivel.INSUFICIENTE,
    },
    NivelAlerta.MEDIO: {
        Importancia.ALTA: Nivel.MEDIA, Importancia.MEDIA: Nivel.MEDIA,
        Importancia.BAJA: Nivel.BAJA, Importancia.NO_CATALOGADO: Nivel.INSUFICIENTE,
    },
    NivelAlerta.BAJO: {
        Importancia.ALTA: Nivel.MEDIA, Importancia.MEDIA: Nivel.BAJA,
        Importancia.BAJA: Nivel.BAJA, Importancia.NO_CATALOGADO: Nivel.INSUFICIENTE,
    },
}

_SUBE = {Nivel.BAJA: Nivel.MEDIA, Nivel.MEDIA: Nivel.ALTA, Nivel.ALTA: Nivel.ALTA}


def sugerir_prioridad(
    nivel_regla: Optional[int],
    importancia: Optional[Importancia],
    alertas_relacionadas: int,
    umbrales: Umbrales = Umbrales(),
) -> PrioridadSugerida:
    """Aplica la matriz y las dos reglas del perfil:
    1) alertas relacionadas que corroboran => sube un nivel (hasta Alta);
    2) falta el nivel de la alerta o el activo no está catalogado =>
       «Información insuficiente» (nunca se interpreta como riesgo bajo).
    """
    motivos: list[str] = []
    nivel_alerta = umbrales.clasificar(nivel_regla)

    if nivel_alerta is None:
        motivos.append("Falta el nivel de la regla de Wazuh en la alerta.")
    else:
        motivos.append(f"Nivel de regla {nivel_regla} => alerta de nivel {nivel_alerta.value}.")

    if importancia is None or importancia is Importancia.NO_CATALOGADO:
        importancia = Importancia.NO_CATALOGADO
        motivos.append("El activo no figura en el catálogo local.")
    else:
        motivos.append(f"Importancia del activo: {importancia.value}.")

    if nivel_alerta is None:
        motivos.append("Resultado: información insuficiente (no equivale a riesgo bajo).")
        return PrioridadSugerida(Nivel.INSUFICIENTE, motivos, None, importancia, False)

    nivel = MATRIZ[nivel_alerta][importancia]
    if nivel is Nivel.INSUFICIENTE:
        motivos.append("Resultado: información insuficiente (no equivale a riesgo bajo).")
        return PrioridadSugerida(nivel, motivos, nivel_alerta, importancia, False)

    motivos.append(f"Matriz de prioridad: {nivel.value}.")
    corroborada = alertas_relacionadas > 0
    if corroborada:
        nuevo = _SUBE[nivel]
        if nuevo is not nivel:
            motivos.append(
                f"{alertas_relacionadas} alerta(s) relacionada(s) corroboran la actividad: "
                f"sube de {nivel.value} a {nuevo.value}."
            )
        else:
            motivos.append(
                f"{alertas_relacionadas} alerta(s) relacionada(s) corroboran la actividad; "
                "ya está en el nivel máximo."
            )
        nivel = nuevo
    return PrioridadSugerida(nivel, motivos, nivel_alerta, importancia, corroborada)

"""Ejecución de pasos con reintentos limitados, tiempo máximo y registro (RF-06, RF-07).

Regla central (RNF-07): una falla, un resultado negativo y un dato no aplicable
son estados distintos y jamás se confunden.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturoVencido
from typing import Any, Callable, Optional

from sara.dominio.models import Estado, RegistroPaso, ahora


class SinDatoAplicable(Exception):
    """El paso no tiene el dato que necesita (p. ej. la alerta no trae dominio)."""


# Valores por defecto: se fijan en las pruebas del Sprint 5 y se justifican en 4.5.2.
REINTENTOS = 2
TIEMPO_MAXIMO_S = 10.0
ESPERA_ENTRE_REINTENTOS_S = 0.0  # en producción, un breve backoff


def ejecutar_paso(
    nombre: str,
    fn: Callable[[], Any],
    *,
    fuente: Optional[str] = None,
    procedencia: Optional[str] = None,
    reintentos: int = REINTENTOS,
    tiempo_maximo_s: float = TIEMPO_MAXIMO_S,
    es_vacio: Callable[[Any], bool] = lambda r: r in (None, [], {}, ()),
) -> RegistroPaso:
    """Corre `fn` y devuelve siempre un RegistroPaso; nunca lanza excepción."""
    inicio = ahora()
    ultimo_error: Optional[str] = None
    intentos = 0
    for intentos in range(reintentos + 1):
        try:
            with ThreadPoolExecutor(max_workers=1) as ex:
                resultado = ex.submit(fn).result(timeout=tiempo_maximo_s)
        except SinDatoAplicable as e:
            return RegistroPaso(nombre, Estado.NO_APLICABLE, inicio, ahora(),
                                error=str(e) or None, fuente=fuente, procedencia=procedencia)
        except FuturoVencido:
            ultimo_error = f"tiempo máximo de {tiempo_maximo_s:g}s agotado"
        except Exception as e:  # conexión, permisos, formato...
            ultimo_error = f"{type(e).__name__}: {e}"
        else:
            estado = Estado.SIN_RESULTADO if es_vacio(resultado) else Estado.CON_RESULTADO
            return RegistroPaso(nombre, estado, inicio, ahora(), resultado=resultado,
                                reintentos=intentos, fuente=fuente, procedencia=procedencia)
    return RegistroPaso(nombre, Estado.FALLIDO, inicio, ahora(), error=ultimo_error,
                        reintentos=intentos, fuente=fuente, procedencia=procedencia)

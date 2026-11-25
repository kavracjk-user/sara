"""Comando de ingesta de alertas nuevas (fase 4b).

    .venv/Scripts/python -m sara.interfaces.ingesta --una-vez

Lee el índice de Wazuh (usuario de solo consulta) desde la última marca, abre una
investigación por cada alerta de las reglas elegidas e imprime un resumen JSON.
Solo existe el modo --una-vez (sin bucle ni programación periódica).

Variables: las de la API (WAZUH_INDEXER_*, WAZUH_CA_CERT, POSTGRES_*) y
  SARA_REGLAS_INGESTA  reglas separadas por comas (por defecto, REGLAS_CATALOGADAS)
  SARA_INGESTA_LOTE    máximo de alertas leídas por ejecución (por defecto 100)
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
from typing import Mapping, Optional

from sara.aplicacion.ingesta import LOTE_POR_DEFECTO

LOTE_MAXIMO = 1000


def configuracion(env: Mapping[str, str]) -> tuple[list[str], int]:
    from sara.adaptadores.wazuh.normalizer import REGLAS_CATALOGADAS

    texto = (env.get("SARA_REGLAS_INGESTA") or "").strip()
    reglas = sorted({r.strip() for r in texto.split(",") if r.strip()}) if texto \
        else sorted(REGLAS_CATALOGADAS)
    if not all(r.isdigit() for r in reglas):
        raise ValueError("SARA_REGLAS_INGESTA debe ser una lista de números de regla.")
    try:
        lote = int(env.get("SARA_INGESTA_LOTE") or LOTE_POR_DEFECTO)
    except ValueError:
        raise ValueError("SARA_INGESTA_LOTE debe ser un número entero.") from None
    if not 1 <= lote <= LOTE_MAXIMO:
        raise ValueError(f"SARA_INGESTA_LOTE debe estar entre 1 y {LOTE_MAXIMO}.")
    return reglas, lote


def main(argv: Optional[list[str]] = None, env: Optional[Mapping[str, str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Ingesta de alertas nuevas de Wazuh")
    ap.add_argument("--una-vez", action="store_true", required=True,
                    help="lee un lote y termina (único modo disponible)")
    ap.parse_args(argv)
    env = os.environ if env is None else env
    try:
        reglas, lote = configuracion(env)
    except ValueError as e:
        print(f"Configuración inválida: {e}", file=sys.stderr)
        return 2

    from sara.interfaces import flows
    from sara.interfaces.composicion import dependencias_desde_entorno

    dependencias_desde_entorno(env)
    resumen = flows.ingesta_alertas(reglas, lote)
    print(json.dumps(dataclasses.asdict(resumen), ensure_ascii=False, indent=2))
    return 1 if resumen.con_error else 0


if __name__ == "__main__":
    sys.exit(main())

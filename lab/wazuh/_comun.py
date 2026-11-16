"""Utilidades compartidas por los scripts del laboratorio (solo biblioteca estándar)."""
from __future__ import annotations

import os
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]      # raíz del repositorio
LAB_WAZUH = Path(__file__).resolve().parent     # lab/wazuh
VERSION_WAZUH = "4.14.10"


def leer_env(ruta: Path | None = None) -> dict[str, str]:
    """Lee KEY=VALOR de .env. Las variables de entorno ya definidas tienen prioridad."""
    ruta = ruta or RAIZ / ".env"
    valores: dict[str, str] = {}
    if ruta.exists():
        for linea in ruta.read_text(encoding="utf-8").splitlines():
            linea = linea.strip()
            if not linea or linea.startswith("#") or "=" not in linea:
                continue
            clave, _, valor = linea.partition("=")
            valores[clave.strip()] = valor.strip().strip('"').strip("'")
    valores.update({k: v for k, v in os.environ.items() if k in valores or k.startswith("WAZUH_")})
    return valores


def exigir(valores: dict[str, str], *claves: str) -> None:
    faltan = [c for c in claves if not valores.get(c) or valores[c].startswith("cambia-")]
    if faltan:
        raise SystemExit(
            "Faltan variables en .env (o siguen con el valor de ejemplo): " + ", ".join(faltan)
        )

"""Genera los eventos sintéticos del guion de 12 pares DENTRO del laboratorio.

Solo actúa en los cinco contenedores de agentes de lab/wazuh (docker compose exec).
No hay tráfico de red, no hay internet, no hay herramientas de ataque.

Uso (desde la raíz del repositorio, con el laboratorio levantado):
    python lab/eventos/sara_eventos.py listar
    python lab/eventos/sara_eventos.py ejecutar 01A          # un caso
    python lab/eventos/sara_eventos.py limpiar 01A           # deshace lo que creó
    python lab/eventos/sara_eventos.py ejecutar todos        # los 24, con pausas
    python lab/eventos/sara_eventos.py limpiar todos
    python lab/eventos/sara_eventos.py --simular ejecutar 06A   # muestra, no ejecuta

Cada ejecución o limpieza deja un manifiesto en lab/corridas/ (fuera de Git) con el
contenedor, el id de agente y las horas UTC de inicio y fin, para luego capturar las
alertas de esa franja. Las alertas ya indexadas NO se borran: el usuario de SARA es de
solo lectura y además son evidencia. La limpieza de archivos (pares 5 a 8) genera a su
vez alertas de integridad; su franja queda en el manifiesto de la limpieza.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from casos import AGENTES, Caso, Paso, construir

RAIZ = Path(__file__).resolve().parents[2]
CORRIDAS = RAIZ / "lab" / "corridas"
COMPOSE = ["docker", "compose", "--env-file", str(RAIZ / ".env"),
           "-f", str(RAIZ / "lab" / "wazuh" / "docker-compose.yml")]
ID_AGENTE = {"srv-web": "001", "srv-bd": "002", "pc-analista": "003",
             "pc-lab-01": "004", "pc-nuevo": "099"}

Correr = Callable[..., subprocess.CompletedProcess]


def comando(paso: Paso) -> list[str]:
    if paso.contenedor not in AGENTES:
        raise ValueError(f"Contenedor fuera del laboratorio de agentes: {paso.contenedor}")
    return COMPOSE + ["exec", "-T", paso.contenedor, "sh", "-c", paso.script]


def ejecutar_pasos(pasos: Iterable[Paso], correr: Correr = subprocess.run) -> None:
    for paso in pasos:
        # bytes, no texto: en Windows el modo texto convertiría \n en \r\n.
        res = correr(comando(paso), input=paso.entrada.encode(), capture_output=True)
        if res.returncode != 0:
            err = res.stderr.decode(errors="replace") if isinstance(res.stderr, bytes) else res.stderr
            raise RuntimeError(f"Falló en {paso.contenedor}: {paso.script}\n{err}")


def manifiesto(caso: Caso, accion: str, inicio: datetime, fin: datetime) -> dict:
    return {
        "caso": caso.clave, "par": caso.par, "variante": caso.variante,
        "tipo": caso.tipo, "situacion": caso.situacion, "accion": accion,
        "contenedor": caso.contenedor, "agente_id": ID_AGENTE[caso.contenedor],
        "contenedores": list(caso.contenedores),
        "inicio_utc": inicio.isoformat(), "fin_utc": fin.isoformat(),
        "reglas_esperadas_hipotesis": list(caso.reglas_esperadas) if accion == "ejecutar" else [],
        "fuente": "lab/eventos (datos sintéticos, RNF-03)",
    }


def guardar_manifiesto(datos: dict, carpeta: Path = CORRIDAS) -> Path:
    carpeta.mkdir(parents=True, exist_ok=True)
    marca = datos["inicio_utc"].replace(":", "").replace("-", "")[:15]
    ruta = carpeta / f"{marca}-{datos['caso']}-{datos['accion']}.json"
    ruta.write_text(json.dumps(datos, ensure_ascii=False, indent=2), encoding="utf-8")
    return ruta


def mostrar(caso: Caso, pasos: Iterable[Paso]) -> None:
    for p in pasos:
        print(f"  [{p.contenedor}] sh -c '{p.script}'")
        for linea in p.entrada.splitlines()[:3]:
            print(f"      < {linea[:110]}")
        if p.entrada.count("\n") > 3:
            print(f"      < ... ({p.entrada.count(chr(10))} líneas en total)")


def seleccionar(casos: dict[str, Caso], clave: str) -> list[Caso]:
    if clave.lower() == "todos":
        return list(casos.values())
    clave = clave.upper()
    if len(clave) == 2:                       # «1A» -> «01A»
        clave = "0" + clave
    if clave not in casos:
        raise SystemExit(f"No existe el caso {clave}. Usa `listar`.")
    return [casos[clave]]


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--simular", action="store_true", help="muestra los pasos sin ejecutarlos")
    ap.add_argument("--sin-pausa", action="store_true",
                    help="no espera entre casos (las reglas de frecuencia pueden no repetirse)")
    sub = ap.add_subparsers(dest="orden", required=True)
    sub.add_parser("listar")
    for nombre in ("ejecutar", "limpiar"):
        sub.add_parser(nombre).add_argument("caso", help="p. ej. 01A, 1B o «todos»")
    args = ap.parse_args(argv)

    casos = construir(datetime.now(timezone.utc))
    if args.orden == "listar":
        for c in casos.values():
            print(f"{c.clave}  {c.tipo:<16} {c.contenedor:<12} reglas {','.join(c.reglas_esperadas):<22} {c.situacion}")
        return

    elegidos = seleccionar(casos, args.caso)
    for i, caso in enumerate(elegidos):
        pasos = caso.pasos if args.orden == "ejecutar" else caso.limpieza
        print(f"== {args.orden} {caso.clave}: {caso.situacion}")
        if args.simular:
            mostrar(caso, pasos)
            continue
        inicio = datetime.now(timezone.utc)
        ejecutar_pasos(pasos)
        fin = datetime.now(timezone.utc)
        ruta = guardar_manifiesto(manifiesto(caso, args.orden, inicio, fin))
        print(f"   manifiesto: {ruta.relative_to(RAIZ)}")
        ultimo = i == len(elegidos) - 1
        if args.orden == "ejecutar" and not args.sin_pausa and not ultimo:
            print(f"   pausa de {caso.pausa_s} s (reglas de frecuencia)")
            time.sleep(caso.pausa_s)


if __name__ == "__main__":
    sys.exit(main())

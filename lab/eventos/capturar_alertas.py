"""Captura las alertas de cada caso ejecutado y las compara con las reglas esperadas.

Lee los manifiestos de lab/corridas/ (*-ejecutar.json) y, para cada caso, consulta el
indexador con el usuario de SOLO CONSULTA (el mismo de SARA, RNF-02) las alertas de los
agentes del caso entre su inicio y el inicio del caso siguiente. No escribe en Wazuh.

Guarda las alertas crudas en lab/capturas/crudas/<caso>.json (fuera de Git: son datos
de una corrida) y un resumen en lab/capturas/crudas/resumen.json.

Uso (desde la raíz, después de `sara_eventos.py ejecutar ...`):
    python lab/eventos/capturar_alertas.py
    python lab/eventos/capturar_alertas.py --desde 20261118T0500   # solo corridas desde esa marca
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(RAIZ / "backend"), str(RAIZ / "lab" / "wazuh"), str(RAIZ / "lab" / "eventos")]
from _comun import exigir, leer_env  # noqa: E402
from sara.adaptadores.wazuh.tls import abridor, contexto_tls  # noqa: E402

import casos as cs  # noqa: E402

CORRIDAS = RAIZ / "lab" / "corridas"
SALIDA = RAIZ / "lab" / "capturas" / "crudas"
ID_AGENTE = {"srv-web": "001", "srv-bd": "002", "pc-analista": "003",
             "pc-lab-01": "004", "pc-nuevo": "099"}
MARGEN_FINAL = timedelta(seconds=90)      # para el último caso (no hay siguiente)


def cargar_manifiestos(desde: str = "") -> list[dict]:
    salida = []
    for f in sorted(CORRIDAS.glob("*-ejecutar.json")):
        if f.name[:len(desde)] >= desde:
            salida.append(json.loads(f.read_text(encoding="utf-8")))
    return sorted(salida, key=lambda m: m["inicio_utc"])


def ventanas(manifiestos: list[dict]) -> list[tuple[dict, str, str]]:
    """Cada caso va desde su inicio hasta el inicio del siguiente (o fin + margen)."""
    res = []
    for i, m in enumerate(manifiestos):
        if i + 1 < len(manifiestos):
            hasta = manifiestos[i + 1]["inicio_utc"]
        else:
            hasta = (datetime.fromisoformat(m["fin_utc"]) + MARGEN_FINAL).isoformat()
        res.append((m, m["inicio_utc"], hasta))
    return res


def consulta(agentes: list[str], desde: str, hasta: str) -> dict:
    return {"size": 1000, "sort": [{"timestamp": "asc"}],
            "query": {"bool": {"filter": [
                {"terms": {"agent.id": agentes}},
                {"range": {"timestamp": {"gte": desde, "lt": hasta}}}]}}}


def resumir(alertas: list[dict]) -> dict:
    return {"total": len(alertas),
            "por_regla": dict(Counter(a["rule"]["id"] for a in alertas)),
            "por_agente_regla": dict(Counter(f'{a["agent"]["name"]}:{a["rule"]["id"]}'
                                             for a in alertas))}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--desde", default="", help="marca AAAAMMDDTHHMM mínima del manifiesto")
    args = ap.parse_args(argv)

    env = leer_env()
    exigir(env, "WAZUH_INDEXER_URL", "WAZUH_INDEXER_USER", "WAZUH_INDEXER_PASS", "WAZUH_CA_CERT")
    abrir = abridor(contexto_tls(str(RAIZ / env["WAZUH_CA_CERT"])),
                    env.get("WAZUH_INDEXER_TLS_NOMBRE"))
    auth = "Basic " + base64.b64encode(
        f'{env["WAZUH_INDEXER_USER"]}:{env["WAZUH_INDEXER_PASS"]}'.encode()).decode()
    url = env["WAZUH_INDEXER_URL"].rstrip("/") + "/wazuh-alerts-*/_search"

    # Las reglas esperadas salen de casos.py (hipótesis vigente), no del manifiesto.
    hipotesis = {k: c.reglas_esperadas for k, c in cs.construir(datetime.now()).items()}
    manifiestos = cargar_manifiestos(args.desde)
    if not manifiestos:
        raise SystemExit("No hay manifiestos de ejecución en lab/corridas/.")
    SALIDA.mkdir(parents=True, exist_ok=True)
    resumen, difieren = {}, 0
    for m, desde, hasta in ventanas(manifiestos):
        agentes = sorted({ID_AGENTE[c] for c in m["contenedores"]})
        req = urllib.request.Request(url, data=json.dumps(consulta(agentes, desde, hasta)).encode(),
                                     headers={"Content-Type": "application/json",
                                              "Authorization": auth}, method="POST")
        try:
            with abrir(req, timeout=30) as r:
                datos = json.load(r)
        except urllib.error.HTTPError as e:
            raise SystemExit(f"{m['caso']}: HTTP {e.code} {e.read()[:200]!r}")
        alertas = [h["_source"] | {"_id": h["_id"]} for h in datos["hits"]["hits"]]
        (SALIDA / f'{m["caso"]}.json').write_text(
            json.dumps({"manifiesto": m, "ventana": [desde, hasta], "alertas": alertas},
                       ensure_ascii=False, indent=1), encoding="utf-8")
        r = resumir(alertas)
        esperadas = set(hipotesis[m["caso"]])
        faltan = sorted(esperadas - set(r["por_regla"]))
        r |= {"esperadas": sorted(esperadas), "faltan": faltan}
        resumen[m["caso"]] = r
        difieren += bool(faltan)
        estado = "OK" if not faltan else f"FALTAN {faltan}"
        print(f'{m["caso"]}: {estado}  {r["por_agente_regla"]}')
    (SALIDA / "resumen.json").write_text(json.dumps(resumen, ensure_ascii=False, indent=1),
                                         encoding="utf-8")
    print(f"Capturas en {SALIDA.relative_to(RAIZ)} (fuera de Git).")
    return 1 if difieren else 0


if __name__ == "__main__":
    sys.exit(main())

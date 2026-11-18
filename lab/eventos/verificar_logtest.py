"""Pasa por wazuh-logtest las líneas que genera casos.py y compara con las reglas esperadas.

No escribe nada en los agentes ni en el índice: wazuh-logtest solo evalúa las líneas en
el servidor. Cada caso usa una sesión nueva (las reglas de frecuencia parten de cero).
Los pares 5 a 8 (cambio de archivos) no aplican: sus eventos los genera el FIM del
agente, no una línea de log; se confirman con una corrida real.

Uso (desde la raíz, con el laboratorio levantado):
    python lab/eventos/verificar_logtest.py            # los 24 casos
    python lab/eventos/verificar_logtest.py 02A 10B
"""
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import casos as cs

RAIZ = Path(__file__).resolve().parents[2]

COMPOSE = ["docker", "compose", "--env-file", str(RAIZ / ".env"),
           "-f", str(RAIZ / "lab" / "wazuh" / "docker-compose.yml")]


def logtest(lineas):
    res = subprocess.run(COMPOSE + ["exec", "-T", "wazuh.manager", "/var/ossec/bin/wazuh-logtest"],
                         input=("\n".join(lineas) + "\n").encode(), capture_output=True)
    salida = (res.stdout + res.stderr).decode(errors="replace")
    bloques = salida.split("**Phase 1")[1:]
    reglas, alertas, decoders = [], [], Counter()
    for b in bloques:
        m = re.search(r"id: '(\d+)'", b.split("**Phase 3")[-1]) if "**Phase 3" in b else None
        d = re.search(r"name: '([^']+)'", b.split("**Phase 2")[-1]) if "**Phase 2" in b else None
        decoders[d.group(1) if d else "-"] += 1
        regla = m.group(1) if m else "-"
        reglas.append(regla)
        if "**Alert to be generated" in b:
            nivel = re.search(r"level: '(\d+)'", b.split("**Phase 3")[-1]).group(1)
            alertas.append(f"{regla}(n{nivel})")
    return reglas, alertas, decoders, res.returncode, salida


def main():
    casos = cs.construir(datetime.now(timezone.utc))
    elegidos = [k.upper() for k in sys.argv[1:]] or list(casos)
    fallos = 0
    for clave in elegidos:
        c = casos[clave]
        lineas = [] if c.tipo == cs.CAMBIO_ARCHIVOS else [l for p in c.pasos for l in p.entrada.splitlines() if l.strip()]
        if not lineas:
            print(f"{clave}: sin líneas de log (cambio de archivos; no aplica logtest)")
            continue
        reglas, alertas, dec, rc, salida = logtest(lineas)
        if len(reglas) != len(lineas):
            fallos += 1
            print(f"{clave}: ERROR {len(reglas)} resultados para {len(lineas)} líneas rc={rc}\n{salida[-800:]}")
            continue
        esperadas = set(c.reglas_esperadas)
        ids = {a.split("(")[0] for a in alertas}
        estado = "OK" if esperadas <= ids else "DIFIERE"
        fallos += estado != "OK"
        print(f"{clave}: {estado} esperadas={sorted(esperadas)} decoders={dict(dec)} "
              f"reglas={dict(Counter(reglas))} alertas={dict(Counter(alertas))}")
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())

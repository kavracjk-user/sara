"""Registra los agentes de prueba con los id del Anexo C (incluido 099 de pc-nuevo).

Por qué hace falta: Wazuh asigna el id por orden de registro (001, 002, ...) y ni el
registro automático ni `manage_agents` permiten elegirlo. La API del servidor sí:
`POST /agents/insert` recibe `id`, `name`, `ip` y `key`, y el agente debe tener esa
misma clave en su `client.keys` (especificación oficial de la API, wazuh v4.14.10,
api/api/spec/spec.yaml, «Add agent full»).

Qué hace:
  1. Genera una clave de 64 caracteres por agente y escribe
     lab/wazuh/claves-agentes/<nombre>/client.keys  (fuera de Git).
     Si ya existe, reutiliza la clave: repetir el script no cambia nada.
  2. Dentro del contenedor del servidor, se autentica en la API con `wazuh-wui` y
     llama a /agents/insert por cada agente (con `force` para poder repetirlo).
     La API no se publica al equipo; la clave de la API viaja por la entrada
     estándar, no por la línea de comandos.

Orden de uso (desde la raíz del repositorio):
    docker compose --env-file .env -f lab/wazuh/docker-compose.yml up -d wazuh.indexer wazuh.manager wazuh.dashboard
    python lab/wazuh/registrar_agentes.py
    docker compose --env-file .env -f lab/wazuh/docker-compose.yml up -d
    python lab/wazuh/registrar_agentes.py --simular   # muestra el plan sin Docker

PROBADO con Wazuh 4.14.10 (2026-11-18): se confirmaron el formato de client.keys
(«ID NOMBRE IP CLAVE»), que /agents/insert acepta «099» e IP «any», que el servidor
trae `curl`, que `wazuh-wui` puede crear agentes y que el agente conecta solo con
client.keys y sin registro automático. Los cinco quedan `Active`.
"""
from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from _comun import LAB_WAZUH, RAIZ, exigir, leer_env

CLAVES = LAB_WAZUH / "claves-agentes"

# docs/anexo-c-guion-casos.md (PROPUESTA pendiente del tutor).
AGENTES: tuple[tuple[str, str], ...] = (
    ("001", "srv-web"),
    ("002", "srv-bd"),
    ("003", "pc-analista"),
    ("004", "pc-lab-01"),
    ("099", "pc-nuevo"),     # tiene agente en Wazuh, NO está en el catálogo de SARA
)

GUION_SERVIDOR = r"""
set -e
read -r CLAVE_API
API=https://localhost:55000
TOKEN=$(curl -sk -u "wazuh-wui:$CLAVE_API" -X POST "$API/security/user/authenticate?raw=true")
[ -n "$TOKEN" ] || { echo "No se obtuvo token de la API" >&2; exit 1; }
while read -r ID NOMBRE KEY; do
  [ -n "$ID" ] || continue
  curl -sk -X POST "$API/agents/insert" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "{\"id\":\"$ID\",\"name\":\"$NOMBRE\",\"ip\":\"any\",\"key\":\"$KEY\",\"force\":{\"enabled\":true}}"
  echo
done
"""


@dataclass(frozen=True)
class Registro:
    id: str
    nombre: str
    clave: str

    def linea_client_keys(self) -> str:
        return f"{self.id} {self.nombre} any {self.clave}\n"


def nueva_clave() -> str:
    return secrets.token_hex(32)          # 64 caracteres hexadecimales


def leer_clave_existente(ruta: Path, ident: str, nombre: str) -> str | None:
    if not ruta.is_file():
        return None
    partes = ruta.read_text(encoding="utf-8").split()
    if len(partes) == 4 and partes[0] == ident and partes[1] == nombre and len(partes[3]) == 64:
        return partes[3]
    raise SystemExit(f"{ruta} no coincide con el Anexo C; bórralo y vuelve a ejecutar.")


def preparar_registros(carpeta: Path = CLAVES, escribir: bool = True) -> list[Registro]:
    registros = []
    for ident, nombre in AGENTES:
        ruta = carpeta / nombre / "client.keys"
        if ruta.is_dir():
            raise SystemExit(f"{ruta} es una carpeta (la creó Docker al montar un archivo "
                             "inexistente). Bórrala y vuelve a ejecutar.")
        clave = leer_clave_existente(ruta, ident, nombre) or nueva_clave()
        reg = Registro(ident, nombre, clave)
        if escribir:
            ruta.parent.mkdir(parents=True, exist_ok=True)
            ruta.write_text(reg.linea_client_keys(), encoding="utf-8", newline="\n")
        registros.append(reg)
    return registros


def entrada_servidor(clave_api: str, registros: list[Registro]) -> bytes:
    lineas = [clave_api] + [f"{r.id} {r.nombre} {r.clave}" for r in registros]
    return ("\n".join(lineas) + "\n").encode()


def comprobar_respuestas(salida: str, registros: list[Registro]) -> list[str]:
    """Devuelve los problemas encontrados (lista vacía = todos registrados)."""
    respuestas = [l for l in salida.splitlines() if l.strip()]
    problemas = []
    if len(respuestas) != len(registros):
        problemas.append(f"Se esperaban {len(registros)} respuestas y llegaron {len(respuestas)}.")
    for reg, texto in zip(registros, respuestas):
        try:
            datos = json.loads(texto)
        except json.JSONDecodeError:
            problemas.append(f"{reg.nombre}: respuesta no es JSON: {texto[:200]}")
            continue
        if datos.get("error") != 0 or datos.get("data", {}).get("id") != reg.id:
            problemas.append(f"{reg.nombre}: {texto[:300]}")
    return problemas


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--simular", action="store_true",
                    help="muestra qué se registraría, sin escribir ni usar Docker")
    args = ap.parse_args()

    if args.simular:
        for r in preparar_registros(escribir=False):
            print(f"[simulación] id {r.id}  {r.nombre:<12} clave {r.clave[:6]}… (64 car.)")
        return

    env = leer_env()
    exigir(env, "WAZUH_API_PASS")
    registros = preparar_registros()
    print(f"[+] client.keys listos en {CLAVES.relative_to(RAIZ)}/ (fuera de Git)")

    cmd = ["docker", "compose", "--env-file", str(RAIZ / ".env"),
           "-f", str(LAB_WAZUH / "docker-compose.yml"),
           "exec", "-T", "wazuh.manager", "sh", "-c", GUION_SERVIDOR]
    res = subprocess.run(cmd, input=entrada_servidor(env["WAZUH_API_PASS"], registros),
                         capture_output=True)
    if res.returncode != 0:
        raise SystemExit("Falló el registro en el servidor:\n" + res.stderr.decode(errors="replace"))
    problemas = comprobar_respuestas(res.stdout.decode(errors="replace"), registros)
    if problemas:
        raise SystemExit("La API no confirmó todos los agentes:\n  " + "\n  ".join(problemas))
    for r in registros:
        print(f"[ok] id {r.id}  {r.nombre}")
    print("Ahora levanta los agentes: docker compose ... up -d  (ver README.md)")


if __name__ == "__main__":
    sys.exit(main())

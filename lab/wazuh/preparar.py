"""Prepara lab/wazuh/config/ a partir de la configuración oficial de Wazuh para Docker.

Qué hace (nada de esto se sube a Git: `upstream/` y `config/` están en .gitignore):
  1. Clona wazuh-docker en la etiqueta fijada (v4.14.10) en lab/wazuh/upstream/.
  2. Copia single-node/config/ a lab/wazuh/config/.
  3. Agrega 127.0.0.1 y localhost al certificado del indexador, para que SARA pueda
     validar el certificado al conectarse desde el equipo anfitrión.
  4. Reescribe internal_users.yml solo con `admin` y `kibanaserver`, con las claves
     de .env (se eliminan los usuarios de demostración con claves públicas).
  5. Escribe la clave de la API en wazuh.yml del panel.

Uso (desde la raíz del repositorio, con Docker en marcha):
    python lab/wazuh/preparar.py            # no pisa una config/ existente
    python lab/wazuh/preparar.py --forzar   # la regenera (conserva los certificados)

SUPOSICIONES pendientes de verificar con Docker (ver README.md de esta carpeta):
  - Ruta de hash.sh dentro de la imagen del indexador.
  - Que certs.yml acepte una lista en `ip`.
  - Que el indexador cargue internal_users.yml al crear el volumen por primera vez.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys

from _comun import LAB_WAZUH, VERSION_WAZUH, exigir, leer_env

REPO = "https://github.com/wazuh/wazuh-docker.git"
UPSTREAM = LAB_WAZUH / "upstream"
CONFIG = LAB_WAZUH / "config"
CERTS = "wazuh_indexer_ssl_certs"
HASH_SH = "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh"


def ejecutar(*cmd: str) -> str:
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise SystemExit(f"Falló: {' '.join(cmd[:4])} ...\n{res.stderr.strip()}")
    return res.stdout


def clonar_oficial() -> None:
    if (UPSTREAM / "single-node").exists():
        print(f"[=] Ya existe {UPSTREAM.name}/ (v{VERSION_WAZUH}).")
        return
    print(f"[+] Clonando wazuh-docker v{VERSION_WAZUH} ...")
    ejecutar("git", "clone", "--depth", "1", "-b", f"v{VERSION_WAZUH}", REPO, str(UPSTREAM))


def copiar_config(forzar: bool) -> bool:
    if CONFIG.exists() and not forzar:
        print("[=] config/ ya existe; no se toca (usa --forzar para regenerarla).")
        return False
    certs_previos = CONFIG / CERTS
    respaldo = LAB_WAZUH / f".{CERTS}.tmp"
    if certs_previos.exists():
        shutil.move(str(certs_previos), str(respaldo))
    if CONFIG.exists():
        shutil.rmtree(CONFIG)
    shutil.copytree(UPSTREAM / "single-node" / "config", CONFIG)
    if respaldo.exists():
        shutil.move(str(respaldo), str(CONFIG / CERTS))
    (CONFIG / CERTS).mkdir(exist_ok=True)
    print("[+] Copiada la configuración oficial a config/.")
    return True


def parchear_certs_yml(texto: str) -> str:
    """El nodo indexador pasa de `ip: wazuh.indexer` a una lista con 127.0.0.1."""
    nuevo, n = re.subn(
        r"^( *)ip: wazuh\.indexer *$",
        r"\1ip:\n\1  - wazuh.indexer\n\1  - 127.0.0.1\n\1  - localhost",
        texto, count=1, flags=re.MULTILINE,
    )
    if n != 1:
        raise SystemExit("certs.yml no tiene la forma esperada; revísalo a mano.")
    return nuevo


def usuarios_internos(hash_admin: str, hash_panel: str) -> str:
    return f"""---
# Generado por lab/wazuh/preparar.py. NO subir a Git.
_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "{hash_admin}"
  reserved: true
  backend_roles:
  - "admin"
  description: "Administrador del laboratorio (no lo usa SARA)"

kibanaserver:
  hash: "{hash_panel}"
  reserved: true
  description: "Usuario de servicio del panel"
"""


def parchear_wazuh_yml(texto: str, clave_api: str) -> str:
    nuevo, n = re.subn(r'^( *password: *).*$', lambda m: f'{m.group(1)}"{clave_api}"',
                       texto, count=1, flags=re.MULTILINE)
    if n != 1:
        raise SystemExit("wazuh.yml no tiene la forma esperada; revísalo a mano.")
    return nuevo


def generar_hash(clave: str) -> str:
    salida = ejecutar("docker", "run", "--rm", f"wazuh/wazuh-indexer:{VERSION_WAZUH}",
                      "bash", HASH_SH, "-p", clave)
    for linea in reversed(salida.strip().splitlines()):
        if linea.strip().startswith("$2"):
            return linea.strip()
    raise SystemExit("hash.sh no devolvió un hash bcrypt; revisa la ruta de la herramienta.")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--forzar", action="store_true", help="regenera config/")
    args = ap.parse_args()

    env = leer_env()
    claves = ("WAZUH_ADMIN_PASS", "WAZUH_DASHBOARD_PASS", "WAZUH_API_PASS")
    exigir(env, *claves)
    for c in claves:
        if set(env[c]) & set("$\"'\\ "):
            raise SystemExit(f"{c}: evita $, comillas, barra invertida y espacios.")
    for herramienta in ("git", "docker"):
        if shutil.which(herramienta) is None:
            raise SystemExit(f"No encuentro `{herramienta}` en el PATH.")

    clonar_oficial()
    if not copiar_config(args.forzar):
        return

    ruta = CONFIG / "certs.yml"
    ruta.write_text(parchear_certs_yml(ruta.read_text(encoding="utf-8")), encoding="utf-8")

    print("[+] Generando hashes con la herramienta del indexador ...")
    ruta = CONFIG / "wazuh_indexer" / "internal_users.yml"
    ruta.write_text(usuarios_internos(generar_hash(env["WAZUH_ADMIN_PASS"]),
                                      generar_hash(env["WAZUH_DASHBOARD_PASS"])),
                    encoding="utf-8")

    ruta = CONFIG / "wazuh_dashboard" / "wazuh.yml"
    ruta.write_text(parchear_wazuh_yml(ruta.read_text(encoding="utf-8"), env["WAZUH_API_PASS"]),
                    encoding="utf-8")

    print("[ok] Listo. Siguiente paso: generar certificados y levantar (ver README.md).")


if __name__ == "__main__":
    sys.exit(main())

"""P3. Extracción de indicadores: IP, dominio o hash (Sec. 4.5.2)."""
from __future__ import annotations

import ipaddress
import re

from .models import Indicador, TipoIndicador, VistaComun

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_DOMINIO = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$", re.IGNORECASE
)
# Longitud hex -> algoritmo (el perfil distingue por 32, 40 o 64 caracteres)
_LONG_HASH = {32: "md5", 40: "sha1", 64: "sha256"}


def es_ip(valor: str) -> bool:
    try:
        ipaddress.ip_address(valor)
        return True
    except ValueError:
        return False


def es_dominio(valor: str) -> bool:
    return not es_ip(valor) and bool(_DOMINIO.match(valor))


def tipo_hash(valor: str) -> str | None:
    if _HEX.match(valor) and len(valor) in _LONG_HASH:
        return _LONG_HASH[len(valor)]
    return None


def extraer_indicadores(vista: VistaComun) -> list[Indicador]:
    """Devuelve los indicadores presentes. Lista vacía => el paso queda
    'no aplicable' (no es un resultado negativo)."""
    salida: list[Indicador] = []
    vistos: set[tuple[str, str]] = set()

    def agregar(tipo: TipoIndicador, valor: str | None, campo: str) -> None:
        if not valor:
            return
        valor = valor.strip()
        clave = (tipo.value, valor.lower())
        if clave in vistos:
            return
        vistos.add(clave)
        salida.append(Indicador(tipo, valor, campo))

    for campo in ("ip_origen", "ip_destino"):
        v = getattr(vista, campo)
        if v and es_ip(v):
            agregar(TipoIndicador.IP, v, campo)
    if vista.dominio and es_dominio(vista.dominio):
        agregar(TipoIndicador.DOMINIO, vista.dominio, "dominio")
    if vista.archivo_hash and tipo_hash(vista.archivo_hash):
        agregar(TipoIndicador.HASH, vista.archivo_hash.lower(), "archivo_hash")
    return salida

"""P2. Normalización: documento original de Wazuh -> VistaComun (Tabla 4.14).

Los nombres de campo de origen dependen de los decodificadores del laboratorio;
por eso el mapeo está concentrado en MAPA_CAMPOS y se confirma en el Sprint 4.
Un campo que falta se registra en `campos_ausentes`; no se completa ni se supone.
"""
from __future__ import annotations

from typing import Any, Optional

from .models import TipoAlerta, VistaComun

# campo de la vista común -> ruta en el documento (a confirmar en el laboratorio)
MAPA_CAMPOS: dict[str, str] = {
    "marca_tiempo": "@timestamp",
    "regla_id": "rule.id",
    "regla_nivel": "rule.level",
    "regla_descripcion": "rule.description",
    "agente_id": "agent.id",
    "agente_nombre": "agent.name",
    "ip_origen": "data.srcip",
    "ip_destino": "data.dstip",
    "usuario": "data.srcuser",
    "dominio": "data.hostname",
    "archivo_ruta": "syscheck.path",
    "archivo_hash": "syscheck.sha256_after",
    "evento": "syscheck.event",
}

# Campos obligatorios según el tipo (Sec. 4.4.2, "Validación").
OBLIGATORIOS: dict[TipoAlerta, tuple[str, ...]] = {
    TipoAlerta.AUTENTICACION: (
        "marca_tiempo", "regla_id", "regla_nivel", "agente_id", "ip_origen",
    ),
    TipoAlerta.CAMBIO_ARCHIVOS: (
        "marca_tiempo", "regla_id", "regla_nivel", "agente_id", "archivo_ruta",
        "archivo_hash", "evento",
    ),
    TipoAlerta.ACTIVIDAD_RED: (
        "marca_tiempo", "regla_id", "regla_nivel", "agente_id", "ip_origen",
    ),
    TipoAlerta.DESCONOCIDO: ("marca_tiempo", "regla_id", "regla_nivel", "agente_id"),
}

# Evidencia mínima que se conserva (Sec. 3.4.5: solo lo necesario).
CAMPOS_EVIDENCIA: tuple[str, ...] = tuple(MAPA_CAMPOS.values()) + ("full_log",)


def _get(doc: dict[str, Any], ruta: str) -> Any:
    """Lee una ruta con puntos. Acepta también claves planas 'a.b' (Wazuh a veces
    las entrega así en `_source`)."""
    if ruta in doc:
        return doc[ruta]
    actual: Any = doc
    for parte in ruta.split("."):
        if not isinstance(actual, dict) or parte not in actual:
            return None
        actual = actual[parte]
    return actual


def clasificar_tipo(doc: dict[str, Any]) -> TipoAlerta:
    """Deriva el tipo a partir de rule.groups. Heurística inicial; se ajusta
    con los grupos reales que genere el laboratorio."""
    grupos = _get(doc, "rule.groups") or []
    if isinstance(grupos, str):
        grupos = [grupos]
    g = {str(x).lower() for x in grupos}
    if _get(doc, "syscheck.path") or g & {"syscheck", "syscheck_entry_added",
                                           "syscheck_entry_modified",
                                           "syscheck_entry_deleted"}:
        return TipoAlerta.CAMBIO_ARCHIVOS
    if g & {"authentication_failed", "authentication_success", "authentication_failures",
            "sshd", "pam", "syslog", "invalid_login"}:
        return TipoAlerta.AUTENTICACION
    if g & {"firewall", "ids", "suricata", "web", "network"}:
        return TipoAlerta.ACTIVIDAD_RED
    return TipoAlerta.DESCONOCIDO


def _a_entero(valor: Any) -> Optional[int]:
    try:
        return int(valor)
    except (TypeError, ValueError):
        return None


def normalizar(doc: dict[str, Any], id_alerta: Optional[str] = None) -> VistaComun:
    vista = VistaComun(id_alerta=id_alerta or doc.get("id") or doc.get("_id"))
    vista.tipo_alerta = clasificar_tipo(doc)

    for campo, ruta in MAPA_CAMPOS.items():
        valor = _get(doc, ruta)
        if campo == "regla_nivel":
            valor = _a_entero(valor)
        if valor in (None, ""):
            valor = None
        setattr(vista, campo, valor if valor is None or campo == "regla_nivel" else str(valor))

    if vista.usuario is None:  # autenticaciones: algunos decodificadores usan dstuser
        alt = _get(doc, "data.dstuser")
        if alt:
            vista.usuario = str(alt)

    for campo in OBLIGATORIOS[vista.tipo_alerta]:
        if getattr(vista, campo) is None:
            vista.campos_ausentes.append(campo)

    for ruta in CAMPOS_EVIDENCIA:
        valor = _get(doc, ruta)
        if valor is not None:
            vista.evidencia_minima[ruta] = valor
    return vista

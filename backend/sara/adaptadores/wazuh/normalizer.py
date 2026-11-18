"""P2. Normalización: documento original de Wazuh -> VistaComun (Tabla 4.14).

Nombres de campo CONFIRMADOS con alertas reales del laboratorio (Wazuh 4.14.10,
corrida del 2026-11-18; fixtures en tests/fixtures/). Cada campo de la vista puede
venir en varias rutas según el decodificador; se toma la primera que exista.
Un campo que falta se registra en `campos_ausentes`; no se completa ni se supone.

Identificador: la vista usa SIEMPRE el `_id` del índice (el mismo que sirve para
buscar la alerta y para excluirla de sus relacionadas). El `id` propio de Wazuh se
conserva aparte, en la evidencia («id_wazuh»).
"""
from __future__ import annotations

from typing import Any, Optional

from sara.dominio.models import TipoAlerta, VistaComun

DATO_NO_DISPONIBLE = "dato no disponible"

# campo de la vista común -> rutas posibles en el documento, en orden de preferencia
MAPA_CAMPOS: dict[str, tuple[str, ...]] = {
    "marca_tiempo": ("@timestamp",),
    "regla_id": ("rule.id",),
    "regla_nivel": ("rule.level",),
    "regla_descripcion": ("rule.description",),
    "agente_id": ("agent.id",),
    "agente_nombre": ("agent.name",),
    # sshd y kernel (cortafuegos): srcip/dstip; eve.json tipo Suricata: src_ip/dest_ip
    "ip_origen": ("data.srcip", "data.src_ip"),
    "ip_destino": ("data.dstip", "data.dest_ip"),
    # sshd pone la cuenta atacada en dstuser; srcuser se mantiene por otros decodificadores
    "usuario": ("data.srcuser", "data.dstuser"),
    "dominio": ("data.dns.rrname",),
    "archivo_ruta": ("syscheck.path",),
    "archivo_hash": ("syscheck.sha256_after",),
    "evento": ("syscheck.event",),
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

# Evidencia mínima (Sec. 3.4.5: solo lo necesario), por tipo de alerta. Cada entrada
# es nombre -> rutas posibles. Si ninguna ruta existe, el valor es DATO_NO_DISPONIBLE
# (nunca texto inventado ni cadena vacía). Las entradas que no aplican al tipo no se
# listan (RNF-07: no aplicable ≠ ausente).
_EVIDENCIA_COMUN: dict[str, tuple[str, ...]] = {
    "id_wazuh": ("id",),
    "marca_tiempo": ("@timestamp",),
    "regla_id": ("rule.id",),
    "regla_nivel": ("rule.level",),
    "regla_descripcion": ("rule.description",),
    "agente_id": ("agent.id",),
    "agente_nombre": ("agent.name",),
    "full_log": ("full_log",),
}
_EVIDENCIA_RED: dict[str, tuple[str, ...]] = {
    "ip_origen": MAPA_CAMPOS["ip_origen"],
    "ip_destino": MAPA_CAMPOS["ip_destino"],
}
EVIDENCIA: dict[TipoAlerta, dict[str, tuple[str, ...]]] = {
    TipoAlerta.AUTENTICACION: _EVIDENCIA_COMUN | {
        "ip_origen": MAPA_CAMPOS["ip_origen"],
        "usuario": MAPA_CAMPOS["usuario"],
    },
    TipoAlerta.CAMBIO_ARCHIVOS: _EVIDENCIA_COMUN | {
        "archivo_ruta": ("syscheck.path",),
        "evento": ("syscheck.event",),
        "archivo_hash": ("syscheck.sha256_after",),
    },
    TipoAlerta.ACTIVIDAD_RED: _EVIDENCIA_COMUN | _EVIDENCIA_RED | {
        "firma": ("data.alert.signature",),
        "dominio": MAPA_CAMPOS["dominio"],
    },
    TipoAlerta.DESCONOCIDO: dict(_EVIDENCIA_COMUN),
}

# ---- Clasificación ----
# SOLO cubre reglas y grupos CATALOGADOS, comprobados con alertas reales del
# laboratorio (2026-11-18). Cualquier otra alerta queda DESCONOCIDO y su prioridad es
# «Información insuficiente» (nunca baja). Ampliar la lista exige una alerta real que
# la respalde y una prueba.
REGLAS_CATALOGADAS: dict[str, TipoAlerta] = {
    # 40112 «Multiple authentication failures followed by a success» trae los grupos
    # ['syslog', 'attacks']: ninguno identifica la autenticación, por eso va explícita.
    # Se clasifica por rule.id y NO por el grupo «attacks», que en el conjunto de
    # reglas de Wazuh abarca ataques de otros tipos.
    "40112": TipoAlerta.AUTENTICACION,
}
GRUPOS_CAMBIO_ARCHIVOS = frozenset({"syscheck", "syscheck_entry_added",
                                    "syscheck_entry_modified", "syscheck_entry_deleted"})
GRUPOS_AUTENTICACION = frozenset({"sshd", "authentication_failed",
                                  "authentication_failures", "authentication_success"})
GRUPOS_RED = frozenset({"firewall", "ids", "suricata"})


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


def _primero(doc: dict[str, Any], rutas: tuple[str, ...]) -> tuple[Any, Optional[str]]:
    """Primer valor no vacío entre las rutas, con la ruta de donde salió."""
    for ruta in rutas:
        valor = _get(doc, ruta)
        if valor not in (None, ""):
            return valor, ruta
    return None, None


def clasificar_tipo(doc: dict[str, Any]) -> TipoAlerta:
    """Tipo de alerta según reglas y grupos catalogados (ver REGLAS_CATALOGADAS)."""
    regla = _get(doc, "rule.id")
    if regla is not None and str(regla) in REGLAS_CATALOGADAS:
        return REGLAS_CATALOGADAS[str(regla)]
    grupos = _get(doc, "rule.groups") or []
    if isinstance(grupos, str):
        grupos = [grupos]
    g = {str(x).lower() for x in grupos}
    if _get(doc, "syscheck.path") or g & GRUPOS_CAMBIO_ARCHIVOS:
        return TipoAlerta.CAMBIO_ARCHIVOS
    if g & GRUPOS_AUTENTICACION:
        return TipoAlerta.AUTENTICACION
    if g & GRUPOS_RED:
        return TipoAlerta.ACTIVIDAD_RED
    return TipoAlerta.DESCONOCIDO


def _a_entero(valor: Any) -> Optional[int]:
    try:
        return int(valor)
    except (TypeError, ValueError):
        return None


def evidencia(doc: dict[str, Any], tipo: TipoAlerta) -> dict[str, Any]:
    """Evidencia mínima con su procedencia (RNF-05): ruta de origen de cada dato."""
    salida: dict[str, Any] = {}
    procedencia: dict[str, Optional[str]] = {}
    for nombre, rutas in EVIDENCIA[tipo].items():
        valor, ruta = _primero(doc, rutas)
        salida[nombre] = DATO_NO_DISPONIBLE if valor is None else valor
        procedencia[nombre] = ruta
    salida["procedencia"] = procedencia
    return salida


def normalizar(doc: dict[str, Any], id_alerta: Optional[str] = None) -> VistaComun:
    """`id_alerta` es el `_id` del índice; si no se pasa, se toma `doc["_id"]`.
    Nunca se usa el `id` de Wazuh como identificador de la alerta."""
    vista = VistaComun(id_alerta=id_alerta or doc.get("_id"))
    vista.tipo_alerta = clasificar_tipo(doc)

    for campo, rutas in MAPA_CAMPOS.items():
        valor, _ = _primero(doc, rutas)
        if campo == "regla_nivel":
            valor = _a_entero(valor)
        setattr(vista, campo, valor if valor is None or campo == "regla_nivel" else str(valor))

    for campo in OBLIGATORIOS[vista.tipo_alerta]:
        if getattr(vista, campo) is None:
            vista.campos_ausentes.append(campo)

    vista.evidencia_minima = evidencia(doc, vista.tipo_alerta)
    return vista

"""Normalizador con alertas REALES del laboratorio (Wazuh 4.14.10, 2026-11-18).

Las fixtures salen de lab/capturas/crudas/ (corrida de los 12 pares) sin modificar.
Solo contienen datos del laboratorio: lo comprueba test_fixtures_solo_datos_del_laboratorio.
"""
import ipaddress
import json
import re
from pathlib import Path

import pytest

from sara.adaptadores.wazuh import indexador as ix
from sara.adaptadores.wazuh.normalizer import (DATO_NO_DISPONIBLE, clasificar_tipo,
                                                normalizar)
from sara.aplicacion import pipeline
from sara.dominio.models import Activo, Importancia, Nivel, TipoAlerta, VistaComun

FIXTURES = Path(__file__).parent / "fixtures"


def cargar(nombre: str) -> dict:
    return json.loads((FIXTURES / f"{nombre}.json").read_text(encoding="utf-8"))


TODAS = sorted(f.stem for f in FIXTURES.glob("*.json"))

ESPERADO = {
    # fixture: (tipo, campos de la vista que deben coincidir)
    "auth_5760": (TipoAlerta.AUTENTICACION, {"regla_id": "5760", "regla_nivel": 5,
                  "agente_id": "001", "ip_origen": "203.0.113.10", "usuario": "operador"}),
    "auth_40112": (TipoAlerta.AUTENTICACION, {"regla_id": "40112", "regla_nivel": 12,
                   "agente_id": "001", "ip_origen": "203.0.113.11", "usuario": "operador"}),
    "fim_550": (TipoAlerta.CAMBIO_ARCHIVOS, {"regla_id": "550", "regla_nivel": 7,
                "archivo_ruta": "/etc/passwd", "evento": "modified"}),
    "fim_554": (TipoAlerta.CAMBIO_ARCHIVOS, {"regla_id": "554", "regla_nivel": 5,
                "agente_id": "004", "archivo_ruta": "/tmp/prueba_a.com", "evento": "added"}),
    "fim_553": (TipoAlerta.CAMBIO_ARCHIVOS, {"regla_id": "553", "regla_nivel": 7,
                "archivo_ruta": "/var/log/auth.log", "evento": "deleted"}),
    "red_86601_suricata": (TipoAlerta.ACTIVIDAD_RED, {"regla_id": "86601", "regla_nivel": 3,
                           "ip_origen": "10.10.0.11", "ip_destino": "203.0.113.50"}),
    "red_86601_dns": (TipoAlerta.ACTIVIDAD_RED, {"regla_id": "86601", "agente_id": "004",
                      "ip_origen": "10.10.0.14", "dominio": "servicio-a.test"}),
    "red_4151_firewall": (TipoAlerta.ACTIVIDAD_RED, {"regla_id": "4151", "regla_nivel": 10,
                          "agente_id": "002", "ip_origen": "10.10.0.41",
                          "ip_destino": "10.10.0.12"}),
}


def test_hay_una_fixture_por_cada_tipo_de_alerta_observado():
    assert set(TODAS) == set(ESPERADO)


@pytest.mark.parametrize("nombre", sorted(ESPERADO))
def test_alerta_real_completa(nombre):
    tipo, campos = ESPERADO[nombre]
    v = normalizar(cargar(nombre))
    assert v.tipo_alerta is tipo
    assert v.campos_ausentes == []
    for campo, valor in campos.items():
        assert getattr(v, campo) == valor, campo


# ---------- identificador único ----------
@pytest.mark.parametrize("nombre", TODAS)
def test_id_es_el_del_indice_y_el_de_wazuh_va_aparte(nombre):
    doc = cargar(nombre)
    v = normalizar(doc)
    assert v.id_alerta == doc["_id"]
    assert v.id_alerta != doc["id"]
    assert v.evidencia_minima["id_wazuh"] == doc["id"]


def test_sin_id_del_indice_no_se_usa_el_de_wazuh():
    doc = cargar("auth_5760")
    del doc["_id"]
    assert normalizar(doc).id_alerta is None


# ---------- evidencia ----------
@pytest.mark.parametrize("nombre", TODAS)
def test_evidencia_sin_cadenas_vacias_ni_none(nombre):
    ev = normalizar(cargar(nombre)).evidencia_minima
    for clave, valor in ev.items():
        if clave != "procedencia":
            assert valor not in (None, ""), clave


def test_evidencia_de_red_trae_ips_firma_y_dominio():
    ev = normalizar(cargar("red_86601_dns")).evidencia_minima
    assert ev["ip_origen"] == "10.10.0.14" and ev["ip_destino"] == "10.10.0.53"
    assert ev["firma"] == "SARA-LAB consulta DNS a dominio de prueba"
    assert ev["dominio"] == "servicio-a.test"
    assert ev["procedencia"]["ip_origen"] == "data.src_ip"


def test_alerta_tipo_suricata_sin_full_log_dice_dato_no_disponible():
    ev = normalizar(cargar("red_86601_suricata")).evidencia_minima
    assert ev["full_log"] == DATO_NO_DISPONIBLE and ev["procedencia"]["full_log"] is None
    assert ev["dominio"] == DATO_NO_DISPONIBLE          # esta alerta no es DNS


def test_cortafuegos_sin_firma_dice_dato_no_disponible():
    ev = normalizar(cargar("red_4151_firewall")).evidencia_minima
    assert ev["firma"] == DATO_NO_DISPONIBLE
    assert ev["ip_origen"] == "10.10.0.41" and ev["procedencia"]["ip_origen"] == "data.srcip"
    assert ev["full_log"].startswith("Nov 18")


def test_evidencia_de_autenticacion_trae_el_usuario_real():
    ev = normalizar(cargar("auth_5760")).evidencia_minima
    assert ev["usuario"] == "operador" and ev["procedencia"]["usuario"] == "data.dstuser"


def test_evidencia_de_archivos_no_lista_campos_que_no_aplican():
    ev = normalizar(cargar("fim_550")).evidencia_minima
    assert "ip_origen" not in ev and "firma" not in ev     # no aplica ≠ no disponible
    assert ev["archivo_hash"] == cargar("fim_550")["syscheck"]["sha256_after"]


# ---------- clasificación ----------
def test_40112_es_autenticacion_por_regla_explicita():
    doc = cargar("auth_40112")
    assert doc["rule"]["groups"] == ["syslog", "attacks"]
    assert clasificar_tipo(doc) is TipoAlerta.AUTENTICACION


@pytest.mark.parametrize("grupos", [["syslog"], ["attacks"], ["syslog", "attacks"], ["web"]])
def test_grupos_no_catalogados_quedan_desconocidos(grupos):
    doc = {"rule": {"id": "99999", "level": 3, "groups": grupos}}
    assert clasificar_tipo(doc) is TipoAlerta.DESCONOCIDO


def test_no_clasificada_es_informacion_insuficiente_y_nunca_baja():
    doc = cargar("auth_5760") | {"rule": {"id": "99999", "level": 3, "groups": ["syslog"],
                                          "description": "regla no catalogada"}}
    catalogo = {"001": Activo("001", "srv-web", "web", Importancia.BAJA)}
    caso = pipeline.investigar(doc, catalogo, normalizar)
    # con la matriz habría salido Baja (nivel 3, activo Baja)
    assert caso.vista.tipo_alerta is TipoAlerta.DESCONOCIDO
    assert caso.prioridad.nivel is Nivel.INSUFICIENTE
    assert any("no está catalogada" in m for m in caso.prioridad.motivos)


# ---------- relacionadas (sin red: se captura la consulta) ----------
class IndexadorFalso(ix.IndexadorWazuh):
    def __init__(self, respuesta):
        self.consultas, self.respuesta = [], respuesta

    def _buscar(self, cuerpo):
        self.consultas.append(cuerpo)
        return self.respuesta


def test_relacionadas_excluye_la_propia_alerta_por_su_id_del_indice():
    doc = cargar("red_86601_suricata")
    v = normalizar(doc)
    falso = IndexadorFalso({"hits": {"hits": [{"_id": "otra-1"}]}})
    assert falso.relacionadas(v) == ["otra-1"]
    q = falso.consultas[0]["query"]["bool"]
    assert q["must_not"] == [{"ids": {"values": [doc["_id"]]}}]
    assert {"term": {"data.srcip": "10.10.0.11"}} in q["should"]
    assert {"term": {"data.src_ip": "10.10.0.11"}} in q["should"]


def test_relacionadas_sin_id_del_indice_falla_y_no_consulta():
    falso = IndexadorFalso({})
    with pytest.raises(ValueError):
        falso.relacionadas(VistaComun(marca_tiempo="t", agente_id="001"))
    assert falso.consultas == []


# ---------- las fixtures solo tienen datos del laboratorio (RNF-03) ----------
PERMITIDAS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24",
                                                "203.0.113.0/24", "10.10.0.0/24")]


def _valores(x):
    if isinstance(x, dict):
        for v in x.values():
            yield from _valores(v)
    elif isinstance(x, list):
        for v in x:
            yield from _valores(v)
    else:
        yield str(x)


@pytest.mark.parametrize("nombre", TODAS)
def test_fixtures_solo_datos_del_laboratorio(nombre):
    doc = cargar(nombre)
    for valor in _valores(doc):
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", valor):
            assert any(ipaddress.ip_address(ip) in n for n in PERMITIDAS), ip
        assert not re.search(r"@|C:\\|/home/|/Users/", valor), valor
    usuarios = {doc.get("data", {}).get(k) for k in ("srcuser", "dstuser")} - {None}
    assert usuarios <= {"operador", "ana.lab", "luis.lab"}
    assert doc["agent"]["name"] in {"srv-web", "srv-bd", "pc-analista", "pc-lab-01", "pc-nuevo"}

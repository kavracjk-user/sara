"""PR-10 — el usuario con el que SARA lee Wazuh NO puede escribir (RNF-02).

Todos los intentos de escritura apuntan a un índice que no existe
(`wazuh-alerts-4.x-pr10-prueba`) y a un documento que no existe: si el usuario
estuviera mal configurado y la operación se aceptara, no se tocaría ninguna alerta
real y la prueba fallaría diciendo exactamente qué operación quedó permitida.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.integracion

INDICE_PRUEBA = "wazuh-alerts-4.x-pr10-prueba"   # coincide con wazuh-alerts-*, no existe
DOC = {"nota": "PR-10: este documento no debería existir", "sintetico": True}
PROHIBIDO = 403


def test_el_lector_no_es_el_administrador(lector):
    assert lector.usuario != "admin"


def test_puede_consultar_alertas(lector):
    codigo, cuerpo = lector.pedir("POST", "wazuh-alerts-*/_search",
                                  {"size": 1, "query": {"match_all": {}}})
    assert codigo == 200, cuerpo


@pytest.mark.parametrize("nombre,metodo,ruta,cuerpo", [
    ("indexar un documento", "POST", f"{INDICE_PRUEBA}/_doc", DOC),
    ("indexar con id", "PUT", f"{INDICE_PRUEBA}/_doc/pr10", DOC),
    ("actualizar un documento", "POST", f"{INDICE_PRUEBA}/_update/pr10", {"doc": DOC}),
    ("borrar un documento", "DELETE", f"{INDICE_PRUEBA}/_doc/pr10", None),
    ("borrar por consulta", "POST", f"{INDICE_PRUEBA}/_delete_by_query",
     {"query": {"ids": {"values": ["pr10"]}}}),
    ("crear un índice de alertas", "PUT", INDICE_PRUEBA, None),
    ("borrar un índice de alertas", "DELETE", INDICE_PRUEBA, None),
    ("crear un índice ajeno", "PUT", "sara-pr10-prueba", None),
])
def test_no_puede_escribir(lector, nombre, metodo, ruta, cuerpo):
    codigo, respuesta = lector.pedir(metodo, ruta, cuerpo)
    assert codigo == PROHIBIDO, f"El lector pudo intentar «{nombre}»: HTTP {codigo} {respuesta}"


def test_no_puede_escribir_en_lote(lector):
    lote = f'{{"index":{{"_index":"{INDICE_PRUEBA}","_id":"pr10"}}}}\n{{"sintetico":true}}\n'
    codigo, respuesta = lector.pedir("POST", "_bulk", ndjson=lote)
    # _bulk puede responder 403 directo, o 200 con el error dentro de cada elemento.
    assert codigo == PROHIBIDO or (
        '"errors":true' in respuesta.replace(" ", "") and "security_exception" in respuesta
    ), f"HTTP {codigo} {respuesta}"


@pytest.mark.parametrize("ruta", [
    "wazuh-monitoring-*/_search",        # otros índices de Wazuh
    "wazuh-states-vulnerabilities-*/_search",
    "_plugins/_security/api/internalusers",   # administración de usuarios
])
def test_restringido_a_las_alertas(lector, ruta):
    codigo, respuesta = lector.pedir("GET", ruta)
    assert codigo == PROHIBIDO, f"El lector pudo leer {ruta}: HTTP {codigo} {respuesta[:200]}"

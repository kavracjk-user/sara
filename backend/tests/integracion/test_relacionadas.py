"""Identificador único y alertas relacionadas contra el indexador real del laboratorio.

Necesita alertas de la corrida de los 12 pares (lab/eventos). Solo lectura.
"""
import pytest

from sara.adaptadores.wazuh.normalizer import normalizar

pytestmark = pytest.mark.integracion


def _una_alerta(indexador, regla: str) -> dict:
    res = indexador._buscar({"size": 1, "sort": [{"timestamp": "asc"}],
                             "query": {"term": {"rule.id": regla}}})
    golpes = res["hits"]["hits"]
    if not golpes:
        pytest.skip(f"No hay alertas {regla} en el índice: corre primero los pares.")
    return golpes[0]["_source"] | {"_id": golpes[0]["_id"]}


@pytest.mark.parametrize("regla", ["5760", "550", "86601", "4151"])
def test_una_alerta_no_es_relacionada_de_si_misma(indexador, regla):
    doc = _una_alerta(indexador, regla)
    vista = normalizar(doc)
    assert vista.id_alerta == doc["_id"] != doc["id"]
    relacionadas = indexador.relacionadas(vista, ventana="1h", maximo=100)
    assert vista.id_alerta not in relacionadas
    assert relacionadas, "el mismo agente tuvo otras alertas en la ventana"


def test_alerta_por_id_usa_el_id_del_indice(indexador):
    doc = _una_alerta(indexador, "5760")
    encontrada = indexador.alerta_por_id(doc["_id"])
    assert encontrada is not None and encontrada["_id"] == doc["_id"]
    assert indexador.alerta_por_id(doc["id"]) is None      # el id de Wazuh no sirve aquí


def test_relacionadas_por_ip_en_alertas_tipo_suricata(indexador):
    doc = _una_alerta(indexador, "86601")
    vista = normalizar(doc)
    assert vista.ip_origen == doc["data"]["src_ip"]
    relacionadas = indexador.relacionadas(vista, ventana="1h", maximo=100)
    assert doc["_id"] not in relacionadas

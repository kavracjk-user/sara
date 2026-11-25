"""Flujo de la fase 3 sin servicios: dependencias falsas en memoria, sin Prefect en marcha.

Se prueba `flujo_investigacion` (la lógica que el flujo de Prefect orquesta) con una
alerta REAL del laboratorio (tests/fixtures).
"""
import inspect
import json
import os
from pathlib import Path

import pytest

from sara.adaptadores.wazuh.normalizer import normalizar
from sara.dominio.models import Activo, Caso, Estado, Importancia, Nivel

flows = pytest.importorskip("sara.interfaces.flows",
                            reason="Prefect no instalado: usa backend/.venv (requirements.txt)")

FIXTURES = Path(__file__).parent / "fixtures"


def cargar(nombre):
    return json.loads((FIXTURES / f"{nombre}.json").read_text(encoding="utf-8"))


class FuenteFalsa:
    def __init__(self, docs, relacionadas=None, falla_lectura=None):
        self.docs, self._rel, self.falla_lectura = docs, relacionadas or {}, falla_lectura
        self.lecturas = 0

    def alerta_por_id(self, id_alerta):
        self.lecturas += 1
        if self.falla_lectura:
            raise self.falla_lectura
        return self.docs.get(id_alerta)

    def relacionadas(self, vista):
        r = self._rel
        if isinstance(r, Exception):
            raise r
        return r.get(vista.id_alerta, [])


class CatalogoFalso:
    def __init__(self, activos=None, falla=None):
        self.activos, self.falla = activos or {}, falla

    def obtener(self, id_agente):
        if self.falla:
            raise self.falla
        return self.activos.get(id_agente)


class RepositorioFalso:
    def __init__(self, falla=None):
        self.casos: dict[str, Caso] = {}
        self.falla = falla

    def guardar(self, caso):
        if self.falla:
            raise self.falla
        self.casos[caso.vista.id_alerta] = caso

    def obtener(self, id_alerta):
        return self.casos.get(id_alerta)

    def listar(self):
        return list(self.casos.values())


CATALOGO = {"001": Activo("001", "srv-web", "Servidor web de pruebas", Importancia.ALTA)}


def deps(doc=None, **kw):
    docs = {doc["_id"]: doc} if doc else {}
    return flows.Dependencias(
        kw.pop("fuente", None) or FuenteFalsa(docs, kw.pop("relacionadas", None)),
        kw.pop("catalogo", None) or CatalogoFalso(CATALOGO),
        kw.pop("repositorio", None) or RepositorioFalso(), normalizar)


def test_alerta_investigada_guardada_y_releida():
    doc = cargar("auth_5760")
    d = deps(doc, relacionadas={doc["_id"]: ["otra-1"]})
    caso = flows.flujo_investigacion(doc["_id"], d)
    assert d.repositorio.obtener(doc["_id"]) is caso
    assert [p.paso for p in caso.pasos][:2] == [flows.PASO_LECTURA, "P2_normalizacion"]
    assert caso.pasos[0].estado is Estado.CON_RESULTADO
    assert caso.pasos[0].resultado == {"_id": doc["_id"]}    # no se guarda el documento
    assert caso.alertas_relacionadas == ["otra-1"]
    assert caso.prioridad.nivel is Nivel.ALTA                  # 5 => Bajo; activo Alta => Media; +1


def test_alerta_inexistente_es_sin_resultado_y_no_se_guarda():
    d = deps()
    caso = flows.flujo_investigacion("no-existe", d)
    assert caso.pasos[0].estado is Estado.SIN_RESULTADO
    assert caso.prioridad.nivel is Nivel.INSUFICIENTE
    assert d.repositorio.casos == {}


def test_fallo_de_lectura_es_fallido_con_reintentos_y_no_se_guarda():
    fuente = FuenteFalsa({}, falla_lectura=ConnectionError("indexador caído"))
    d = deps(fuente=fuente)
    caso = flows.flujo_investigacion("x", d)
    assert caso.pasos[0].estado is Estado.FALLIDO and "indexador caído" in caso.pasos[0].error
    assert fuente.lecturas == 3                                # 1 intento + 2 reintentos
    assert caso.prioridad.nivel is Nivel.INSUFICIENTE and d.repositorio.casos == {}


def test_paso_que_falla_queda_fallido_sin_tumbar_el_flujo():
    doc = cargar("red_4151_firewall")
    d = deps(doc, relacionadas=ConnectionError("sin conexión simulada"))
    caso = flows.flujo_investigacion(doc["_id"], d)
    estados = {p.paso: p.estado for p in caso.pasos}
    assert estados["P4_alertas_relacionadas"] is Estado.FALLIDO
    assert d.repositorio.obtener(doc["_id"]) is caso           # se guardó igual
    assert caso.prioridad.nivel is not Nivel.BAJA


def test_catalogo_caido_es_fallido_y_no_sin_resultado():
    doc = cargar("auth_5760")
    d = deps(doc, catalogo=CatalogoFalso(falla=ConnectionError("PostgreSQL caído")))
    caso = flows.flujo_investigacion(doc["_id"], d)
    p4 = next(p for p in caso.pasos if p.paso == "P4_catalogo_activos")
    assert p4.estado is Estado.FALLIDO
    assert caso.prioridad.nivel is Nivel.INSUFICIENTE


def test_si_no_se_puede_guardar_el_flujo_falla_a_la_vista():
    doc = cargar("auth_5760")
    d = deps(doc, repositorio=RepositorioFalso(falla=ConnectionError("PostgreSQL caído")))
    with pytest.raises(RuntimeError, match="NO se guardó"):
        flows.flujo_investigacion(doc["_id"], d)


def test_agente_099_no_catalogado_es_informacion_insuficiente():
    doc = cargar("red_86601_suricata") | {"agent": {"id": "099", "name": "pc-nuevo"}}
    caso = flows.flujo_investigacion(doc["_id"], deps(doc))
    assert caso.vista.agente_id == "099" and caso.prioridad.nivel is Nivel.INSUFICIENTE


# ---------- configuración de Prefect ----------
def test_el_flujo_solo_recibe_el_id_de_la_alerta():
    assert list(inspect.signature(flows.investigacion_inicial.fn).parameters) == ["id_alerta"]


def test_prefect_sin_analitica_ni_interfaz_y_fuera_de_git():
    assert os.environ["PREFECT_SERVER_ANALYTICS_ENABLED"] == "false"
    assert os.environ["PREFECT_SERVER_UI_ENABLED"] == "false"
    assert os.environ["PREFECT_HOME"].endswith(".prefect")


def test_tareas_sin_reintentos_propios_ni_cache():
    # Los reintentos y tiempos los aplica ejecutar_paso (una sola regla, steps.py).
    for t in (flows.leer_alerta_t, flows.investigar_alerta_t, flows.guardar_caso_t):
        assert t.retries == 0

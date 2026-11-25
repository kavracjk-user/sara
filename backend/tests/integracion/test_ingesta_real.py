"""Ingesta (fase 4b) con las alertas REALES del índice y la base real.

La marca de prueba empieza justo antes de la corrida del 2026-11-18 para acotar el
trabajo. Al terminar se borran los casos creados y la marca: la base queda con 0 casos
y sin marca de avance.
"""
import secrets

import pytest

from sara.adaptadores.postgres.catalogo import CatalogoPostgres
from sara.adaptadores.postgres.marcas import MarcasPostgres
from sara.adaptadores.postgres.repositorio import RepositorioPostgres
from sara.adaptadores.wazuh.normalizer import normalizar
from sara.aplicacion.ingesta import NOMBRE_MARCA, ingerir
from sara.dominio.models import Nivel
from sara.puertos import MarcaIngesta

flows = pytest.importorskip("sara.interfaces.flows", reason="Prefect no instalado")
pytestmark = pytest.mark.integracion

INICIO_CORRIDA = "2026-11-18T04:52:00Z"


@pytest.fixture
def entorno(indexador, conectar_pg):
    nombre = f"prueba-{secrets.token_hex(4)}"
    creados: list[str] = []
    deps = flows.Dependencias(indexador, CatalogoPostgres(conectar_pg),
                              RepositorioPostgres(conectar_pg), normalizar,
                              marcas=MarcasPostgres(conectar_pg))
    yield deps, nombre, creados
    with conectar_pg() as con:
        con.execute("DELETE FROM caso WHERE id_alerta = ANY(%s)", (creados,))
        con.execute("DELETE FROM ingesta_marca WHERE nombre = ANY(%s)", ([nombre, NOMBRE_MARCA],))


def _marca_antes_de(indexador, filtro):
    """Marca que deja como siguiente a la primera alerta que cumple el filtro."""
    primera = indexador._buscar({"size": 1, "sort": [{"timestamp": "asc"}, {"id": "asc"}],
                                 "_source": False, "query": filtro})["hits"]["hits"]
    if not primera:
        pytest.skip("No hay alertas de la corrida en el índice.")
    previa = indexador._buscar({"size": 1, "sort": [{"timestamp": "desc"}, {"id": "desc"}],
                                "_source": ["timestamp"], "search_after": primera[0]["sort"],
                                "query": {"match_all": {}}})["hits"]["hits"]
    return MarcaIngesta(tuple(previa[0]["sort"]), previa[0]["_source"]["timestamp"])


def _ingerir(deps, nombre, creados, reglas, lote, investigar=None):
    r = ingerir(deps.fuente, deps.marcas, deps.repositorio,
                investigar or (lambda i: flows.flujo_investigacion(i, deps)), reglas, lote,
                nombre=nombre)
    creados.extend(r.creados)
    return r


def test_primera_pasada_crea_segunda_no_y_la_marca_avanza(entorno, indexador):
    deps, nombre, creados = entorno
    inicio = _marca_antes_de(indexador, {"range": {"timestamp": {"gte": INICIO_CORRIDA}}})
    deps.marcas.guardar_marca(nombre, inicio)

    # Solo 5760: las 5763 de las mismas corridas se omiten y se cuentan.
    r1 = _ingerir(deps, nombre, creados, ["5760"], lote=30)
    assert r1.leidas == 30 and r1.creadas > 0 and r1.con_error == 0
    assert r1.creadas + r1.omitidas_por_regla + r1.ya_existentes == r1.leidas
    assert r1.omitidas_por_regla_detalle.get("5763", 0) > 0  # las demás reglas se cuentan
    assert sum(r1.omitidas_por_regla_detalle.values()) == r1.omitidas_por_regla
    avance = deps.marcas.leer_marca(nombre)
    assert tuple(avance.orden) > tuple(inicio.orden)         # la marca avanzó

    deps.marcas.guardar_marca(nombre, inicio)                # misma ventana otra vez
    r2 = _ingerir(deps, nombre, creados, ["5760"], lote=30)
    assert r2.creadas == 0 and r2.ya_existentes == r1.creadas


def test_un_fallo_no_detiene_el_lote(entorno, indexador):
    deps, nombre, creados = entorno
    inicio = _marca_antes_de(indexador, {"range": {"timestamp": {"gte": INICIO_CORRIDA}}})
    deps.marcas.guardar_marca(nombre, inicio)
    intentos = []

    def investigar(id_alerta):
        intentos.append(id_alerta)
        if len(intentos) == 2:
            raise ConnectionError("falla simulada en la segunda alerta")
        return flows.flujo_investigacion(id_alerta, deps)

    r = _ingerir(deps, nombre, creados, ["5760", "5763"], lote=30, investigar=investigar)
    assert r.con_error == 1 and r.creadas == len(intentos) - 1 and r.creadas >= 2
    assert r.errores[0]["id"] == intentos[1]
    # La marca quedó antes de la alerta que falló: la próxima vez se reintenta.
    siguientes = deps.fuente.alertas_despues_de(deps.marcas.leer_marca(nombre), 30)
    assert intentos[1] in [a.id for a in siguientes]


def test_alerta_del_099_queda_informacion_insuficiente(entorno, indexador):
    deps, nombre, creados = entorno
    filtro = {"bool": {"filter": [{"term": {"agent.id": "099"}}, {"term": {"rule.id": "86601"}}]}}
    deps.marcas.guardar_marca(nombre, _marca_antes_de(indexador, filtro))
    r = _ingerir(deps, nombre, creados, ["86601"], lote=1)
    assert r.creadas == 1
    caso = deps.repositorio.obtener(r.creados[0])
    assert caso.vista.agente_id == "099" and caso.prioridad.nivel is Nivel.INSUFICIENTE


def test_flujo_de_prefect_de_ingesta(entorno, indexador, conectar_pg):
    deps, _, creados = entorno
    if deps.marcas.leer_marca(NOMBRE_MARCA) is not None:
        pytest.skip("Ya existe una marca real de ingesta: no se toca.")
    deps.marcas.guardar_marca(NOMBRE_MARCA, _marca_antes_de(
        indexador, {"range": {"timestamp": {"gte": INICIO_CORRIDA}}}))
    with flows.usar_dependencias(deps):
        r = flows.ingesta_alertas(["5760"], 5)
    creados.extend(r.creados)
    assert r.leidas == 5 and r.creadas >= 1 and r.con_error == 0

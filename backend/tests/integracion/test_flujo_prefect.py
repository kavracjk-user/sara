"""Fase 3: el flujo REAL de Prefect (servidor temporal en proceso) con alertas reales.

Lee del índice con el usuario de solo consulta, investiga, guarda en PostgreSQL y
relee. Al terminar se borran SOLO los casos creados: la base queda como estaba.
"""
import pytest

from sara.adaptadores.postgres.catalogo import CatalogoPostgres
from sara.adaptadores.postgres.repositorio import RepositorioPostgres
from sara.adaptadores.wazuh.normalizer import normalizar
from sara.dominio.models import Estado, Nivel, TipoAlerta

flows = pytest.importorskip("sara.interfaces.flows", reason="Prefect no instalado")
pytestmark = pytest.mark.integracion

# Reglas catalogadas que dispararon en la corrida del 2026-11-18 (5715 no disparó).
REGLAS = {"5760": TipoAlerta.AUTENTICACION, "5763": TipoAlerta.AUTENTICACION,
          "40112": TipoAlerta.AUTENTICACION, "550": TipoAlerta.CAMBIO_ARCHIVOS,
          "554": TipoAlerta.CAMBIO_ARCHIVOS, "553": TipoAlerta.CAMBIO_ARCHIVOS,
          "86601": TipoAlerta.ACTIVIDAD_RED, "4151": TipoAlerta.ACTIVIDAD_RED}


@pytest.fixture
def entorno(indexador, conectar_pg):
    creados: list[str] = []
    deps = flows.Dependencias(indexador, CatalogoPostgres(conectar_pg),
                              RepositorioPostgres(conectar_pg), normalizar)
    yield deps, creados
    with conectar_pg() as con:
        con.execute("DELETE FROM caso WHERE id_alerta = ANY(%s)", (creados,))


def _id(indexador, filtros):
    res = indexador._buscar({"size": 1, "sort": [{"timestamp": "asc"}],
                             "_source": False, "query": {"bool": {"filter": filtros}}})
    golpes = res["hits"]["hits"]
    if not golpes:
        pytest.skip(f"Sin alertas para {filtros} en el índice.")
    return golpes[0]["_id"]


def _correr(deps, creados, id_alerta):
    creados.append(id_alerta)
    with flows.usar_dependencias(deps):
        return flows.investigacion_inicial(id_alerta)


@pytest.mark.parametrize("regla", sorted(REGLAS))
def test_una_alerta_de_cada_regla_catalogada(entorno, indexador, regla):
    deps, creados = entorno
    id_alerta = _id(indexador, [{"term": {"rule.id": regla}}])
    caso = _correr(deps, creados, id_alerta)
    assert caso.vista.id_alerta == id_alerta and caso.vista.regla_id == regla
    assert caso.vista.tipo_alerta is REGLAS[regla]
    assert caso.vista.campos_ausentes == []
    assert caso.pasos[0].paso == flows.PASO_LECTURA
    assert caso.pasos[0].estado is Estado.CON_RESULTADO
    assert id_alerta not in caso.alertas_relacionadas
    assert caso.prioridad is not None
    assert deps.repositorio.obtener(id_alerta) is not None   # quedó en PostgreSQL


def test_agente_099_queda_informacion_insuficiente(entorno, indexador):
    deps, creados = entorno
    id_alerta = _id(indexador, [{"term": {"agent.id": "099"}}, {"term": {"rule.id": "86601"}}])
    caso = _correr(deps, creados, id_alerta)
    assert caso.vista.agente_id == "099"
    assert caso.prioridad.nivel is Nivel.INSUFICIENTE


class _FuenteSinRelacionadas:
    """El índice real para leer; la búsqueda de relacionadas falla siempre."""

    def __init__(self, real):
        self.real = real

    def alerta_por_id(self, id_alerta):
        return self.real.alerta_por_id(id_alerta)

    def relacionadas(self, vista):
        raise ConnectionError("falla simulada de la consulta de relacionadas")


def test_paso_que_falla_queda_fallido_sin_tumbar_el_flujo(entorno, indexador):
    deps, creados = entorno
    id_alerta = _id(indexador, [{"term": {"rule.id": "5763"}}])
    deps.fuente = _FuenteSinRelacionadas(indexador)
    caso = _correr(deps, creados, id_alerta)
    p4 = next(p for p in caso.pasos if p.paso == "P4_alertas_relacionadas")
    assert p4.estado is Estado.FALLIDO and p4.reintentos == 2
    assert any("pasos fallidos" in m for m in caso.prioridad.motivos)
    assert caso.prioridad.nivel is not Nivel.BAJA


def test_alerta_inexistente_no_crea_caso(entorno, conectar_pg):
    deps, creados = entorno
    caso = _correr(deps, creados, "no-existe-en-el-indice")
    assert caso.pasos[0].estado is Estado.SIN_RESULTADO
    with conectar_pg() as con:
        n = con.execute("SELECT count(*) FROM caso WHERE id_alerta = %s",
                        ("no-existe-en-el-indice",)).fetchone()[0]
    assert n == 0

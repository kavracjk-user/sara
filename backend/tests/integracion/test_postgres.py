"""Persistencia en PostgreSQL contra la base real del laboratorio (fase 2).

Recorrido completo: alerta real del índice -> investigar -> guardar -> releer ->
v_exportacion. Cada prueba borra al terminar SOLO los casos que creó.
"""
import pytest

from sara.adaptadores.postgres.catalogo import CatalogoPostgres
from sara.adaptadores.postgres.repositorio import RepositorioPostgres
from sara.adaptadores.wazuh.normalizer import normalizar
from sara.aplicacion.pipeline import investigar, registrar_decision
from sara.dominio.models import Estado, Importancia, Nivel, TipoAlerta

pytestmark = pytest.mark.integracion


@pytest.fixture
def repo(conectar_pg):
    creados: list[str] = []
    r = RepositorioPostgres(conectar_pg)
    original = r.guardar

    def guardar(caso):
        creados.append(caso.vista.id_alerta)
        original(caso)

    r.guardar = guardar
    yield r
    with conectar_pg() as con:
        con.execute("DELETE FROM caso WHERE id_alerta = ANY(%s)", (creados,))


def _alerta(indexador, consulta):
    res = indexador._buscar({"size": 1, "sort": [{"timestamp": "asc"}], "query": consulta})
    golpes = res["hits"]["hits"]
    if not golpes:
        pytest.skip("No hay alertas de la corrida en el índice.")
    return golpes[0]["_source"] | {"_id": golpes[0]["_id"]}


# ---------- catálogo ----------
def test_catalogo_del_anexo_c(conectar_pg):
    cat = CatalogoPostgres(conectar_pg)
    todos = cat.todos()
    assert {k: a.importancia for k, a in todos.items()} == {
        "001": Importancia.ALTA, "002": Importancia.ALTA,
        "003": Importancia.MEDIA, "004": Importancia.BAJA}
    assert cat.obtener("099") is None                      # no catalogado a propósito
    assert cat.obtener("001").nombre == "srv-web"


# ---------- recorrido completo ----------
def test_alerta_real_investigada_guardada_y_releida(indexador, conectar_pg, repo):
    doc = _alerta(indexador, {"term": {"rule.id": "5763"}})
    catalogo = CatalogoPostgres(conectar_pg).todos()
    caso = investigar(doc, catalogo, normalizar, buscar_relacionadas=indexador.relacionadas)
    repo.guardar(caso)

    leido = repo.obtener(doc["_id"])
    assert leido is not None
    assert leido.vista == caso.vista                       # la vista vuelve idéntica
    assert [(i.tipo, i.valor) for i in leido.indicadores] == \
        [(i.tipo, i.valor) for i in caso.indicadores]
    assert [(p.paso, p.estado) for p in leido.pasos] == [(p.paso, p.estado) for p in caso.pasos]
    assert leido.alertas_relacionadas == caso.alertas_relacionadas
    assert doc["_id"] not in leido.alertas_relacionadas
    assert leido.prioridad == caso.prioridad
    assert leido.t0 == caso.t0 and leido.t1 is None


def test_agente_no_catalogado_099_es_informacion_insuficiente(indexador, conectar_pg, repo):
    doc = _alerta(indexador, {"bool": {"filter": [{"term": {"agent.id": "099"}},
                                                {"term": {"rule.id": "86601"}}]}})
    caso = investigar(doc, CatalogoPostgres(conectar_pg).todos(), normalizar,
                      buscar_relacionadas=indexador.relacionadas)
    repo.guardar(caso)
    leido = repo.obtener(doc["_id"])
    assert leido.vista.agente_id == "099"                  # el dato de la alerta se conserva
    assert leido.prioridad.nivel is Nivel.INSUFICIENTE
    assert any("no figura en el catálogo" in m for m in leido.prioridad.motivos)
    with conectar_pg() as con:
        fk = con.execute("SELECT id_agente FROM caso WHERE id_alerta = %s",
                         (doc["_id"],)).fetchone()[0]
    assert fk is None                                      # FK al catálogo: NULL


def test_estados_de_los_pasos_se_conservan(indexador, conectar_pg, repo):
    doc = _alerta(indexador, {"term": {"rule.id": "550"}})

    def cae(_v):
        raise ConnectionError("sin conexión simulada")

    caso = investigar(doc, CatalogoPostgres(conectar_pg).todos(), normalizar,
                      buscar_relacionadas=cae)
    repo.guardar(caso)
    estados = {p.paso: p.estado for p in repo.obtener(doc["_id"]).pasos}
    assert estados["P4_alertas_relacionadas"] is Estado.FALLIDO
    assert estados["P3_indicadores"] is Estado.CON_RESULTADO
    assert caso.vista.tipo_alerta is TipoAlerta.CAMBIO_ARCHIVOS


# ---------- decisiones y exportación ----------
def test_decisiones_t1_y_exportacion(indexador, conectar_pg, repo):
    doc = _alerta(indexador, {"term": {"rule.id": "40112"}})
    caso = investigar(doc, CatalogoPostgres(conectar_pg).todos(), normalizar,
                      buscar_relacionadas=indexador.relacionadas)
    repo.guardar(caso)

    registrar_decision(caso, "escalar", "Acceso correcto tras fallos repetidos.", Nivel.ALTA)
    t1 = caso.t1
    repo.guardar(caso)
    repo.guardar(caso)                                     # repetir no duplica la decisión
    registrar_decision(caso, "solicitar_mas_informacion", "Confirmar con el dueño.",
                       Nivel.MEDIA)
    repo.guardar(caso)

    leido = repo.obtener(doc["_id"])
    assert leido.t1 == t1                                  # t1 = primera decisión, no cambia
    assert leido.decision == "solicitar_mas_informacion"
    with conectar_pg() as con:
        n = con.execute("""SELECT count(*) FROM decision_humana d JOIN caso c USING (id_caso)
                           WHERE c.id_alerta = %s""", (doc["_id"],)).fetchone()[0]
        fila = con.execute("""SELECT procedimiento, decision, prioridad_sugerida,
                                     minutos_hasta_decision
                              FROM v_exportacion WHERE id_alerta = %s""",
                           (doc["_id"],)).fetchone()
    assert n == 2
    assert fila[0] == "sara" and fila[1] == "escalar"      # la exportación usa la PRIMERA
    assert fila[2] == caso.prioridad.nivel.value and fila[3] >= 0



def test_la_conexion_no_muestra_claves_en_los_informes(conectar_pg):
    # Se compara fuera del assert para que pytest nunca imprima la clave si falla.
    clave = conectar_pg._ConectarPG__env["POSTGRES_PASSWORD"]
    aparece = bool(clave) and clave in repr(conectar_pg)
    assert not aparece, "la clave de PostgreSQL aparece en el repr de la fixture"


# ---------- número de caso (fase 4b) ----------
def test_numeros_consecutivos_sin_reutilizar_y_estables(indexador, conectar_pg, repo):
    catalogo = CatalogoPostgres(conectar_pg).todos()
    ids = []
    for regla in ("5760", "550", "4151"):
        doc = _alerta(indexador, {"term": {"rule.id": regla}})
        caso = investigar(doc, catalogo, normalizar)
        repo.guardar(caso)
        ids.append((doc["_id"], caso))
    n = [repo.numero_caso(i) for i, _ in ids]
    assert n[1] == n[0] + 1 and n[2] == n[1] + 1              # consecutivos

    repo.guardar(ids[0][1])                                     # volver a guardar
    assert repo.numero_caso(ids[0][0]) == n[0]                  # no cambia

    with conectar_pg() as con:                                  # borrar el último
        con.execute("DELETE FROM caso WHERE id_alerta = %s", (ids[2][0],))
    repo.guardar(ids[2][1])                                     # se crea de nuevo
    assert repo.numero_caso(ids[2][0]) == n[2] + 1              # no reutiliza n[2]

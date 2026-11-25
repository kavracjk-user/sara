"""Fase 4: la API real (composición desde el entorno) contra Wazuh y PostgreSQL reales.

alerta real -> POST /investigaciones -> GET /casos/{id} -> POST decisión -> GET /exportacion.
Se borran SOLO los casos creados. Ninguna respuesta de error puede contener credenciales.
"""
import pytest

pytest.importorskip("fastapi", reason="FastAPI no instalado: usa backend/.venv")
from fastapi.testclient import TestClient  # noqa: E402

pytestmark = pytest.mark.integracion

VARIABLES_SECRETAS = ("API_KEY_SARA", "POSTGRES_PASSWORD", "WAZUH_INDEXER_PASS",
                      "WAZUH_ADMIN_PASS", "WAZUH_API_PASS", "WAZUH_DASHBOARD_PASS")


@pytest.fixture
def api(entorno_lab, conectar_pg):
    from sara.interfaces.composicion import crear_app_desde_entorno

    creados: list[str] = []
    cliente = TestClient(crear_app_desde_entorno(entorno_lab), raise_server_exceptions=False)
    cabecera = {"X-API-Key": entorno_lab["API_KEY_SARA"]}
    yield cliente, cabecera, creados
    with conectar_pg() as con:
        con.execute("DELETE FROM caso WHERE id_alerta = ANY(%s)", (creados,))


def _id(indexador, filtros):
    res = indexador._buscar({"size": 1, "sort": [{"timestamp": "asc"}], "_source": False,
                             "query": {"bool": {"filter": filtros}}})
    golpes = res["hits"]["hits"]
    if not golpes:
        pytest.skip(f"Sin alertas para {filtros} en el índice.")
    return golpes[0]["_id"]


def _contiene_secreto(texto, env):
    # Se calcula fuera del assert: si falla, pytest no imprime ningún valor.
    return any(env.get(v) and len(env[v]) >= 4 and env[v] in texto for v in VARIABLES_SECRETAS)


def test_salud_con_dependencias_reales(api):
    cliente, cabecera, _ = api
    r = cliente.get("/salud", headers=cabecera)
    assert r.status_code == 200
    assert r.json() == {"estado": "ok", "dependencias": {"indexador": "disponible",
                                                          "base_de_datos": "disponible"}}


def test_recorrido_completo_con_alerta_real(api, indexador):
    cliente, cabecera, creados = api
    id_caso = _id(indexador, [{"term": {"rule.id": "5763"}}])
    creados.append(id_caso)

    r = cliente.post("/investigaciones", json={"id_alerta": id_caso}, headers=cabecera)
    assert r.status_code == 201, r.json().get("error")
    e = cliente.get(f"/casos/{id_caso}", headers=cabecera).json()
    assert e["alerta"]["regla_id"] == "5763"
    assert e["pasos"][0]["paso"] == "P1_lectura_alerta"
    assert e["pasos"][0]["estado"] == "con_resultado"
    assert id_caso not in e["alertas_relacionadas"]
    assert all(d["procedencia"] for d in e["evidencia"] if d["valor"] != "dato no disponible")
    fin_p1 = e["pasos"][0]["fin"]                      # RNF-05: hora de lectura en UTC
    from datetime import datetime, timezone
    hora = datetime.fromisoformat(fin_p1).astimezone(timezone.utc).isoformat()
    assert all(d["obtenida_en"] == hora for d in e["evidencia"])

    decision = {"decision": "escalar", "justificacion": "Fuerza bruta desde IP externa.",
                "prioridad_considerada": e["prioridad"]["nivel"], "analista": "analista-01"}
    r = cliente.post(f"/casos/{id_caso}/decision", json=decision, headers=cabecera)
    assert r.status_code == 201
    t1 = r.json()["t1"]
    assert cliente.post(f"/casos/{id_caso}/decision", json=decision,
                        headers=cabecera).status_code == 409
    r = cliente.post(f"/casos/{id_caso}/decision", headers=cabecera, json={
        **decision, "decision": "descartar", "justificacion": "Era una prueba del laboratorio."})
    assert r.status_code == 201 and r.json()["t1"] == t1 and len(r.json()["decisiones"]) == 2

    filas = cliente.get("/exportacion", headers=cabecera).json()["casos"]
    fila = next(f for f in filas if f["id"] == id_caso)
    assert fila["decision"] == "escalar" and fila["procedimiento"] == "sara"
    assert fila["completitud"] == 100.0 and fila["minutos_hasta_decision"] >= 0
    csv = cliente.get("/exportacion", params={"formato": "csv"}, headers=cabecera).text
    assert id_caso in csv

    lista = cliente.get("/casos", params={"con_decision": "true"}, headers=cabecera).json()
    assert id_caso in [c["id"] for c in lista["casos"]]


def test_exportacion_coincide_con_la_vista_sql(api, indexador, conectar_pg):
    cliente, cabecera, creados = api
    id_caso = _id(indexador, [{"term": {"rule.id": "40112"}}])
    creados.append(id_caso)
    cliente.post("/investigaciones", json={"id_alerta": id_caso}, headers=cabecera)
    for d in ("escalar", "descartar"):
        cliente.post(f"/casos/{id_caso}/decision", headers=cabecera, json={
            "decision": d, "justificacion": f"Prueba {d}.", "prioridad_considerada": "Alta",
            "analista": "analista-01"})
    fila = next(f for f in cliente.get("/exportacion", headers=cabecera).json()["casos"]
                if f["id"] == id_caso)
    with conectar_pg() as con:
        sql = con.execute("""SELECT decision, prioridad_sugerida, prioridad_considerada
                             FROM v_exportacion WHERE id_alerta = %s""", (id_caso,)).fetchone()
    assert (fila["decision"], fila["prioridad_sugerida"], fila["prioridad_considerada"]) == sql


def test_agente_099_informacion_insuficiente(api, indexador):
    cliente, cabecera, creados = api
    id_caso = _id(indexador, [{"term": {"agent.id": "099"}}, {"term": {"rule.id": "86601"}}])
    creados.append(id_caso)
    e = cliente.post("/investigaciones", json={"id_alerta": id_caso}, headers=cabecera).json()
    assert e["alerta"]["agente_id"] == "099"
    assert e["prioridad"]["nivel"] == "Información insuficiente"


def test_ninguna_respuesta_de_error_contiene_credenciales(api, entorno_lab, indexador):
    cliente, cabecera, creados = api
    id_caso = _id(indexador, [{"term": {"rule.id": "550"}}])
    creados.append(id_caso)
    cliente.post("/investigaciones", json={"id_alerta": id_caso}, headers=cabecera)
    errores = [
        cliente.get("/casos", headers={"X-API-Key": "incorrecta"}),                 # 401
        cliente.get("/casos/noExisteXYZ", headers=cabecera),                         # 404
        cliente.post("/investigaciones", json={"id_alerta": "noExisteXYZ"},
                     headers=cabecera),                                              # 404
        cliente.post("/investigaciones", json={"id_alerta": id_caso},
                     headers=cabecera),                                              # 409
        cliente.post("/investigaciones", json={"id_alerta": "../x"}, headers=cabecera),  # 422
        cliente.post(f"/casos/{id_caso}/decision", json={"decision": "x"},
                     headers=cabecera),                                              # 422
    ]
    assert [r.status_code for r in errores] == [401, 404, 404, 409, 422, 422]
    for r in errores:
        assert set(r.json()) == {"error"}
        filtra = _contiene_secreto(r.text, entorno_lab)
        assert not filtra, f"la respuesta {r.status_code} contiene una credencial"

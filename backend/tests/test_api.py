"""API de la fase 4 sin servicios: TestClient, repositorio en memoria y alertas reales
del laboratorio (tests/fixtures). Las claves de estas pruebas son inventadas."""
import ast
import json
from datetime import timedelta
from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="FastAPI no instalado: usa backend/.venv")
from fastapi.testclient import TestClient  # noqa: E402

from sara.adaptadores.wazuh.normalizer import OBLIGATORIOS, normalizar  # noqa: E402
from sara.aplicacion.casos import ServicioCasos  # noqa: E402
from sara.aplicacion.pipeline import investigar as pipeline_investigar  # noqa: E402
from sara.dominio.models import (Activo, Caso, Estado, Importancia, RegistroPaso,  # noqa: E402
                                 VistaComun, ahora)
from sara.interfaces.api import ConfiguracionAPI, crear_app  # noqa: E402
from sara.interfaces.composicion import ocultador  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
RAIZ = Path(__file__).resolve().parents[2]
CLAVE = "clave-de-prueba-api-123"
SECRETO_BD = "secreto-bd-inventado-456"
CABECERA = {"X-API-Key": CLAVE}
CATALOGO = {"001": Activo("001", "srv-web", "Servidor web de pruebas", Importancia.ALTA),
            "002": Activo("002", "srv-bd", "Base de datos de pruebas", Importancia.ALTA)}


def cargar(nombre):
    return json.loads((FIXTURES / f"{nombre}.json").read_text(encoding="utf-8"))


class RepoMemoria:
    def __init__(self):
        self.casos, self.historial, self.numeros = {}, {}, {}
        self._siguiente = 1

    def guardar(self, caso):
        if caso.vista.id_alerta not in self.numeros:
            self.numeros[caso.vista.id_alerta] = self._siguiente
            self._siguiente += 1
        self.casos[caso.vista.id_alerta] = caso

    def numero_caso(self, id_alerta):
        return self.numeros.get(id_alerta) if id_alerta in self.casos else None

    def obtener(self, id_alerta):
        return self.casos.get(id_alerta)

    def listar(self):
        return list(self.casos.values())

    def decisiones(self, id_alerta):
        return list(self.historial.get(id_alerta, []))

    def registrar_decision(self, id_alerta, decision, t1):
        caso = self.casos[id_alerta]
        if caso.t1 is None:
            caso.t1 = t1
        caso.decision = decision.decision
        self.historial.setdefault(id_alerta, []).append(decision)

    def procedimiento(self, id_alerta):
        return "sara" if id_alerta in self.casos else None

    def relacionadas_de(self, id_alerta):
        from sara.puertos import AlertasRelacionadas
        caso = self.casos.get(id_alerta)
        p4 = next((p for p in (caso.pasos if caso else []) if p.paso == "P4_alertas_relacionadas"
                   and p.estado is Estado.CON_RESULTADO), None)
        r = p4.resultado if p4 else None
        return r if isinstance(r, AlertasRelacionadas) else AlertasRelacionadas(0)


class Mundo:
    """Índice falso con alertas reales + repositorio en memoria."""

    def __init__(self, docs=(), error_lectura=None, error_paso=None):
        self.docs = {d["_id"]: d for d in docs}
        self.repo = RepoMemoria()
        self.error_lectura, self.error_paso = error_lectura, error_paso
        self.relacionadas_fijas = []

    def investigar(self, id_alerta):
        inicio = ahora()
        if self.error_lectura:
            return Caso(vista=VistaComun(id_alerta=id_alerta), pasos=[RegistroPaso(
                "P1_lectura_alerta", Estado.FALLIDO, inicio, ahora(), error=self.error_lectura)])
        doc = self.docs.get(id_alerta)
        if doc is None:
            return Caso(vista=VistaComun(id_alerta=id_alerta), pasos=[RegistroPaso(
                "P1_lectura_alerta", Estado.SIN_RESULTADO, inicio, ahora())])

        def relacionadas(_v):
            if self.error_paso:
                raise ConnectionError(self.error_paso)
            return self.relacionadas_fijas

        caso = pipeline_investigar(doc, CATALOGO, normalizar, buscar_relacionadas=relacionadas,
                                   id_alerta=id_alerta)
        caso.pasos.insert(0, RegistroPaso("P1_lectura_alerta", Estado.CON_RESULTADO, inicio,
                                          ahora(), resultado={"_id": id_alerta}))
        self.repo.guardar(caso)
        return caso


def cliente(mundo, clave=CLAVE, salud=None, **kw):
    servicio = ServicioCasos(mundo.repo, mundo.investigar, lambda t: OBLIGATORIOS[t])
    app = crear_app(ConfiguracionAPI(servicio, clave, salud or {}, ocultar=ocultador(
        [CLAVE, SECRETO_BD]), **kw))
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def mundo():
    return Mundo([cargar("auth_5760"), cargar("fim_550"), cargar("red_86601_suricata"),
                  cargar("red_4151_firewall")])


def crear(c, doc_id):
    r = c.post("/investigaciones", json={"id_alerta": doc_id}, headers=CABECERA)
    assert r.status_code == 201, r.json()
    return r.json()


DECISION = {"decision": "escalar", "justificacion": "Fallos repetidos desde IP externa.",
            "prioridad_considerada": "Alta", "analista": "analista-01"}


# ---------- clave de API ----------
@pytest.mark.parametrize("cabeceras", [{}, {"X-API-Key": "incorrecta"}, {"X-API-Key": ""}])
def test_sin_clave_o_clave_incorrecta_401(mundo, cabeceras):
    c = cliente(mundo)
    for metodo, ruta in [("get", "/salud"), ("get", "/casos"), ("get", "/exportacion"),
                         ("post", "/investigaciones")]:
        r = getattr(c, metodo)(ruta, headers=cabeceras)
        assert r.status_code == 401, ruta
        assert r.json()["error"]["codigo"] == "no_autorizado"


def test_sin_clave_configurada_503(mundo):
    r = cliente(mundo, clave=None).get("/casos", headers=CABECERA)
    assert r.status_code == 503 and r.json()["error"]["codigo"] == "servicio_no_disponible"


# ---------- salud ----------
def test_salud_ok_y_degradada_sin_detalles(mundo):
    def cae():
        raise ConnectionError(f"host interno con {SECRETO_BD}")

    r = cliente(mundo, salud={"indexador": lambda: True, "base_de_datos": cae}).get(
        "/salud", headers=CABECERA)
    assert r.status_code == 200
    assert r.json() == {"estado": "degradado",
                        "dependencias": {"indexador": "disponible",
                                         "base_de_datos": "no disponible"}}
    r = cliente(mundo, salud={"indexador": lambda: True}).get("/salud", headers=CABECERA)
    assert r.json()["estado"] == "ok"


# ---------- investigaciones ----------
def test_investigar_crea_el_caso_y_devuelve_el_expediente(mundo):
    doc = cargar("auth_5760")
    e = crear(cliente(mundo), doc["_id"])
    assert e["id"] == doc["_id"] and e["alerta"]["regla_id"] == "5760"
    assert e["pasos"][0] == {**e["pasos"][0], "paso": "P1_lectura_alerta",
                             "estado": "con_resultado"}
    ev = {d["dato"]: d for d in e["evidencia"]}
    assert {k: ev["ip_origen"][k] for k in ("dato", "valor", "procedencia")} == {
        "dato": "ip_origen", "valor": "203.0.113.10", "procedencia": "data.srcip"}
    assert e["prioridad"]["motivos"] and e["decisiones"] == [] and e["t1"] is None


def test_evidencia_ausente_dice_dato_no_disponible(mundo):
    e = crear(cliente(mundo), cargar("red_86601_suricata")["_id"])
    ev = {d["dato"]: d for d in e["evidencia"]}
    assert {k: ev["full_log"][k] for k in ("dato", "valor", "procedencia")} == {
        "dato": "full_log", "valor": "dato no disponible", "procedencia": None}


def test_investigar_dos_veces_409(mundo):
    c = cliente(mundo)
    crear(c, cargar("auth_5760")["_id"])
    r = c.post("/investigaciones", json={"id_alerta": cargar("auth_5760")["_id"]},
               headers=CABECERA)
    assert r.status_code == 409 and r.json()["error"]["codigo"] == "conflicto"


def test_alerta_inexistente_404_y_no_crea_caso(mundo):
    r = cliente(mundo).post("/investigaciones", json={"id_alerta": "noExiste123"},
                            headers=CABECERA)
    assert r.status_code == 404 and mundo.repo.casos == {}


def test_indice_caido_503(mundo):
    mundo.error_lectura = "ConnectionError: sin conexión"
    r = cliente(mundo).post("/investigaciones", json={"id_alerta": "abc"}, headers=CABECERA)
    assert r.status_code == 503 and mundo.repo.casos == {}


@pytest.mark.parametrize("id_malo", ["../etc/passwd", "a b", "x" * 65, "", "ñandú"])
def test_id_de_alerta_invalido_422(mundo, id_malo):
    r = cliente(mundo).post("/investigaciones", json={"id_alerta": id_malo}, headers=CABECERA)
    assert r.status_code == 422 and r.json()["error"]["detalles"][0]["campo"] == "id_alerta"


# ---------- expediente ----------
def test_expediente_404_y_422(mundo):
    c = cliente(mundo)
    assert c.get("/casos/noExiste", headers=CABECERA).status_code == 404
    r = c.get("/casos/a%20b", headers=CABECERA)
    assert r.status_code == 422 and r.json()["error"]["codigo"] == "datos_invalidos"


def test_paso_fallido_se_ve_y_su_error_no_filtra_secretos(mundo):
    mundo.error_paso = f"no se pudo conectar con clave {SECRETO_BD}"
    e = crear(cliente(mundo), cargar("red_4151_firewall")["_id"])
    p4 = next(p for p in e["pasos"] if p["paso"] == "P4_alertas_relacionadas")
    assert p4["estado"] == "fallido" and "[oculto]" in p4["error"]
    assert SECRETO_BD not in json.dumps(e)


# ---------- decisiones ----------
def test_decision_registrada_fija_t1(mundo):
    c = cliente(mundo)
    id_caso = cargar("auth_5760")["_id"]
    crear(c, id_caso)
    r = c.post(f"/casos/{id_caso}/decision", json=DECISION, headers=CABECERA)
    assert r.status_code == 201
    e = r.json()
    assert e["t1"] is not None and e["minutos_hasta_decision"] >= 0
    assert e["decisiones"][0]["analista"] == "analista-01"


def test_decision_repetida_409_y_t1_no_cambia(mundo):
    c = cliente(mundo)
    id_caso = cargar("auth_5760")["_id"]
    crear(c, id_caso)
    t1 = c.post(f"/casos/{id_caso}/decision", json=DECISION, headers=CABECERA).json()["t1"]
    r = c.post(f"/casos/{id_caso}/decision", json=DECISION, headers=CABECERA)
    assert r.status_code == 409
    otra = {**DECISION, "decision": "solicitar_mas_informacion",
            "justificacion": "Confirmar con el responsable.", "prioridad_considerada": "Media"}
    e = c.post(f"/casos/{id_caso}/decision", json=otra, headers=CABECERA).json()
    assert e["t1"] == t1 and len(e["decisiones"]) == 2


@pytest.mark.parametrize("cambio,campo", [
    ({"justificacion": "   "}, "justificacion"), ({"justificacion": ""}, "justificacion"),
    ({"decision": "bloquear"}, "decision"), ({"analista": "  "}, "analista"),
    ({"prioridad_considerada": "Critica"}, "prioridad_considerada")])
def test_decision_invalida_422(mundo, cambio, campo):
    c = cliente(mundo)
    id_caso = cargar("auth_5760")["_id"]
    crear(c, id_caso)
    r = c.post(f"/casos/{id_caso}/decision", json={**DECISION, **cambio}, headers=CABECERA)
    assert r.status_code == 422
    assert r.json()["error"]["detalles"][0]["campo"] == campo
    assert mundo.repo.decisiones(id_caso) == []


def test_decision_sobre_caso_inexistente_404(mundo):
    r = cliente(mundo).post("/casos/noExiste/decision", json=DECISION, headers=CABECERA)
    assert r.status_code == 404


def test_422_no_repite_el_valor_enviado(mundo):
    c = cliente(mundo)
    id_caso = cargar("auth_5760")["_id"]
    crear(c, id_caso)
    r = c.post(f"/casos/{id_caso}/decision",
               json={**DECISION, "justificacion": SECRETO_BD * 200}, headers=CABECERA)
    assert r.status_code == 422 and SECRETO_BD not in r.text


# ---------- listado y exportación ----------
def test_listado_paginado_y_filtros(mundo):
    c = cliente(mundo)
    for nombre in ("auth_5760", "fim_550", "red_4151_firewall"):
        crear(c, cargar(nombre)["_id"])
    c.post(f"/casos/{cargar('auth_5760')['_id']}/decision", json=DECISION, headers=CABECERA)
    r = c.get("/casos", params={"tamano": 2}, headers=CABECERA).json()
    assert r["total"] == 3 and len(r["casos"]) == 2
    con = c.get("/casos", params={"con_decision": "true"}, headers=CABECERA).json()
    assert [x["id"] for x in con["casos"]] == [cargar("auth_5760")["_id"]]
    sin = c.get("/casos", params={"con_decision": "false"}, headers=CABECERA).json()
    assert sin["total"] == 2
    assert c.get("/casos", params={"tamano": 0}, headers=CABECERA).status_code == 422
    assert c.get("/casos", params={"prioridad": "Urgente"}, headers=CABECERA).status_code == 422


def test_exportacion_usa_la_primera_decision(mundo):
    c = cliente(mundo)
    id_caso = cargar("auth_5760")["_id"]
    crear(c, id_caso)
    t1 = c.post(f"/casos/{id_caso}/decision", json=DECISION, headers=CABECERA).json()["t1"]
    c.post(f"/casos/{id_caso}/decision", headers=CABECERA, json={
        **DECISION, "decision": "descartar", "justificacion": "Revisado: prueba del lab.",
        "prioridad_considerada": "Baja"})
    fila = c.get("/exportacion", headers=CABECERA).json()["casos"][0]
    assert fila["decision"] == "escalar" and fila["prioridad_considerada"] == "Alta"
    assert fila["t1"] == t1 and fila["completitud"] == 100.0
    assert fila["procedimiento"] == "sara"


def test_exportacion_csv(mundo):
    c = cliente(mundo)
    crear(c, cargar("fim_550")["_id"])
    r = c.get("/exportacion", params={"formato": "csv"}, headers=CABECERA)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    lineas = r.text.splitlines()
    assert lineas[0] == ("id,numero_caso,tipo_alerta,procedimiento,t0,t1,"
                         "minutos_hasta_decision,prioridad_sugerida,decision,"
                         "prioridad_considerada,completitud")
    assert lineas[1].startswith(cargar("fim_550")["_id"] + ",C-0001,cambio_archivos,sara,")


# ---------- errores internos, CORS, contrato ----------
def test_error_interno_500_sin_trazas(mundo):
    def explota(_id):
        raise RuntimeError(f"Traceback ... /ruta/interna {SECRETO_BD}")

    mundo.repo.listar = lambda: (_ for _ in ()).throw(RuntimeError(SECRETO_BD))
    r = cliente(mundo).get("/casos", headers=CABECERA)
    assert r.status_code == 500 and r.json()["error"]["codigo"] == "error_interno"
    assert SECRETO_BD not in r.text and "Traceback" not in r.text


def test_ruta_inexistente_404_con_el_mismo_esquema(mundo):
    r = cliente(mundo).get("/no-existe", headers=CABECERA)
    assert r.status_code == 404 and r.json()["error"]["codigo"] == "no_encontrado"


def test_cors_solo_el_origen_configurado(mundo):
    c = cliente(mundo)
    ok = c.options("/casos", headers={"Origin": "http://localhost:5173",
                                      "Access-Control-Request-Method": "GET"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    malo = c.options("/casos", headers={"Origin": "http://evil.test",
                                        "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in malo.headers


def test_no_hay_rutas_de_escritura_sobre_wazuh_ni_de_contencion():
    import sara.interfaces.api as api
    app = crear_app(ConfiguracionAPI(None, CLAVE))  # type: ignore[arg-type]
    escritura = sorted((r.path, sorted(r.methods)) for r in app.routes
                       if getattr(r, "methods", None) and r.methods & {"POST", "PUT", "DELETE",
                                                                       "PATCH"})
    assert escritura == [("/casos/{id_caso}/decision", ["POST"]),
                         ("/investigaciones", ["POST"])]
    texto = Path(api.__file__).read_text(encoding="utf-8").lower()
    for palabra in ("bloquear(", "aislar(", "active-response", "/ar"):
        assert palabra not in texto


def test_api_no_importa_adaptadores():
    import sara.interfaces.api as api
    arbol = ast.parse(Path(api.__file__).read_text(encoding="utf-8"))
    modulos = [n.module for n in ast.walk(arbol) if isinstance(n, ast.ImportFrom) and n.module]
    modulos += [a.name for n in ast.walk(arbol) if isinstance(n, ast.Import) for a in n.names]
    assert not [m for m in modulos if m.startswith(("sara.adaptadores", "psycopg", "prefect"))]


def test_openapi_al_dia():
    import sys
    sys.path.insert(0, str(RAIZ / "backend" / "scripts"))
    from exportar_openapi import DESTINO, contrato
    assert DESTINO.read_text(encoding="utf-8").replace("\r\n", "\n") == contrato(), \
        "docs/api/openapi.json desactualizado: corre scripts/exportar_openapi.py"


def test_ocultador():
    o = ocultador(["abcd1234", None, "", "xy"])
    assert o("clave abcd1234 y xy") == "clave [oculto] y xy"


# ---------- RNF-05: hora de obtención de la evidencia ----------
def test_cada_evidencia_lleva_la_hora_de_lectura_en_utc(mundo):
    from datetime import datetime, timezone
    e = crear(cliente(mundo), cargar("red_86601_suricata")["_id"])
    fin_p1 = next(p for p in e["pasos"] if p["paso"] == "P1_lectura_alerta")["fin"]
    esperado = datetime.fromisoformat(fin_p1).astimezone(timezone.utc).isoformat()
    assert e["evidencia"] and all(d["obtenida_en"] == esperado for d in e["evidencia"])
    no_disp = [d for d in e["evidencia"] if d["valor"] == "dato no disponible"]
    assert no_disp and all(d["obtenida_en"] == esperado for d in no_disp)
    assert esperado.endswith("+00:00")


# ---------- alertas relacionadas con detalle ----------
def test_relacionadas_con_detalle_hasta_50_y_total(mundo):
    from sara.puertos import AlertasRelacionadas, ResumenAlerta
    alertas = tuple(ResumenAlerta(f"rel-{i:03d}", "5760", "sshd: authentication failed.", 5,
                                  f"2026-11-18T04:52:{i % 60:02d}.000Z", "srv-web")
                    for i in range(50))
    mundo.relacionadas_fijas = AlertasRelacionadas(73, alertas)
    e = crear(cliente(mundo), cargar("auth_5760")["_id"])
    assert e["total_relacionadas"] == 73 and len(e["alertas_relacionadas"]) == 50
    assert e["alertas_relacionadas"][0] == {
        "id": "rel-000", "regla_id": "5760", "regla_descripcion": "sshd: authentication failed.",
        "regla_nivel": 5, "marca_tiempo": "2026-11-18T04:52:00.000Z", "agente_nombre": "srv-web"}
    assert e["prioridad"]["corroborada"] is True


def test_sin_relacionadas_total_cero(mundo):
    e = crear(cliente(mundo), cargar("fim_550")["_id"])
    assert e["alertas_relacionadas"] == [] and e["total_relacionadas"] == 0


# ---------- número de caso legible ----------
def test_numero_de_caso_en_lista_expediente_y_exportacion(mundo):
    c = cliente(mundo)
    a = crear(c, cargar("auth_5760")["_id"])
    b = crear(c, cargar("fim_550")["_id"])
    assert (a["numero_caso"], b["numero_caso"]) == ("C-0001", "C-0002")
    lista = {x["id"]: x["numero_caso"] for x in c.get("/casos", headers=CABECERA).json()["casos"]}
    assert lista == {a["id"]: "C-0001", b["id"]: "C-0002"}
    filas = {f["id"]: f["numero_caso"] for f in
             c.get("/exportacion", headers=CABECERA).json()["casos"]}
    assert filas == lista
    assert c.get(f"/casos/{a['id']}", headers=CABECERA).json()["numero_caso"] == "C-0001"


def test_formato_numero():
    from sara.aplicacion.casos import formato_numero
    assert (formato_numero(7), formato_numero(12345), formato_numero(None)) ==         ("C-0007", "C-12345", None)


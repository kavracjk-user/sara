"""Pruebas del núcleo. Cubren las pruebas PR-02, PR-04, PR-05, PR-06, PR-07, PR-08,
PR-09 y PR-12 del plan (Tabla 4.19) que no necesitan Wazuh ni PostgreSQL."""
import time
from pathlib import Path

import pytest

from sara.indicators import extraer_indicadores, tipo_hash
from sara.models import Activo, Estado, Importancia, Nivel, TipoAlerta, TipoIndicador
from sara.normalizer import normalizar
from sara.pipeline import completitud, investigar, minutos_hasta_decision, registrar_decision
from sara.priority import Umbrales, sugerir_prioridad
from sara.steps import SinDatoAplicable, ejecutar_paso

CATALOGO = {
    "001": Activo("001", "srv-web", "Servidor web de pruebas", Importancia.ALTA),
    "002": Activo("002", "pc-lab", "Equipo de laboratorio", Importancia.BAJA),
}


def alerta_auth(**extra):
    doc = {
        "id": "A-1", "@timestamp": "2027-02-10T10:00:00.000Z",
        "rule": {"id": "5710", "level": 10, "description": "sshd: intento fallido",
                 "groups": ["syslog", "sshd", "authentication_failed"]},
        "agent": {"id": "001", "name": "srv-web"},
        "data": {"srcip": "203.0.113.7", "srcuser": "root"},
    }
    doc.update(extra)
    return doc


def alerta_archivo():
    return {
        "id": "A-2", "@timestamp": "2027-02-10T11:00:00.000Z",
        "rule": {"id": "550", "level": 7, "description": "Archivo modificado",
                 "groups": ["syscheck", "syscheck_entry_modified"]},
        "agent": {"id": "002", "name": "pc-lab"},
        "syscheck": {"path": "/etc/passwd", "event": "modified",
                     "sha256_after": "a" * 64},
    }


# ---------- normalización (RF-03, PR-02) ----------
def test_normaliza_autenticacion_completa():
    v = normalizar(alerta_auth())
    assert v.tipo_alerta is TipoAlerta.AUTENTICACION
    assert (v.regla_nivel, v.agente_id, v.ip_origen) == (10, "001", "203.0.113.7")
    assert v.campos_ausentes == []


def test_normaliza_cambio_de_archivos():
    v = normalizar(alerta_archivo())
    assert v.tipo_alerta is TipoAlerta.CAMBIO_ARCHIVOS
    assert v.archivo_ruta == "/etc/passwd" and v.evento == "modified"


def test_campo_obligatorio_ausente_se_marca_y_no_se_inventa():  # PR-02
    doc = alerta_auth()
    del doc["data"]["srcip"]
    v = normalizar(doc)
    assert v.ip_origen is None
    assert "ip_origen" in v.campos_ausentes


def test_acepta_claves_planas_de_wazuh():
    doc = {"@timestamp": "t", "rule.id": "5710", "rule.level": "10",
           "rule.groups": ["sshd"], "agent.id": "001", "data.srcip": "203.0.113.7"}
    v = normalizar(doc, id_alerta="X")
    assert v.regla_nivel == 10 and v.ip_origen == "203.0.113.7"


def test_nivel_no_numerico_queda_ausente():
    doc = alerta_auth()
    doc["rule"]["level"] = "alto"
    assert "regla_nivel" in normalizar(doc).campos_ausentes


# ---------- indicadores (RF-04, PR-05) ----------
def test_extrae_ip_y_hash():
    assert [(i.tipo, i.valor) for i in extraer_indicadores(normalizar(alerta_auth()))] == [
        (TipoIndicador.IP, "203.0.113.7")]
    inds = extraer_indicadores(normalizar(alerta_archivo()))
    assert [i.tipo for i in inds] == [TipoIndicador.HASH]


@pytest.mark.parametrize("largo,algo", [(32, "md5"), (40, "sha1"), (64, "sha256")])
def test_hash_se_distingue_por_longitud(largo, algo):
    assert tipo_hash("a" * largo) == algo


def test_hash_invalido_no_es_indicador():
    assert tipo_hash("a" * 33) is None and tipo_hash("z" * 32) is None


def test_ip_invalida_no_es_indicador():
    doc = alerta_auth()
    doc["data"]["srcip"] = "999.1.1.1"
    assert extraer_indicadores(normalizar(doc)) == []


def test_sin_indicadores_el_paso_es_no_aplicable():  # PR-05
    doc = alerta_auth()
    del doc["data"]["srcip"]
    caso = investigar(doc, CATALOGO)
    p3 = next(p for p in caso.pasos if p.paso == "P3_indicadores")
    assert p3.estado is Estado.NO_APLICABLE


# ---------- prioridad (RF-09, RF-10, PR-07, PR-08) ----------
@pytest.mark.parametrize("nivel_regla,imp,esperado", [
    (12, Importancia.ALTA, Nivel.ALTA), (12, Importancia.MEDIA, Nivel.ALTA),
    (12, Importancia.BAJA, Nivel.MEDIA), (8, Importancia.ALTA, Nivel.MEDIA),
    (8, Importancia.MEDIA, Nivel.MEDIA), (8, Importancia.BAJA, Nivel.BAJA),
    (3, Importancia.ALTA, Nivel.MEDIA), (3, Importancia.MEDIA, Nivel.BAJA),
    (3, Importancia.BAJA, Nivel.BAJA),
])
def test_matriz_de_prioridad_tabla_3_5(nivel_regla, imp, esperado):
    assert sugerir_prioridad(nivel_regla, imp, 0).nivel is esperado


@pytest.mark.parametrize("nivel_regla", [3, 8, 12])
def test_activo_no_catalogado_es_informacion_insuficiente(nivel_regla):  # PR-07
    p = sugerir_prioridad(nivel_regla, Importancia.NO_CATALOGADO, 0)
    assert p.nivel is Nivel.INSUFICIENTE and p.nivel is not Nivel.BAJA


def test_sin_nivel_de_regla_es_informacion_insuficiente():
    assert sugerir_prioridad(None, Importancia.ALTA, 5).nivel is Nivel.INSUFICIENTE


def test_relacionadas_suben_un_nivel_hasta_alta():  # PR-08
    assert sugerir_prioridad(8, Importancia.BAJA, 0).nivel is Nivel.BAJA
    assert sugerir_prioridad(8, Importancia.BAJA, 2).nivel is Nivel.MEDIA
    assert sugerir_prioridad(8, Importancia.ALTA, 2).nivel is Nivel.ALTA
    assert sugerir_prioridad(12, Importancia.ALTA, 9).nivel is Nivel.ALTA  # tope


def test_relacionadas_no_rescatan_informacion_insuficiente():
    assert sugerir_prioridad(12, Importancia.NO_CATALOGADO, 5).nivel is Nivel.INSUFICIENTE


def test_los_motivos_se_muestran():
    p = sugerir_prioridad(12, Importancia.ALTA, 1)
    assert any("Nivel de regla 12" in m for m in p.motivos)
    assert any("relacionada" in m for m in p.motivos)


def test_umbrales_configurables():
    u = Umbrales(medio_desde=5, alto_desde=9)
    assert sugerir_prioridad(9, Importancia.ALTA, 0, u).nivel is Nivel.ALTA


# ---------- pasos: reintentos, tiempos y estados (RF-06, RF-07, RNF-07, PR-04, PR-06) ----------
def test_con_resultado():
    p = ejecutar_paso("x", lambda: ["a"])
    assert p.estado is Estado.CON_RESULTADO and p.reintentos == 0


def test_sin_resultado_no_es_fallo():  # PR-06
    p = ejecutar_paso("x", lambda: [])
    assert p.estado is Estado.SIN_RESULTADO and p.error is None


def test_no_aplicable():
    def f():
        raise SinDatoAplicable("sin dominio")
    assert ejecutar_paso("x", f).estado is Estado.NO_APLICABLE


def test_fallo_tras_reintentos_limitados():  # PR-04
    llamadas = []

    def f():
        llamadas.append(1)
        raise ConnectionError("indexador caído")

    p = ejecutar_paso("x", f, reintentos=2)
    assert p.estado is Estado.FALLIDO and len(llamadas) == 3
    assert "ConnectionError" in p.error and p.reintentos == 2


def test_reintento_exitoso():
    estado = {"n": 0}

    def f():
        estado["n"] += 1
        if estado["n"] < 2:
            raise TimeoutError("lento")
        return ["ok"]

    p = ejecutar_paso("x", f, reintentos=2)
    assert p.estado is Estado.CON_RESULTADO and p.reintentos == 1


def test_tiempo_maximo_agotado_es_fallido():  # PR-04
    p = ejecutar_paso("x", lambda: time.sleep(0.5), reintentos=0, tiempo_maximo_s=0.05)
    assert p.estado is Estado.FALLIDO and "tiempo máximo" in p.error


# ---------- pipeline completo ----------
def test_pipeline_alta_prioridad_con_relacionadas():
    caso = investigar(alerta_auth(), CATALOGO, buscar_relacionadas=lambda v: ["A-9", "A-10"],
                      id_alerta="A-1")
    assert caso.prioridad.nivel is Nivel.ALTA  # 10 => Medio; activo Alta => Media; +1 => Alta
    assert caso.alertas_relacionadas == ["A-9", "A-10"]
    assert caso.activo.nombre == "srv-web"


def test_pipeline_activo_no_catalogado():
    doc = alerta_auth()
    doc["agent"]["id"] = "999"
    caso = investigar(doc, CATALOGO)
    assert caso.prioridad.nivel is Nivel.INSUFICIENTE


def test_falla_de_contexto_no_se_lee_como_riesgo_bajo():
    def cae(_v):
        raise ConnectionError("sin conexión")

    caso = investigar(alerta_auth(), CATALOGO, buscar_relacionadas=cae)
    p4 = next(p for p in caso.pasos if p.paso == "P4_alertas_relacionadas")
    assert p4.estado is Estado.FALLIDO
    assert caso.prioridad.nivel is not Nivel.BAJA
    assert any("pasos fallidos" in m for m in caso.prioridad.motivos)


def test_documento_corrupto_no_rompe_el_flujo():
    caso = investigar({}, CATALOGO)
    assert caso.prioridad.nivel is Nivel.INSUFICIENTE
    assert any(p.paso == "P2_validacion" and p.estado is Estado.FALLIDO for p in caso.pasos)


# ---------- decisión humana (RF-11, RF-13, RNF-06, PR-09) ----------
def test_registro_de_decision_y_tiempos():
    caso = investigar(alerta_auth(), CATALOGO)
    assert caso.decision is None and minutos_hasta_decision(caso) is None
    registrar_decision(caso, "escalar", "IP externa con intentos repetidos", Nivel.ALTA)
    assert caso.decision == "escalar" and caso.t1 >= caso.t0
    assert minutos_hasta_decision(caso) >= 0


def test_t1_solo_cuenta_la_primera_decision():
    caso = investigar(alerta_auth(), CATALOGO)
    registrar_decision(caso, "solicitar_mas_informacion", "falta contexto", Nivel.MEDIA)
    primera = caso.t1
    registrar_decision(caso, "escalar", "llegó el contexto", Nivel.ALTA)
    assert caso.t1 == primera and caso.decision == "escalar"


def test_decision_invalida_o_sin_justificacion_se_rechaza():
    caso = investigar(alerta_auth(), CATALOGO)
    with pytest.raises(ValueError):
        registrar_decision(caso, "bloquear_ip", "x", Nivel.ALTA)
    with pytest.raises(ValueError):
        registrar_decision(caso, "escalar", "   ", Nivel.ALTA)


def test_completitud():
    assert completitud(["a", "b", "c", "d"], ["a", "b", "c"]) == 75.0
    assert completitud([], []) == 100.0


# ---------- RNF-01 / PR-12: sin acciones de contención ----------
def test_no_hay_codigo_de_contencion():
    prohibidos = ("iptables", "firewall-cmd", "active-response", "kill ", "subprocess",
                  "os.system", "block_ip", "isolate", "quarantine")
    for f in (Path(__file__).parent.parent / "sara").glob("*.py"):
        texto = f.read_text(encoding="utf-8").lower()
        for p in prohibidos:
            # las menciones en docstrings que NIEGAN la contención se permiten
            lineas = [l for l in texto.splitlines()
                      if p in l and "no ejecuta" not in l and "ni contención" not in l
                      and "sin acciones" not in l and "pr-12" not in l and "rnf-01" not in l]
            assert not lineas, f"{f.name} contiene '{p}': {lineas}"


def test_wazuh_client_solo_lee():
    texto = (Path(__file__).parent.parent / "sara" / "wazuh_client.py").read_text()
    for metodo in ('method="PUT"', 'method="DELETE"', "_update", "_delete_by_query", "_bulk"):
        assert metodo not in texto

"""Ingesta de alertas nuevas (fase 4b) sin servicios: fuente simulada con alertas reales
del laboratorio (tests/fixtures) y repositorios en memoria."""
import json
from pathlib import Path

import pytest

from sara.adaptadores.wazuh.normalizer import REGLAS_CATALOGADAS, normalizar
from sara.aplicacion.ingesta import ingerir
from sara.aplicacion.pipeline import PASO_LECTURA, investigar
from sara.dominio.models import (Activo, Caso, Estado, Importancia, Nivel, RegistroPaso,
                                 VistaComun, ahora)
from sara.puertos import AlertaNueva, MarcaIngesta

FIXTURES = Path(__file__).parent / "fixtures"
CATALOGO = {"001": Activo("001", "srv-web", "Servidor web de pruebas", Importancia.ALTA),
            "002": Activo("002", "srv-bd", "Base de datos de pruebas", Importancia.ALTA)}


def cargar(nombre):
    return json.loads((FIXTURES / f"{nombre}.json").read_text(encoding="utf-8"))


class FuenteFalsa:
    def __init__(self, docs):
        self.docs = docs                                 # en orden de marca de tiempo
        self.pedidos = []

    def alertas_despues_de(self, marca, lote):
        self.pedidos.append((marca, lote))
        inicio = 0 if marca is None else marca.orden[0] + 1
        return [AlertaNueva(d["_id"], d["rule"]["id"], d["timestamp"], (i,))
                for i, d in enumerate(self.docs)][inicio:inicio + lote]


class MarcasMemoria:
    def __init__(self):
        self.marcas = {}

    def leer_marca(self, nombre):
        return self.marcas.get(nombre)

    def guardar_marca(self, nombre, marca):
        self.marcas[nombre] = marca


class RepoMemoria:
    def __init__(self):
        self.casos = {}

    def numero_caso(self, id_alerta):
        return list(self.casos).index(id_alerta) + 1 if id_alerta in self.casos else None


def investigador(docs, repo, falla=()):
    por_id = {d["_id"]: d for d in docs}

    def investigar_(id_alerta):
        if id_alerta in falla:
            raise ConnectionError(f"falla simulada con clave secreta-xyz para {id_alerta}")
        doc = por_id.get(id_alerta)
        if doc is None:
            return Caso(vista=VistaComun(id_alerta=id_alerta), pasos=[RegistroPaso(
                PASO_LECTURA, Estado.SIN_RESULTADO, ahora(), ahora())])
        caso = investigar(doc, CATALOGO, normalizar, id_alerta=id_alerta)
        caso.pasos.insert(0, RegistroPaso(PASO_LECTURA, Estado.CON_RESULTADO, ahora(), ahora()))
        repo.casos[id_alerta] = caso
        return caso

    return investigar_


@pytest.fixture
def docs():
    sin_regla = cargar("auth_5760") | {"_id": "otra-regla", "rule": {"id": "501", "level": 3}}
    agente_099 = cargar("red_86601_suricata") | {"_id": "del-099",
                                                 "agent": {"id": "099", "name": "pc-nuevo"}}
    return [cargar("auth_5760"), sin_regla, cargar("fim_550"), cargar("red_4151_firewall"),
            agente_099]


def test_primera_pasada_crea_y_cuenta_las_omitidas(docs):
    fuente, marcas, repo = FuenteFalsa(docs), MarcasMemoria(), RepoMemoria()
    r = ingerir(fuente, marcas, repo, investigador(docs, repo), REGLAS_CATALOGADAS)
    assert (r.leidas, r.creadas, r.omitidas_por_regla, r.ya_existentes, r.con_error) == \
        (5, 4, 1, 0, 0)
    assert r.omitidas_por_regla_detalle == {"501": 1}
    assert r.creados == [d["_id"] for d in docs if d["_id"] != "otra-regla"]
    assert marcas.marcas["wazuh-alertas"].orden == (4,)       # la marca avanzó al final


def test_segunda_pasada_no_crea_nada(docs):
    fuente, marcas, repo = FuenteFalsa(docs), MarcasMemoria(), RepoMemoria()
    ingerir(fuente, marcas, repo, investigador(docs, repo), REGLAS_CATALOGADAS)
    r = ingerir(fuente, marcas, repo, investigador(docs, repo), REGLAS_CATALOGADAS)
    assert (r.leidas, r.creadas) == (0, 0)                     # nada nuevo tras la marca
    marcas.marcas.clear()                                      # desde el principio otra vez
    r = ingerir(fuente, marcas, repo, investigador(docs, repo), REGLAS_CATALOGADAS)
    assert (r.creadas, r.ya_existentes, r.omitidas_por_regla) == (0, 4, 1)


def test_un_fallo_no_detiene_el_lote_y_la_marca_para_antes_del_fallo(docs):
    fuente, marcas, repo = FuenteFalsa(docs), MarcasMemoria(), RepoMemoria()
    falla = {docs[2]["_id"]}                                   # fim_550, tercera alerta
    r = ingerir(fuente, marcas, repo, investigador(docs, repo, falla), REGLAS_CATALOGADAS,
                ocultar=lambda t: t.replace("secreta-xyz", "[oculto]"))
    assert (r.creadas, r.con_error) == (3, 1)                  # siguió con las demás
    assert r.errores == [{"id": docs[2]["_id"], "error":
                          f"ConnectionError: falla simulada con clave [oculto] para {docs[2]['_id']}"}]
    assert marcas.marcas["wazuh-alertas"].orden == (1,)        # antes del fallo
    # La siguiente ejecución reintenta la fallida y omite las ya creadas.
    r2 = ingerir(fuente, marcas, repo, investigador(docs, repo), REGLAS_CATALOGADAS)
    assert (r2.creadas, r2.ya_existentes, r2.con_error) == (1, 2, 0)
    assert marcas.marcas["wazuh-alertas"].orden == (4,)


def test_lote_maximo(docs):
    fuente, marcas, repo = FuenteFalsa(docs), MarcasMemoria(), RepoMemoria()
    r = ingerir(fuente, marcas, repo, investigador(docs, repo), REGLAS_CATALOGADAS, lote=2)
    assert r.leidas == 2 and fuente.pedidos == [(None, 2)]
    with pytest.raises(ValueError):
        ingerir(fuente, marcas, repo, investigador(docs, repo), REGLAS_CATALOGADAS, lote=0)


def test_alerta_que_ya_no_esta_cuenta_como_error(docs):
    fuente, marcas, repo = FuenteFalsa(docs[:1]), MarcasMemoria(), RepoMemoria()
    r = ingerir(fuente, marcas, repo, investigador([], repo), REGLAS_CATALOGADAS)
    assert r.con_error == 1 and "ya no está" in r.errores[0]["error"]


def test_alerta_del_099_queda_informacion_insuficiente(docs):
    fuente, marcas, repo = FuenteFalsa(docs), MarcasMemoria(), RepoMemoria()
    ingerir(fuente, marcas, repo, investigador(docs, repo), REGLAS_CATALOGADAS)
    assert repo.casos["del-099"].prioridad.nivel is Nivel.INSUFICIENTE


def test_solo_las_reglas_pedidas(docs):
    fuente, marcas, repo = FuenteFalsa(docs), MarcasMemoria(), RepoMemoria()
    r = ingerir(fuente, marcas, repo, investigador(docs, repo), ["5760"])
    assert (r.creadas, r.omitidas_por_regla) == (1, 4)
    assert r.omitidas_por_regla_detalle == {"501": 1, "550": 1, "4151": 1, "86601": 1}


# ---------- configuración y comando ----------
def test_configuracion_por_defecto_y_por_entorno():
    ingesta = pytest.importorskip("sara.interfaces.ingesta")
    assert ingesta.configuracion({}) == (sorted(REGLAS_CATALOGADAS), 100)
    assert ingesta.configuracion({"SARA_REGLAS_INGESTA": " 5760, 550 ,5760",
                                  "SARA_INGESTA_LOTE": "7"}) == (["550", "5760"], 7)
    for malo in ({"SARA_REGLAS_INGESTA": "5760;x"}, {"SARA_INGESTA_LOTE": "0"},
                 {"SARA_INGESTA_LOTE": "mucho"}, {"SARA_INGESTA_LOTE": "1001"}):
        with pytest.raises(ValueError):
            ingesta.configuracion(malo)


def test_reglas_catalogadas_son_las_confirmadas_en_la_corrida():
    assert sorted(REGLAS_CATALOGADAS, key=int) == ["550", "553", "554", "4151", "5760", "5763",
                                                   "40112", "86601"]


def test_comando_exige_una_vez():
    ingesta = pytest.importorskip("sara.interfaces.ingesta")
    with pytest.raises(SystemExit):
        ingesta.main([])
    assert ingesta.main(["--una-vez"], env={"SARA_INGESTA_LOTE": "0"}) == 2

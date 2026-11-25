"""Adaptador PostgreSQL: lo que se prueba sin base de datos."""
from datetime import datetime, timedelta, timezone

import pytest

from sara.adaptadores.postgres import conexion
from sara.adaptadores.postgres.repositorio import RepositorioPostgres, _iso
from sara.adaptadores.postgres.serializacion import a_json
from sara.dominio.models import (Activo, Caso, Estado, Importancia, Indicador, TipoIndicador,
                                 VistaComun)


def test_parametros_salen_del_entorno_y_no_tienen_claves_por_defecto():
    env = {"POSTGRES_USER": "u", "POSTGRES_PASSWORD": "p", "POSTGRES_DB": "d"}
    assert conexion.parametros(env) == {"host": "127.0.0.1", "port": "5432", "dbname": "d",
                                        "user": "u", "password": "p"}
    with pytest.raises(RuntimeError, match="POSTGRES_PASSWORD"):
        conexion.parametros({"POSTGRES_USER": "u", "POSTGRES_DB": "d"})


def test_a_json_convierte_objetos_del_dominio():
    datos = a_json([Indicador(TipoIndicador.IP, "203.0.113.10", "ip_origen"),
                    Activo("001", "srv-web", "web", Importancia.ALTA),
                    datetime(2026, 11, 18, 5, 0, tzinfo=timezone.utc), ("a", None)])
    assert datos == [{"tipo": "ip", "valor": "203.0.113.10", "origen_campo": "ip_origen"},
                     {"id_agente": "001", "nombre": "srv-web", "funcion": "web",
                      "importancia": "Alta"},
                     "2026-11-18T05:00:00+00:00", ["a", None]]


def test_a_json_rechaza_lo_que_no_sabe_guardar():
    with pytest.raises(TypeError):
        a_json(object())


def test_iso_devuelve_utc_con_z_como_wazuh():
    hora = datetime(2026, 11, 18, 1, 0, 0, 873000, tzinfo=timezone(timedelta(hours=-4)))
    assert _iso(hora) == "2026-11-18T05:00:00.873Z"
    assert _iso(None) is None


def test_no_guarda_un_caso_sin_id_de_alerta():
    repo = RepositorioPostgres(lambda: pytest.fail("no debe conectar"))
    with pytest.raises(ValueError):
        repo.guardar(Caso(vista=VistaComun()))


def test_procedimiento_solo_sara_o_manual():
    with pytest.raises(ValueError):
        RepositorioPostgres(lambda: None, procedimiento="otro")

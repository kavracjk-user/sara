"""Registro de agentes con id fijo: lo que se puede comprobar sin Docker."""
import json

import pytest

import registrar_agentes as ra


def test_ids_y_nombres_del_anexo_c():
    assert ra.AGENTES == (("001", "srv-web"), ("002", "srv-bd"), ("003", "pc-analista"),
                          ("004", "pc-lab-01"), ("099", "pc-nuevo"))


def test_escribe_un_client_keys_por_agente(tmp_path):
    regs = ra.preparar_registros(tmp_path)
    for r in regs:
        texto = (tmp_path / r.nombre / "client.keys").read_bytes().decode()
        assert texto == f"{r.id} {r.nombre} any {r.clave}\n"
        assert len(r.clave) == 64 and all(c in "0123456789abcdef" for c in r.clave)
    assert len({r.clave for r in regs}) == 5          # claves distintas


def test_repetir_reutiliza_las_claves(tmp_path):
    primera = ra.preparar_registros(tmp_path)
    segunda = ra.preparar_registros(tmp_path)
    assert primera == segunda


def test_rechaza_client_keys_que_no_coincide(tmp_path):
    ruta = tmp_path / "srv-web" / "client.keys"
    ruta.parent.mkdir()
    ruta.write_text("007 srv-web any " + "a" * 64 + "\n")
    with pytest.raises(SystemExit):
        ra.preparar_registros(tmp_path)


def test_detecta_carpeta_creada_por_docker(tmp_path):
    (tmp_path / "srv-web" / "client.keys").mkdir(parents=True)
    with pytest.raises(SystemExit, match="carpeta"):
        ra.preparar_registros(tmp_path)


def test_simular_no_escribe(tmp_path):
    ra.preparar_registros(tmp_path, escribir=False)
    assert not any(tmp_path.iterdir())


def test_la_clave_de_la_api_va_por_stdin_y_no_en_el_comando():
    regs = [ra.Registro("001", "srv-web", "b" * 64)]
    entrada = ra.entrada_servidor("Clave.Api-1", regs).decode()
    assert entrada.splitlines()[0] == "Clave.Api-1"
    assert entrada.splitlines()[1] == "001 srv-web " + "b" * 64
    assert "Clave.Api-1" not in ra.GUION_SERVIDOR


def test_comprobar_respuestas():
    regs = [ra.Registro("001", "srv-web", "b" * 64), ra.Registro("099", "pc-nuevo", "c" * 64)]
    ok = "\n".join(json.dumps({"error": 0, "data": {"id": r.id, "key": "x"}}) for r in regs)
    assert ra.comprobar_respuestas(ok, regs) == []
    malo = json.dumps({"error": 0, "data": {"id": "001"}}) + "\n" + \
        json.dumps({"title": "Bad Request", "error": 1706})
    problemas = ra.comprobar_respuestas(malo, regs)
    assert len(problemas) == 1 and "pc-nuevo" in problemas[0]
    assert ra.comprobar_respuestas("", regs)          # sin respuestas = problema

"""Verificación TLS contra un nombre distinto del host (sin red)."""
import functools
import ssl
import urllib.request

import pytest

from sara.adaptadores.wazuh import tls


def test_sin_nombre_es_urlopen_con_el_contexto():
    ctx = ssl.create_default_context()
    abrir = tls.abridor(ctx)
    assert isinstance(abrir, functools.partial)
    assert abrir.func is urllib.request.urlopen and abrir.keywords["context"] is ctx


def test_con_nombre_usa_el_manejador():
    abrir = tls.abridor(ssl.create_default_context(), "wazuh.indexer")
    manejadores = [h for h in abrir.__self__.handlers if isinstance(h, tls.ManejadorConNombre)]
    assert len(manejadores) == 1 and manejadores[0].nombre_tls == "wazuh.indexer"


def test_rechaza_contexto_sin_verificacion():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with pytest.raises(ValueError):
        tls.abridor(ctx, "wazuh.indexer")


def test_la_conexion_valida_contra_el_nombre_y_no_contra_la_ip(monkeypatch):
    llamado = {}

    class Ctx:
        def wrap_socket(self, sock, server_hostname):
            llamado["nombre"] = server_hostname
            return "socket-tls"

    monkeypatch.setattr(tls.http.client.HTTPConnection, "connect",
                        lambda self: setattr(self, "sock", "socket-tcp"))
    c = tls.ConexionConNombre("127.0.0.1", 9200, nombre_tls="wazuh.indexer",
                              context=ssl.create_default_context())
    c._context = Ctx()
    c.connect()
    assert llamado["nombre"] == "wazuh.indexer" and c.sock == "socket-tls"

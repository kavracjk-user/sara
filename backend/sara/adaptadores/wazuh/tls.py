"""HTTPS hacia el indexador verificando el certificado contra un nombre distinto del host.

El certificado oficial del laboratorio (wazuh-certs-tool) solo admite UN nombre por
nodo: `wazuh.indexer`. SARA se conecta desde el anfitrión a 127.0.0.1:9200, así que
con WAZUH_INDEXER_TLS_NOMBRE=wazuh.indexer se conecta a la URL pero valida la cadena
de la CA Y el nombre del certificado contra `wazuh.indexer`. No se desactiva ninguna
verificación. Sin la variable, se comporta como urllib.request.urlopen.
"""
from __future__ import annotations

import functools
import http.client
import ssl
import urllib.request
from typing import Callable, Optional

Abrir = Callable[..., http.client.HTTPResponse]


class ConexionConNombre(http.client.HTTPSConnection):
    def __init__(self, *args, nombre_tls: str, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.nombre_tls = nombre_tls

    def connect(self) -> None:
        http.client.HTTPConnection.connect(self)          # socket TCP al host de la URL
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.nombre_tls)


class ManejadorConNombre(urllib.request.HTTPSHandler):
    def __init__(self, ctx: ssl.SSLContext, nombre_tls: str) -> None:
        super().__init__(context=ctx)
        self.ctx, self.nombre_tls = ctx, nombre_tls

    def https_open(self, req):
        clase = functools.partial(ConexionConNombre, nombre_tls=self.nombre_tls, context=self.ctx)
        return self.do_open(clase, req)


def contexto_tls(ca: Optional[str] = None) -> ssl.SSLContext:
    """Contexto que verifica cadena y nombre, sin el perfil X.509 estricto.

    Python 3.13 activa VERIFY_X509_STRICT por defecto, y la CA que genera
    wazuh-certs-tool (4.14) no trae la extensión keyUsage: la conexión falla con
    «CA cert does not include key usage extension». Solo se quita esa bandera; la
    cadena de confianza (CERT_REQUIRED) y el nombre (check_hostname) se siguen
    verificando.
    """
    ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return ctx


def abridor(ctx: ssl.SSLContext, nombre_tls: Optional[str] = None) -> Abrir:
    """Devuelve una función `abrir(req, timeout=...)` equivalente a urlopen."""
    if not nombre_tls:
        return functools.partial(urllib.request.urlopen, context=ctx)
    if not ctx.check_hostname or ctx.verify_mode != ssl.CERT_REQUIRED:
        raise ValueError("El contexto TLS debe verificar certificado y nombre.")
    return urllib.request.build_opener(ManejadorConNombre(ctx, nombre_tls)).open

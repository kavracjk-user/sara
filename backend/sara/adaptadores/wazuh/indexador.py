"""P1. Lectura de alertas del indexador de Wazuh (solo lectura, RNF-02/RNF-04).

Credenciales por variables de entorno, nunca en el código:
  WAZUH_INDEXER_URL   p. ej. https://localhost:9200
  WAZUH_INDEXER_USER  usuario con rol de SOLO consulta
  WAZUH_INDEXER_PASS
  WAZUH_CA_CERT       ruta al certificado de la CA del indexador (recomendado)
  WAZUH_INDEXER_TLS_NOMBRE  nombre del certificado si difiere del host de la URL
                      (laboratorio: wazuh.indexer; ver tls.py)

Solo usa _search (POST de consulta). No hay ninguna llamada de escritura.
"""
from __future__ import annotations

import base64
import json
import os
import urllib.request
from typing import Any, Optional

from sara.adaptadores.wazuh.normalizer import MAPA_CAMPOS
from sara.puertos import (MAX_RELACIONADAS, AlertaNueva, AlertasRelacionadas,
                          MarcaIngesta, ResumenAlerta)
from sara.adaptadores.wazuh.tls import abridor, contexto_tls
from sara.dominio.models import VistaComun

INDICE = "wazuh-alerts-*"
CAMPOS_IP_ORIGEN = MAPA_CAMPOS["ip_origen"]


class IndexadorWazuh:
    def __init__(self, url: Optional[str] = None, usuario: Optional[str] = None,
                 clave: Optional[str] = None, ca_cert: Optional[str] = None,
                 nombre_tls: Optional[str] = None, timeout_s: float = 10.0) -> None:
        self.url = (url or os.environ["WAZUH_INDEXER_URL"]).rstrip("/")
        usuario = usuario or os.environ["WAZUH_INDEXER_USER"]
        clave = clave or os.environ["WAZUH_INDEXER_PASS"]
        self._auth = "Basic " + base64.b64encode(f"{usuario}:{clave}".encode()).decode()
        ca = ca_cert or os.environ.get("WAZUH_CA_CERT")
        self._ctx = contexto_tls(ca)
        self._abrir = abridor(self._ctx, nombre_tls or os.environ.get("WAZUH_INDEXER_TLS_NOMBRE"))
        self.timeout_s = timeout_s

    def _buscar(self, cuerpo: dict[str, Any]) -> dict[str, Any]:
        req = urllib.request.Request(
            f"{self.url}/{INDICE}/_search",
            data=json.dumps(cuerpo).encode(),
            headers={"Content-Type": "application/json", "Authorization": self._auth},
            method="POST",
        )
        with self._abrir(req, timeout=self.timeout_s) as r:
            return json.load(r)

    def disponible(self) -> bool:
        """Para /salud: una búsqueda vacía con el usuario de solo consulta."""
        try:
            self._buscar({"size": 0})
            return True
        except Exception:
            return False

    def alerta_por_id(self, id_alerta: str) -> Optional[dict[str, Any]]:
        res = self._buscar({"size": 1, "query": {"ids": {"values": [id_alerta]}}})
        golpes = res.get("hits", {}).get("hits", [])
        if not golpes:
            return None
        doc = golpes[0]["_source"]
        doc["_id"] = golpes[0]["_id"]
        return doc

    def alertas_por_nivel(self, nivel_min: int, desde: str, hasta: str,
                          tamano: int = 50) -> list[dict[str, Any]]:
        res = self._buscar({
            "size": tamano, "sort": [{"@timestamp": "asc"}],
            "query": {"bool": {"filter": [
                {"range": {"rule.level": {"gte": nivel_min}}},
                {"range": {"@timestamp": {"gte": desde, "lte": hasta}}}]}},
        })
        salida = []
        for h in res.get("hits", {}).get("hits", []):
            d = h["_source"]
            d["_id"] = h["_id"]
            salida.append(d)
        return salida

    def relacionadas(self, vista: VistaComun, ventana: str = "1h",
                     maximo: int = MAX_RELACIONADAS) -> AlertasRelacionadas:
        """Alertas que comparten IP de origen o agente dentro de la ventana (la ventana
        definitiva se fija y documenta en 4.5.2): hasta `maximo`, ordenadas por marca de
        tiempo, con el total real. La propia alerta se excluye por su `_id` del índice."""
        if not vista.marca_tiempo:
            raise ValueError("No hay marca de tiempo para acotar la ventana.")
        if not vista.id_alerta:
            raise ValueError("Sin _id de la alerta no se puede excluir de sus relacionadas.")
        compartidos = []
        if vista.ip_origen:
            # La IP de origen va en srcip (sshd, cortafuegos) o src_ip (tipo Suricata).
            compartidos += [{"term": {campo: vista.ip_origen}} for campo in CAMPOS_IP_ORIGEN]
        if vista.agente_id:
            compartidos.append({"term": {"agent.id": vista.agente_id}})
        if not compartidos:
            return AlertasRelacionadas(0)
        res = self._buscar({
            "size": maximo, "track_total_hits": True,
            "sort": [{"@timestamp": "asc"}],
            "_source": ["rule.id", "rule.description", "rule.level", "@timestamp",
                        "agent.name"],
            "query": {"bool": {
                "must_not": [{"ids": {"values": [vista.id_alerta]}}],
                "should": compartidos, "minimum_should_match": 1,
                "filter": [{"range": {"@timestamp": {
                    "gte": f"{vista.marca_tiempo}||-{ventana}",
                    "lte": f"{vista.marca_tiempo}||+{ventana}"}}}]}},
        })
        golpes = res.get("hits", {}).get("hits", [])
        total = res.get("hits", {}).get("total", {})
        total = total.get("value", len(golpes)) if isinstance(total, dict) else int(total or 0)
        return AlertasRelacionadas(total, tuple(_resumen(h) for h in golpes))

    def alertas_despues_de(self, marca: Optional[MarcaIngesta],
                           lote: int) -> list[AlertaNueva]:
        """Ingesta: alertas posteriores a la marca, en orden ascendente de marca de
        tiempo. El `id` de Wazuh desempata alertas con la misma marca de tiempo
        (search_after), así ninguna se salta ni se repite entre lotes. Solo lectura."""
        cuerpo: dict[str, Any] = {
            "size": lote, "sort": [{"timestamp": "asc"}, {"id": "asc"}],
            "_source": ["timestamp", "rule.id"], "query": {"match_all": {}}}
        if marca is not None:
            cuerpo["search_after"] = list(marca.orden)
        salida = []
        for h in self._buscar(cuerpo).get("hits", {}).get("hits", []):
            fuente = h.get("_source", {}) or {}
            regla = (fuente.get("rule", {}) or {}).get("id")
            salida.append(AlertaNueva(h["_id"], None if regla is None else str(regla),
                                      fuente.get("timestamp"), tuple(h.get("sort", ()))))
        return salida


def _resumen(golpe: dict[str, Any]) -> ResumenAlerta:
    fuente = golpe.get("_source", {}) or {}
    regla = fuente.get("rule", {}) or {}
    nivel = regla.get("level")
    return ResumenAlerta(
        id=golpe["_id"], regla_id=None if regla.get("id") is None else str(regla["id"]),
        regla_descripcion=regla.get("description"),
        regla_nivel=int(nivel) if isinstance(nivel, (int, str)) and str(nivel).isdigit() else None,
        marca_tiempo=fuente.get("@timestamp"),
        agente_nombre=(fuente.get("agent", {}) or {}).get("name"))

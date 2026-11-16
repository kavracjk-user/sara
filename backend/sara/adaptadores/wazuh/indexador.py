"""P1. Lectura de alertas del indexador de Wazuh (solo lectura, RNF-02/RNF-04).

Credenciales por variables de entorno, nunca en el código:
  WAZUH_INDEXER_URL   p. ej. https://localhost:9200
  WAZUH_INDEXER_USER  usuario con rol de SOLO consulta
  WAZUH_INDEXER_PASS
  WAZUH_CA_CERT       ruta al certificado de la CA del indexador (recomendado)

Solo usa _search (POST de consulta). No hay ninguna llamada de escritura.
"""
from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.request
from typing import Any, Optional

from sara.dominio.models import VistaComun

INDICE = "wazuh-alerts-*"


class IndexadorWazuh:
    def __init__(self, url: Optional[str] = None, usuario: Optional[str] = None,
                 clave: Optional[str] = None, ca_cert: Optional[str] = None,
                 timeout_s: float = 10.0) -> None:
        self.url = (url or os.environ["WAZUH_INDEXER_URL"]).rstrip("/")
        usuario = usuario or os.environ["WAZUH_INDEXER_USER"]
        clave = clave or os.environ["WAZUH_INDEXER_PASS"]
        self._auth = "Basic " + base64.b64encode(f"{usuario}:{clave}".encode()).decode()
        ca = ca_cert or os.environ.get("WAZUH_CA_CERT")
        self._ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
        self.timeout_s = timeout_s

    def _buscar(self, cuerpo: dict[str, Any]) -> dict[str, Any]:
        req = urllib.request.Request(
            f"{self.url}/{INDICE}/_search",
            data=json.dumps(cuerpo).encode(),
            headers={"Content-Type": "application/json", "Authorization": self._auth},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout_s, context=self._ctx) as r:
            return json.load(r)

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
                     maximo: int = 20) -> list[str]:
        """Alertas que comparten IP de origen o agente dentro de la ventana
        (la ventana definitiva se fija y documenta en 4.5.2)."""
        if not vista.marca_tiempo:
            raise ValueError("No hay marca de tiempo para acotar la ventana.")
        compartidos = []
        if vista.ip_origen:
            compartidos.append({"term": {"data.srcip": vista.ip_origen}})
        if vista.agente_id:
            compartidos.append({"term": {"agent.id": vista.agente_id}})
        if not compartidos:
            return []
        res = self._buscar({
            "size": maximo, "_source": False,
            "query": {"bool": {
                "must_not": [{"ids": {"values": [vista.id_alerta or ""]}}],
                "should": compartidos, "minimum_should_match": 1,
                "filter": [{"range": {"@timestamp": {
                    "gte": f"{vista.marca_tiempo}||-{ventana}",
                    "lte": f"{vista.marca_tiempo}||+{ventana}"}}}]}},
        })
        return [h["_id"] for h in res.get("hits", {}).get("hits", [])]

"""Guion de eventos sintéticos: garantías que se comprueban sin Docker.

Comprueba que los 24 casos existen y se pueden limpiar, que todo se queda dentro del
laboratorio (solo contenedores de agentes, IP de documentación o de la red del
laboratorio, dominios .test, sin comandos de red ni de ataque) y que no hay datos
personales reales. NO comprueba qué alerta produce Wazuh: eso es wazuh-logtest y la
captura real.
"""
import ipaddress
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

import casos as cs
import sara_eventos as se

AHORA = datetime(2026, 11, 17, 14, 5, 9, tzinfo=timezone.utc)
CASOS = cs.construir(AHORA)
LAB = Path(__file__).resolve().parents[1]

PERMITIDAS = [ipaddress.ip_network(n) for n in
              ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", cs.RED_LAB)]
PROHIBIDOS = re.compile(r"\b(curl|wget|nc|ncat|netcat|nmap|ping|ssh|scp|hydra|telnet|"
                        r"iptables|nft|dig|nslookup|python|perl|bash -i|/dev/tcp)\b")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def todos_los_pasos():
    for c in CASOS.values():
        for p in c.pasos + c.limpieza:
            yield c, p


def test_hay_24_casos_12_pares_A_y_B():
    assert len(CASOS) == 24
    assert sorted({c.par for c in CASOS.values()}) == list(range(1, 13))
    for par in range(1, 13):
        a, b = CASOS[f"{par:02d}A"], CASOS[f"{par:02d}B"]
        assert a.tipo == b.tipo and a.situacion == b.situacion
        assert a.reglas_esperadas == b.reglas_esperadas      # dificultad semejante
        assert len(a.pasos) == len(b.pasos) and a.pausa_s == b.pausa_s


def test_tipos_segun_el_guion():
    tipo = {1: cs.AUTENTICACION, 5: cs.CAMBIO_ARCHIVOS, 9: cs.ACTIVIDAD_RED}
    for c in CASOS.values():
        esperado = tipo[1] if c.par <= 4 else tipo[5] if c.par <= 8 else tipo[9]
        assert c.tipo == esperado, c.clave


def test_agentes_del_guion():
    esperado = {"01A": "srv-web", "01B": "srv-bd", "03A": "pc-lab-01", "04A": "pc-analista",
                "05A": "srv-web", "05B": "srv-bd", "06A": "pc-lab-01", "06B": "pc-analista",
                "08B": "srv-bd", "09A": "srv-web", "10A": "srv-bd", "10B": "srv-web",
                "11A": "pc-lab-01", "11B": "pc-analista", "12A": "pc-nuevo", "12B": "pc-nuevo"}
    for clave, host in esperado.items():
        assert CASOS[clave].contenedor == host, clave


def test_todo_caso_tiene_limpieza_en_los_mismos_contenedores():
    for c in CASOS.values():
        assert c.limpieza, c.clave
        tocados = {p.contenedor for p in c.pasos}
        limpiados = {p.contenedor for p in c.limpieza}
        assert tocados == limpiados, c.clave


def test_solo_contenedores_de_agentes():
    for c, p in todos_los_pasos():
        assert p.contenedor in cs.AGENTES, (c.clave, p.contenedor)
        assert not p.contenedor.startswith("wazuh."), c.clave


def test_sin_comandos_de_red_ni_de_ataque():
    for c, p in todos_los_pasos():
        assert not PROHIBIDOS.search(p.script), (c.clave, p.script)


def test_ip_solo_de_documentacion_o_del_laboratorio():
    for c, p in todos_los_pasos():
        for ip in IPV4.findall(p.entrada + p.script):
            assert any(ipaddress.ip_address(ip) in n for n in PERMITIDAS), (c.clave, ip)


def test_ip_del_guion():
    texto = {k: "".join(p.entrada for p in c.pasos) for k, c in CASOS.items()}
    for clave, ip in {"01A": "203.0.113.10", "01B": "198.51.100.20", "02A": "203.0.113.11",
                      "02B": "198.51.100.21", "04A": "10.10.0.31", "04B": "10.10.0.32",
                      "09A": "203.0.113.50", "09B": "198.51.100.60", "10A": "10.10.0.41",
                      "10B": "10.10.0.42", "12A": "203.0.113.70", "12B": "198.51.100.80"}.items():
        assert ip in texto[clave], clave


def test_dominios_solo_test():
    for c, p in todos_los_pasos():
        for linea in p.entrada.splitlines():
            if linea.startswith("{"):
                rr = json.loads(linea).get("dns", {}).get("rrname")
                if rr:
                    assert rr.endswith(".test"), c.clave
    assert "servicio-a.test" in CASOS["11A"].pasos[0].entrada
    assert "servicio-b.test" in CASOS["11B"].pasos[0].entrada


def test_usuarios_ficticios():
    usuarios = set()
    for _, p in todos_los_pasos():
        usuarios |= set(re.findall(r"(?:Failed|Accepted) password for (\S+)", p.entrada))
    assert usuarios == {"operador", "ana.lab", "luis.lab"}


def test_rutas_del_guion_en_cambio_de_archivos():
    rutas = {"05A": "/etc/passwd", "05B": "/etc/shadow", "06A": "/tmp/prueba_a.com",
             "06B": "/tmp/prueba_b.com", "07A": "/etc/nginx/nginx.conf",
             "07B": "/etc/postgresql/pg_hba.conf", "08A": "/var/log/auth.log",
             "08B": "/var/log/syslog"}
    for clave, ruta in rutas.items():
        assert ruta in CASOS[clave].pasos[0].script, clave
        assert ruta in CASOS[clave].limpieza[0].script, clave


def test_cantidad_suficiente_para_reglas_de_frecuencia():
    # 5763 y 40111/40112 piden 8 fallos de la misma IP; 4151 pide 18 descartes.
    for clave in ("01A", "01B", "02A", "02B", "04A", "04B"):
        principal = CASOS[clave].pasos[0].entrada
        assert principal.count("Failed password") >= 10, clave
    assert "Accepted password" in CASOS["02A"].pasos[0].entrada
    assert "Accepted password" not in CASOS["01A"].pasos[0].entrada
    assert CASOS["03A"].pasos[0].entrada.count("Failed password") == 1
    for clave in ("10A", "10B"):
        assert CASOS[clave].pasos[0].entrada.count(" DROP ") >= 18, clave


def test_alertas_relacionadas_en_otros_dos_equipos():
    for clave in ("04A", "04B", "10A", "10B"):
        c = CASOS[clave]
        otros = {p.contenedor for p in c.pasos} - {c.contenedor}
        assert len(otros) == 2, clave


def test_eicar_correcto_y_no_literal_en_el_repositorio():
    assert len(cs.eicar()) == 68 and cs.eicar().startswith("X5O!P%@AP")
    completa = cs.eicar()
    for f in LAB.rglob("*"):
        if f.is_file() and f.suffix in {".py", ".sh", ".md", ".yml", ".conf", ".json"}:
            assert completa not in f.read_text(encoding="utf-8", errors="ignore"), f


def test_lineas_syslog_y_eve_bien_formadas():
    linea = CASOS["01A"].pasos[0].entrada.splitlines()[0]
    assert linea == ("Nov 17 14:05:09 srv-web sshd[4100]: Failed password for operador "
                     "from 203.0.113.10 port 50100 ssh2")
    eve = json.loads(CASOS["09A"].pasos[0].entrada.splitlines()[0])
    assert eve["event_type"] == "alert" and eve["dest_port"] == 4444
    assert eve["timestamp"] == "2026-11-17T14:05:09.000000+0000"


# ---- Ejecutor ----

class Grabadora:
    def __init__(self, codigo=0):
        self.llamadas, self.codigo = [], codigo

    def __call__(self, cmd, input=None, capture_output=False):
        self.llamadas.append((cmd, input))
        return subprocess.CompletedProcess(cmd, self.codigo, b"", b"error simulado")


def test_ejecutor_usa_exec_en_el_contenedor_y_bytes_sin_crlf():
    g = Grabadora()
    se.ejecutar_pasos(CASOS["01A"].pasos, correr=g)
    cmd, entrada = g.llamadas[0]
    assert cmd[-6:-2] == ["exec", "-T", "srv-web", "sh"]
    assert isinstance(entrada, bytes) and b"\r\n" not in entrada


def test_ejecutor_rechaza_contenedores_ajenos():
    with pytest.raises(ValueError):
        se.comando(cs.Paso("wazuh.indexer", "true"))


def test_ejecutor_falla_si_el_comando_falla():
    with pytest.raises(RuntimeError, match="srv-web"):
        se.ejecutar_pasos(CASOS["01A"].pasos, correr=Grabadora(codigo=1))


def test_manifiesto(tmp_path):
    c = CASOS["12A"]
    datos = se.manifiesto(c, "ejecutar", AHORA, AHORA)
    assert datos["agente_id"] == "099" and datos["reglas_esperadas_hipotesis"] == ["86601"]
    ruta = se.guardar_manifiesto(datos, tmp_path)
    assert ruta.name == "20261117T140509-12A-ejecutar.json"
    assert se.manifiesto(c, "limpiar", AHORA, AHORA)["reglas_esperadas_hipotesis"] == []


def test_seleccionar():
    assert se.seleccionar(CASOS, "1a")[0].clave == "01A"
    assert len(se.seleccionar(CASOS, "todos")) == 24
    with pytest.raises(SystemExit):
        se.seleccionar(CASOS, "13A")

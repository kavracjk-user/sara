"""Guion de 12 pares (docs/anexo-c-guion-casos.md) convertido en pasos ejecutables.

PROPUESTA pendiente del tutor. Aquí solo hay DATOS: qué texto se escribe y en qué
contenedor. Quien lo ejecuta es sara_eventos.py.

Cómo se produce cada tipo, sin herramientas de ataque ni tráfico real (RNF-03):
  - Autenticación: líneas con formato de sshd en /var/log/lab/auth.log del agente.
  - Cambio de archivos: cambios reales a archivos dentro del contenedor del agente,
    con respaldo previo (lo crea lab/wazuh/agentes/base-lab.sh).
  - Actividad de red: líneas SINTÉTICAS de sensor. NO hay tráfico: la firma y el
    nivel de los pares 9, 11 y 12 los escribimos nosotros con formato Suricata, y
    el barrido del par 10 son líneas de descarte de cortafuegos. Es una limitación
    que se declara en la evaluación.

`reglas_esperadas` es una HIPÓTESIS tomada del conjunto de reglas oficial de Wazuh
v4.14.10 (0095-sshd_rules.xml, 0280-attack_rules.xml, 0015-ossec_rules.xml,
0475-suricata_rules.xml, 0900-firewall_rules.xml). Se confirma con wazuh-logtest y
con las alertas capturadas; si no coincide, se corrige aquí, no en los resultados.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta

# ---- Datos del laboratorio ----
RED_LAB = "10.10.0.0/24"                      # lab/wazuh/docker-compose.yml
IP_AGENTE = {
    "srv-web": "10.10.0.11", "srv-bd": "10.10.0.12", "pc-analista": "10.10.0.13",
    "pc-lab-01": "10.10.0.14", "pc-nuevo": "10.10.0.99",
}
AGENTES = tuple(IP_AGENTE)                    # únicos contenedores donde se actúa
AUTH_LOG = "/var/log/lab/auth.log"
RED_LOG = "/var/log/lab/red.log"
EVE_LOG = "/var/log/lab/eve.json"
RESPALDO = "/lab/respaldo"

AUTENTICACION = "autenticacion"
CAMBIO_ARCHIVOS = "cambio_archivos"
ACTIVIDAD_RED = "actividad_red"

MESES = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")   # syslog usa meses en inglés

# Pausa tras cada caso para que las reglas de frecuencia vuelvan a poder dispararse
# (5763: ignore 60 s; 40112: ventana 240 s; 4151: ignore 240 s).
PAUSA_FRECUENCIA_S = 70
PAUSA_BARRIDO_S = 250
PAUSA_CORTA_S = 10


@dataclass(frozen=True)
class Paso:
    contenedor: str
    script: str            # comando sh que se ejecuta DENTRO del contenedor
    entrada: str = ""      # texto que recibe por la entrada estándar


@dataclass(frozen=True)
class Caso:
    par: int
    variante: str          # "A" o "B"
    tipo: str
    situacion: str
    contenedor: str        # agente principal del caso
    pasos: tuple[Paso, ...]
    limpieza: tuple[Paso, ...]
    reglas_esperadas: tuple[str, ...]
    pausa_s: int

    @property
    def clave(self) -> str:
        return f"{self.par:02d}{self.variante}"

    @property
    def contenedores(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(p.contenedor for p in self.pasos + self.limpieza))


# ---- Construcción de líneas ----

def _syslog(t: datetime, host: str, proceso: str, mensaje: str) -> str:
    return f"{MESES[t.month - 1]} {t.day:2d} {t:%H:%M:%S} {host} {proceso}: {mensaje}"


def _sshd(t: datetime, host: str, pid: int, mensaje: str) -> str:
    return _syslog(t, host, f"sshd[{pid}]", mensaje)


def _fallo_ssh(t, host, usuario, ip, puerto, pid=4100):
    return _sshd(t, host, pid, f"Failed password for {usuario} from {ip} port {puerto} ssh2")


def _acceso_ssh(t, host, usuario, ip, puerto, pid=4100):
    return _sshd(t, host, pid, f"Accepted password for {usuario} from {ip} port {puerto} ssh2")


def _fallos(t, host, usuario, ip, n, puerto0=50100):
    return [_fallo_ssh(t + timedelta(seconds=i), host, usuario, ip, puerto0 + i)
            for i in range(n)]


def _descarte(t: datetime, host: str, origen: str, destino: str, puerto: int, n: int) -> str:
    return _syslog(t, host, "kernel",
                   f"[{1000 + n}.000000] DROP IN=eth0 OUT= SRC={origen} DST={destino} "
                   f"LEN=44 TOS=0x00 PREC=0x00 TTL=64 ID={20000 + n} PROTO=TCP "
                   f"SPT={40000 + n} DPT={puerto} WINDOW=1024 RES=0x00 SYN URGP=0")


def _eve(t: datetime, origen: str, puerto_origen: int, destino: str, puerto: int,
         proto: str, firma: str, categoria: str, sid: int, extra: dict | None = None) -> str:
    evento = {
        "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000000+0000"),
        "event_type": "alert",
        "src_ip": origen, "src_port": puerto_origen,
        "dest_ip": destino, "dest_port": puerto, "proto": proto,
        "alert": {"action": "allowed", "gid": 1, "signature_id": sid, "rev": 1,
                  "signature": firma, "category": categoria, "severity": 2},
    }
    if extra:
        evento.update(extra)
    return json.dumps(evento, separators=(",", ":"))


def eicar() -> str:
    """Cadena de prueba antivirus EICAR (inofensiva). Se arma en tiempo de ejecución
    para que el archivo fuente no contenga la cadena completa y el antivirus del
    equipo no lo marque."""
    return "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-" + "ANTIVIRUS-TEST-FILE!$H+H*"


# ---- Pasos reutilizables ----

def _anexar(contenedor: str, ruta: str, lineas: list[str]) -> Paso:
    return Paso(contenedor, f"cat >> {ruta}", "\n".join(lineas) + "\n")


def _vaciar(contenedor: str, ruta: str) -> Paso:
    """Limpieza de registros sintéticos: Wazuh ya los leyó; se vacían sin borrarlos."""
    return Paso(contenedor, f"[ -f {ruta} ] && : > {ruta} || true")


def _restaurar(contenedor: str, ruta: str) -> Paso:
    return Paso(contenedor, f"cat {RESPALDO}{ruta} > {ruta}")


# ---- Los 12 pares ----

def construir(ahora: datetime) -> dict[str, Caso]:
    """Devuelve los 24 casos con marcas de tiempo a partir de `ahora` (UTC)."""
    t = ahora
    casos: list[Caso] = []

    def agregar(**kw):
        casos.append(Caso(**kw))

    # 1. Fallos SSH repetidos desde IP externa, SIN acceso correcto posterior.
    for v, host, ip in (("A", "srv-web", "203.0.113.10"), ("B", "srv-bd", "198.51.100.20")):
        agregar(par=1, variante=v, tipo=AUTENTICACION, contenedor=host,
                situacion="Fallos SSH repetidos desde IP externa, sin acceso correcto posterior",
                pasos=(_anexar(host, AUTH_LOG, _fallos(t, host, "operador", ip, 10)),),
                limpieza=(_vaciar(host, AUTH_LOG),),
                reglas_esperadas=("5760", "5763"), pausa_s=PAUSA_FRECUENCIA_S)

    # 2. Fallos repetidos SEGUIDOS de un acceso correcto, misma IP externa.
    for v, host, ip in (("A", "srv-web", "203.0.113.11"), ("B", "srv-bd", "198.51.100.21")):
        lineas = _fallos(t, host, "operador", ip, 10) + \
            [_acceso_ssh(t + timedelta(seconds=12), host, "operador", ip, 50200)]
        agregar(par=2, variante=v, tipo=AUTENTICACION, contenedor=host,
                situacion="Fallos repetidos seguidos de un acceso correcto, misma IP externa",
                pasos=(_anexar(host, AUTH_LOG, lineas),),
                limpieza=(_vaciar(host, AUTH_LOG),),
                # Hipótesis original; NO se ajusta a lo observado (decisión del autor). Lo
                # observado (40112 en lugar de 5715) va como limitación en README.md.
                reglas_esperadas=("5760", "5763", "5715", "40112"), pausa_s=PAUSA_FRECUENCIA_S)

    # 3. Un único fallo de un usuario legítimo, sin repetición.
    #    IP de origen: equipos de usuario de la red del laboratorio (dato superficial).
    for v, usuario, ip in (("A", "ana.lab", "10.10.0.21"), ("B", "luis.lab", "10.10.0.22")):
        host = "pc-lab-01"
        agregar(par=3, variante=v, tipo=AUTENTICACION, contenedor=host,
                situacion="Un único fallo de un usuario legítimo, sin repetición",
                pasos=(_anexar(host, AUTH_LOG, [_fallo_ssh(t, host, usuario, ip, 50300)]),),
                limpieza=(_vaciar(host, AUTH_LOG),),
                reglas_esperadas=("5760",), pausa_s=PAUSA_CORTA_S)

    # 4. Fallos repetidos desde IP interna, con alertas relacionadas en otros 2 equipos
    #    (decisión aprobada: srv-web y pc-lab-01, 3 fallos en cada uno).
    for v, ip in (("A", "10.10.0.31"), ("B", "10.10.0.32")):
        host = "pc-analista"
        pasos = [_anexar(host, AUTH_LOG, _fallos(t, host, "operador", ip, 10))]
        for otro in ("srv-web", "pc-lab-01"):
            pasos.append(_anexar(otro, AUTH_LOG, _fallos(t, otro, "operador", ip, 3, 50400)))
        agregar(par=4, variante=v, tipo=AUTENTICACION, contenedor=host,
                situacion="Fallos repetidos desde IP interna, con alertas relacionadas en otros 2 equipos",
                pasos=tuple(pasos),
                limpieza=tuple(_vaciar(c, AUTH_LOG) for c in (host, "srv-web", "pc-lab-01")),
                reglas_esperadas=("5760", "5763"), pausa_s=PAUSA_FRECUENCIA_S)

    # 5. Modificación de archivo sensible fuera de la ventana de mantenimiento.
    #    [PENDIENTE] La «ventana de mantenimiento» no viene de Wazuh (ver README).
    for v, host, ruta, linea in (
            ("A", "srv-web", "/etc/passwd",
             "soporte.tmp:x:1500:1500:cuenta sintetica:/home/soporte.tmp:/bin/sh"),
            ("B", "srv-bd", "/etc/shadow", "soporte.tmp:!:20000:0:99999:7:::")):
        agregar(par=5, variante=v, tipo=CAMBIO_ARCHIVOS, contenedor=host,
                situacion="Modificación de archivo sensible fuera de la ventana de mantenimiento",
                pasos=(_anexar(host, ruta, [linea]),),
                limpieza=(_restaurar(host, ruta),),
                reglas_esperadas=("550",), pausa_s=PAUSA_CORTA_S)

    # 6. Creación de archivo de prueba antivirus (EICAR) en directorio temporal.
    for v, host, ruta in (("A", "pc-lab-01", "/tmp/prueba_a.com"),
                          ("B", "pc-analista", "/tmp/prueba_b.com")):
        agregar(par=6, variante=v, tipo=CAMBIO_ARCHIVOS, contenedor=host,
                situacion="Creación de archivo de prueba antivirus (EICAR) en directorio temporal",
                pasos=(Paso(host, f"cat > {ruta}", eicar()),),
                limpieza=(Paso(host, f"rm -f {ruta}"),),
                reglas_esperadas=("554",), pausa_s=PAUSA_CORTA_S)

    # 7. Modificación esperada de configuración durante un cambio planificado.
    #    [PENDIENTE] El «cambio planificado» no viene de Wazuh (ver README).
    for v, host, ruta, linea in (
            ("A", "srv-web", "/etc/nginx/nginx.conf",
             "# CAMBIO-LAB-001 (planificado): ajuste sintetico de prueba"),
            ("B", "srv-bd", "/etc/postgresql/pg_hba.conf",
             "host    all   all   10.10.0.0/24     scram-sha-256   # CAMBIO-LAB-002")):
        agregar(par=7, variante=v, tipo=CAMBIO_ARCHIVOS, contenedor=host,
                situacion="Modificación esperada de configuración durante un cambio planificado",
                pasos=(_anexar(host, ruta, [linea]),),
                limpieza=(_restaurar(host, ruta),),
                reglas_esperadas=("550",), pausa_s=PAUSA_CORTA_S)

    # 8. Eliminación de un archivo de registro del sistema.
    for v, host, ruta in (("A", "srv-web", "/var/log/auth.log"),
                          ("B", "srv-bd", "/var/log/syslog")):
        agregar(par=8, variante=v, tipo=CAMBIO_ARCHIVOS, contenedor=host,
                situacion="Eliminación de un archivo de registro del sistema",
                pasos=(Paso(host, f"rm -f {ruta}"),),
                limpieza=(_restaurar(host, ruta),),
                reglas_esperadas=("553",), pausa_s=PAUSA_CORTA_S)

    # 9. Conexiones salientes repetidas a IP y puerto no habituales (alertas sintéticas).
    for v, host, destino in (("A", "srv-web", "203.0.113.50"), ("B", "srv-bd", "198.51.100.60")):
        lineas = [_eve(t + timedelta(seconds=i), IP_AGENTE[host], 41000 + i, destino, 4444,
                       "TCP", "SARA-LAB conexion saliente a puerto no habitual",
                       "Potentially Bad Traffic", 9000001) for i in range(5)]
        agregar(par=9, variante=v, tipo=ACTIVIDAD_RED, contenedor=host,
                situacion="Conexiones salientes repetidas a IP y puerto no habituales",
                pasos=(_anexar(host, EVE_LOG, lineas),),
                limpieza=(_vaciar(host, EVE_LOG),),
                reglas_esperadas=("86601",), pausa_s=PAUSA_CORTA_S)

    # 10. Barrido de puertos desde IP interna hacia un servidor, con alertas relacionadas
    #     (decisión aprobada: fallos SSH del mismo origen en los otros dos equipos).
    puertos = (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445,
               993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080)
    for v, origen, destino, relacionados in (
            ("A", "10.10.0.41", "srv-bd", ("srv-web", "pc-lab-01")),
            ("B", "10.10.0.42", "srv-web", ("srv-bd", "pc-lab-01"))):
        lineas = [_descarte(t + timedelta(seconds=i), destino, origen, IP_AGENTE[destino], p, i)
                  for i, p in enumerate(puertos)]
        pasos = [_anexar(destino, RED_LOG, lineas)]
        for otro in relacionados:
            pasos.append(_anexar(otro, AUTH_LOG, _fallos(t, otro, "operador", origen, 3, 50500)))
        agregar(par=10, variante=v, tipo=ACTIVIDAD_RED, contenedor=destino,
                situacion="Barrido de varios puertos desde IP interna hacia un servidor, "
                          "con alertas relacionadas",
                pasos=tuple(pasos),
                limpieza=(_vaciar(destino, RED_LOG),) +
                tuple(_vaciar(o, AUTH_LOG) for o in relacionados),
                reglas_esperadas=("4151", "5760"), pausa_s=PAUSA_BARRIDO_S)

    # 11. Consultas a un dominio de prueba controlado (alertas sintéticas).
    for v, host, dominio in (("A", "pc-lab-01", "servicio-a.test"),
                             ("B", "pc-analista", "servicio-b.test")):
        lineas = [_eve(t + timedelta(seconds=i), IP_AGENTE[host], 52000 + i, "10.10.0.53", 53,
                       "UDP", "SARA-LAB consulta DNS a dominio de prueba",
                       "Misc activity", 9000002,
                       {"dns": {"type": "query", "rrname": dominio, "rrtype": "A"}})
                  for i in range(3)]
        agregar(par=11, variante=v, tipo=ACTIVIDAD_RED, contenedor=host,
                situacion="Consultas a un dominio de prueba controlado",
                pasos=(_anexar(host, EVE_LOG, lineas),),
                limpieza=(_vaciar(host, EVE_LOG),),
                reglas_esperadas=("86601",), pausa_s=PAUSA_CORTA_S)

    # 12. Alerta de red sobre un equipo NO catalogado (agente 099).
    for v, destino in (("A", "203.0.113.70"), ("B", "198.51.100.80")):
        host = "pc-nuevo"
        lineas = [_eve(t, IP_AGENTE[host], 43000, destino, 8443, "TCP",
                       "SARA-LAB conexion saliente a destino externo",
                       "Potentially Bad Traffic", 9000003)]
        agregar(par=12, variante=v, tipo=ACTIVIDAD_RED, contenedor=host,
                situacion="Alerta de red sobre un equipo no catalogado (agente 099)",
                pasos=(_anexar(host, EVE_LOG, lineas),),
                limpieza=(_vaciar(host, EVE_LOG),),
                reglas_esperadas=("86601",), pausa_s=PAUSA_CORTA_S)

    return {c.clave: c for c in casos}

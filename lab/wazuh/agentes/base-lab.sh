#!/bin/sh
# SARA — archivos base del guion en cada agente de prueba.
#
# La imagen oficial wazuh/wazuh-agent:4.14.10 ejecuta /entrypoint-scripts/*.sh ANTES
# de arrancar Wazuh (cont-init.d/1-agent). Así el primer escaneo de integridad toma
# estos archivos como línea base y no genera alertas.
#
# Es idempotente: solo crea lo que falta. Los respaldos de /lab/respaldo/ son los que
# usa `lab/eventos/sara_eventos.py limpiar` para dejar todo como estaba.
# Contenido 100 % sintético (RNF-03).
set -e

# P solo se usa en las pruebas (lab/tests) para ejecutar el script en una carpeta
# temporal; dentro del contenedor está vacío.
P="${SARA_RAIZ_PRUEBA:-}"
R=/lab/respaldo

mkdir -p "$P/var/log/lab" "$P/etc/nginx" "$P/etc/postgresql" \
         "$P$R/etc/nginx" "$P$R/etc/postgresql" "$P$R/var/log"

# Registros donde lab/eventos/ escribe los eventos sintéticos.
touch "$P/var/log/lab/auth.log" "$P/var/log/lab/red.log" "$P/var/log/lab/eve.json"

# Par 7: configuraciones que se modifican «en un cambio planificado».
if [ ! -f "$P/etc/nginx/nginx.conf" ]; then
  cat > "$P/etc/nginx/nginx.conf" <<'EOF'
# Configuración sintética del laboratorio SARA (no hay nginx instalado).
worker_processes 1;
events { worker_connections 512; }
EOF
fi
if [ ! -f "$P/etc/postgresql/pg_hba.conf" ]; then
  cat > "$P/etc/postgresql/pg_hba.conf" <<'EOF'
# Configuración sintética del laboratorio SARA (no hay PostgreSQL instalado).
local   all   all                    peer
host    all   all   127.0.0.1/32     scram-sha-256
EOF
fi

# Par 8: registros del sistema que se eliminan.
[ -f "$P/var/log/auth.log" ] || echo "laboratorio SARA: registro sintetico" > "$P/var/log/auth.log"
[ -f "$P/var/log/syslog" ]   || echo "laboratorio SARA: registro sintetico" > "$P/var/log/syslog"

# Respaldos (solo la primera vez): pares 5, 7 y 8.
for f in /etc/passwd /etc/shadow /etc/nginx/nginx.conf /etc/postgresql/pg_hba.conf \
         /var/log/auth.log /var/log/syslog; do
  [ -f "$P$R$f" ] || cp -p "$P$f" "$P$R$f"
done

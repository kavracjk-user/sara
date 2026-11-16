# Laboratorio — Wazuh de un solo nodo (fase 1)

Wazuh **4.14.10** (última versión estable al 2026-11-16), basado en la configuración
oficial [wazuh-docker v4.14.10](https://github.com/wazuh/wazuh-docker/tree/v4.14.10).
Guía oficial: <https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html>

> **Estado: NADA de esta carpeta se ha ejecutado con Docker todavía.** El equipo no
> tenía Docker ni WSL 2 cuando se escribió. Lo comprobado y lo supuesto está al final.

## 0. Requisitos (una sola vez)

1. Instalar WSL 2: `wsl --install` (PowerShell como administrador) y reiniciar.
2. Instalar Docker Desktop con el motor WSL 2.
3. Copiar `lab/wslconfig.ejemplo` a `%UserProfile%\.wslconfig` y ejecutar `wsl --shutdown`.
4. Comprobar: `wsl -d docker-desktop sysctl vm.max_map_count` debe decir `262144`.
   Si no, `wsl -d docker-desktop sysctl -w vm.max_map_count=262144` (se pierde al reiniciar).

Requisitos oficiales: 4 núcleos, 8 GB de RAM para Docker, 50 GB de disco.

## 1. Levantar

Todo desde la raíz del repositorio:

```
cp .env.example .env            # y cambia TODAS las claves
python lab/wazuh/preparar.py
docker compose --env-file .env -f lab/wazuh/generate-indexer-certs.yml run --rm generator
docker compose --env-file .env -f lab/wazuh/docker-compose.yml up -d
```

La primera vez tarda alrededor de un minuto (según Wazuh). Panel: <https://localhost>
con el usuario `admin` y `WAZUH_ADMIN_PASS`. El navegador avisará del certificado: es
de la autoridad local del laboratorio.

`preparar.py` descarga la configuración oficial en `upstream/` y deja en `config/` las
claves y, luego, los certificados. **Ambas carpetas están en `.gitignore`.**

## 2. Usuario de solo consulta y PR-10

```
python lab/wazuh/crear_lector.py
cd backend && python -m pytest -m integracion -q -rs
```

`crear_lector.py` crea el rol `sara_solo_alertas` (permiso `read` solo sobre
`wazuh-alerts-*`) y el usuario `WAZUH_INDEXER_USER`. La prueba PR-10
(`backend/tests/integracion/test_pr10_solo_lectura.py`) comprueba que ese usuario
consulta alertas y que recibe **403** al indexar, actualizar, borrar, crear índices,
escribir en lote o leer otros índices.

## 3. Agentes

| Contenedor | En el catálogo (Anexo C) |
|---|---|
| `srv-web`, `srv-bd`, `pc-analista`, `pc-lab-01` | Sí |
| `pc-nuevo` | **No**, a propósito |

Imagen oficial `wazuh/wazuh-agent:4.14.10`, 256 MB cada uno. Respuesta activa
**desactivada** en los agentes (RNF-01); el servidor oficial tampoco trae ninguna
respuesta activa habilitada.

**[PENDIENTE] Identificadores.** Wazuh asigna el id por orden de registro (001, 002…).
Fijar los id del Anexo C y el `099` de `pc-nuevo` exige registrar cada agente con su id
y entregarle su clave. Falta el Anexo C y poder probarlo con Docker.

## 4. Memoria

| Contenedor | Límite | Variable |
|---|---|---|
| Indexador | 3 GB (memoria Java 1 GB, el valor oficial) | `WAZUH_INDEXER_MEM`, `WAZUH_INDEXER_HEAP` |
| Servidor | 2 GB | `WAZUH_MANAGER_MEM` |
| Panel | 1 GB | `WAZUH_DASHBOARD_MEM` |
| 5 agentes | 256 MB c/u | `WAZUH_AGENTE_MEM` |
| **Total** | **≈ 7,3 GB** | |

Los límites son una propuesta sin medir. Con el laboratorio en marcha, `docker stats`
dice el consumo real; si el indexador se reinicia solo, sube `WAZUH_INDEXER_HEAP` a `2g`
y `WAZUH_INDEXER_MEM` a `4g`. Cuando no uses el panel puedes detenerlo:
`docker compose --env-file .env -f lab/wazuh/docker-compose.yml stop wazuh.dashboard`.

## 5. Apagar

```
docker compose --env-file .env -f lab/wazuh/docker-compose.yml stop      # conserva datos
docker compose --env-file .env -f lab/wazuh/docker-compose.yml down -v   # BORRA los datos
```

## Verificado y supuesto

**Verificado en fuentes oficiales (leído, no ejecutado):**
- Versión 4.14.10, imágenes, variables y volúmenes: `single-node/docker-compose.yml` de la etiqueta.
- Pasos: generar certificados y `docker compose up -d` (`single-node/README.md`).
- Imagen del agente y sus variables `WAZUH_MANAGER_SERVER`, `WAZUH_AGENT_NAME`
  (`docs/ref/configuration/environment-variables.md`).
- Rol de solo lectura = permiso `read` sobre `wazuh-alerts*` (guía de RBAC de Wazuh, vía panel).

**Suposiciones a confirmar al levantar:**
1. `certs.yml` acepta una lista en `ip` (para incluir `127.0.0.1` en el certificado).
   Si falla, la conexión de SARA por `https://127.0.0.1:9200` no validará el certificado.
2. Ruta de `hash.sh` en la imagen del indexador y que `internal_users.yml` se cargue al
   crear el volumen por primera vez (si no, `admin` conservaría la clave por defecto).
3. Que el servidor aplique `API_PASSWORD` al usuario `wazuh-wui` al arrancar.
4. Crear rol y usuario por la API de seguridad en vez del panel.
5. Que el rol sin permisos de clúster baste para `_search` (si no, agregar
   `cluster_composite_ops_ro`, como indica la guía oficial).
6. Formato `syslog` y rutas de los eventos sintéticos en `agentes/ossec.conf`.
7. Límites de memoria y la línea `kernelCommandLine` de `.wslconfig`.

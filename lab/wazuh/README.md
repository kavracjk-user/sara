# Laboratorio — Wazuh de un solo nodo (fase 1)

Wazuh **4.14.10** (última versión estable al 2026-11-16), basado en la configuración
oficial [wazuh-docker v4.14.10](https://github.com/wazuh/wazuh-docker/tree/v4.14.10).
Guía oficial: <https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html>

> **Estado (2026-11-18):** levantado por primera vez con Docker Desktop 29.9.3 (WSL 2,
> 11,7 GB y 4 CPU para Docker). Servidor, indexador, panel y los cinco agentes
> funcionan. Lo comprobado y lo que sigue sin probar está al final.

**Git Bash:** antepón `MSYS_NO_PATHCONV=1` a los `docker compose exec` con rutas
absolutas (p. ej. `/var/ossec/bin/...`); si no, Git Bash las convierte en rutas de
Windows. En PowerShell no hace falta.

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
docker compose --env-file .env -f lab/wazuh/docker-compose.yml up -d wazuh.indexer wazuh.manager wazuh.dashboard
python lab/wazuh/registrar_agentes.py        # ids del Anexo C (ver sección 3)
docker compose --env-file .env -f lab/wazuh/docker-compose.yml up -d
```

El orden importa: si los agentes arrancan antes de `registrar_agentes.py`, Docker crea
una carpeta donde debía ir `client.keys` y el agente no conecta. Arreglo: `down` de los
agentes, borrar `lab/wazuh/claves-agentes/` y repetir.

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

**Probado (2026-11-18): 14/14.** `crear_lector.py` crea el rol `sara_solo_alertas` (permiso `read` solo sobre
`wazuh-alerts-*`) y el usuario `WAZUH_INDEXER_USER`. La prueba PR-10
(`backend/tests/integracion/test_pr10_solo_lectura.py`) comprueba que ese usuario
consulta alertas y que recibe **403** al indexar, actualizar, borrar, crear índices,
escribir en lote o leer otros índices.

## 3. Agentes

Según [docs/anexo-c-guion-casos.md](../../docs/anexo-c-guion-casos.md) (propuesta
pendiente del tutor):

| Contenedor | Id | IP | En el catálogo de SARA |
|---|---|---|---|
| `srv-web` | 001 | 10.10.0.11 | Sí (Alta) |
| `srv-bd` | 002 | 10.10.0.12 | Sí (Alta) |
| `pc-analista` | 003 | 10.10.0.13 | Sí (Media) |
| `pc-lab-01` | 004 | 10.10.0.14 | Sí (Baja) |
| `pc-nuevo` | 099 | 10.10.0.99 | **No**, a propósito |

Imagen oficial `wazuh/wazuh-agent:4.14.10`, 256 MB cada uno. Respuesta activa
**desactivada** en los agentes (RNF-01); el servidor oficial tampoco trae ninguna
respuesta activa habilitada.

**Ids fijos.** Wazuh asigna el id por orden de registro y ni el registro automático ni
`manage_agents` permiten elegirlo. `registrar_agentes.py` usa `POST /agents/insert` de
la API del servidor (acepta `id`, `name`, `ip` y `key`; verificado en la especificación
oficial de la API v4.14.10), escribe cada `client.keys` en `lab/wazuh/claves-agentes/`
(fuera de Git) y el agente arranca con el registro automático desactivado.
`python lab/wazuh/registrar_agentes.py --simular` muestra el plan sin Docker.
**Probado (2026-11-18):** `agent_control -l` lista 001–004 y 099 como `Active`, con
las IP fijas de la tabla.

Antes de arrancar Wazuh, cada agente ejecuta `agentes/base-lab.sh` (mecanismo
`/entrypoint-scripts/` de la imagen oficial): crea los archivos que usa el guion y sus
respaldos, para que el primer escaneo los tome como línea base.

Red del laboratorio: `10.10.0.0/24`. Si choca con tu red local, cámbiala en el Compose
y en `lab/eventos/casos.py`.

## 4. Memoria

| Contenedor | Límite | Variable |
|---|---|---|
| Indexador | 3 GB (memoria Java 1 GB, el valor oficial) | `WAZUH_INDEXER_MEM`, `WAZUH_INDEXER_HEAP` |
| Servidor | 2 GB | `WAZUH_MANAGER_MEM` |
| Panel | 1 GB | `WAZUH_DASHBOARD_MEM` |
| 5 agentes | 256 MB c/u | `WAZUH_AGENTE_MEM` |
| **Total** | **≈ 7,3 GB** | |

Medido con `docker stats` el 2026-11-18, recién levantado y sin eventos: indexador
1,51 GB, servidor 641 MB, panel 250 MB, agentes 16–25 MB cada uno (≈ 2,5 GB en total).
Es una sola medición en reposo, no bajo carga; si el indexador se reinicia solo, sube `WAZUH_INDEXER_HEAP` a `2g`
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

**Suposiciones y su estado** (laboratorio levantado y corrida de los 12 pares el
2026-11-18; re-verificado el 2026-11-25 tras reiniciar el equipo):

Wazuh:

| # | Suposición | Estado | Evidencia |
|---|---|---|---|
| W1 | `certs.yml` acepta una lista en `ip` para incluir `127.0.0.1` en el certificado | **Falló** | `wazuh-certs-tool` solo lee un nombre por nodo («Invalid IP or DNS»). Reemplazo: `WAZUH_INDEXER_TLS_NOMBRE=wazuh.indexer`; se conecta a 127.0.0.1 y valida el certificado contra ese nombre (127.0.0.1 o un nombre equivocado se rechazan). |
| W2 | Ruta de `hash.sh` y carga de `internal_users.yml` al crear el volumen | Confirmada | `admin` con la clave de `.env`: 200; `admin:admin` y `kibanaro:kibanaro`: 401. |
| W3 | El servidor aplica `API_PASSWORD` a `wazuh-wui` | Confirmada | `registrar_agentes.py` obtuvo el token con esa clave. |
| W4 | Crear rol y usuario por la API de seguridad en vez del panel | Confirmada | 201 en rol, usuario y asignación (`crear_lector.py`). |
| W5 | Un rol sin permisos de clúster basta para `_search` | Confirmada | PR-10: `_search` 200 y 403 en toda escritura; 14/14 (2026-11-18 y de nuevo el 2026-11-25, dentro de las 26 de integración). |
| W6 | Formatos y rutas de los logs, sintaxis de `restrict`, FIM en tiempo real | Confirmada | Corrida real: las líneas de `auth.log`, `red.log` y `eve.json` llegan al índice; 550/554/553 en las rutas del guion; escribir en `/var/log/lab/` no genera alertas de integridad. |
| W7 | Límites de memoria y `kernelCommandLine` de `.wslconfig` | **Sin probar** | `vm.max_map_count = 262144` y, tras la corrida, ≈ 2,6 GB en total, dentro de los límites. No se probó carga sostenida ni si el valor viene de `kernelCommandLine` o de un `sysctl` manual. |

Agentes con id fijo (`registrar_agentes.py`):

| # | Suposición | Estado | Evidencia |
|---|---|---|---|
| A1 | Formato de `client.keys`: «ID NOMBRE IP CLAVE» | Confirmada | Los cinco agentes conectan con ese archivo. |
| A2 | `/agents/insert` acepta el id `099` y la IP `any` | Confirmada | `agent_control -l` lista 099 pc-nuevo, IP `any`. |
| A3 | La imagen del servidor trae `curl` | Confirmada | `/usr/bin/curl`. |
| A4 | `wazuh-wui` tiene permiso para crear agentes | Confirmada | Las cinco inserciones respondieron sin error. |
| A5 | El agente conecta solo con `client.keys`, sin registro automático | Confirmada | 001–004 y 099 `Active`; ninguna línea de registro en `ossec.log`. Siguen `Active` tras reiniciar el equipo (2026-11-25). |

**Problemas encontrados y corregidos al levantar:**
- El clon oficial salía con CRLF (`autocrlf=true`); ahora se clona con `core.autocrlf=false`.
- Python 3.13 rechaza la CA oficial (no trae `keyUsage`); `contexto_tls()` quita solo
  `VERIFY_X509_STRICT` y mantiene la verificación de cadena y nombre.
- En Git Bash hay que usar `MSYS_NO_PATHCONV=1` con `docker compose exec`.

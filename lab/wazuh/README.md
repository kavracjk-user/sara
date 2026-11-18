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

**Suposiciones, comprobadas al levantar el laboratorio (2026-11-18):**

| # | Suposición | Estado | Evidencia |
|---|---|---|---|
| 1 | `certs.yml` acepta una lista en `ip` para incluir `127.0.0.1` | **Falló** | `wazuh-certs-tool` solo lee un nombre por nodo («Invalid IP or DNS»). Se reemplazó por `WAZUH_INDEXER_TLS_NOMBRE=wazuh.indexer`: se conecta a 127.0.0.1 y valida el certificado contra ese nombre. |
| 2 | Ruta de `hash.sh` y carga de `internal_users.yml` al crear el volumen | Confirmada | `admin` con la clave de `.env`: 200; `admin:admin` y `kibanaro:kibanaro`: 401. |
| 3 | El servidor aplica `API_PASSWORD` a `wazuh-wui` | Confirmada | `registrar_agentes.py` obtuvo el token con esa clave. |
| 4 | Rol y usuario por la API de seguridad en vez del panel | Confirmada | 201 en rol, usuario y asignación. |
| 5 | Un rol sin permisos de clúster basta para `_search` | Confirmada | PR-10: `_search` 200 (191 alertas); 14/14 pruebas. |
| 6 | Formatos y rutas de los logs, sintaxis de `restrict`, FIM en tiempo real | Parcial | logcollector lee los 3 archivos; logtest decodifica `sshd`, `kernel` y `json`; FIM en tiempo real iniciado (6012). **Sin probar:** que las líneas escritas en los archivos lleguen al índice y que `restrict` limite lo que se vigila (requiere correr los pares). |
| 7 | Límites de memoria y `kernelCommandLine` de `.wslconfig` | Parcial | `vm.max_map_count = 262144`. Consumo en reposo ≈ 2,5 GB, por debajo de los límites. **Sin probar** bajo carga. |
| 8 | Registro con id fijo (5 suposiciones de agentes) | Confirmada | Ver `registrar_agentes.py` y la sección 3. |

**Problemas encontrados y corregidos al levantar:**
- El clon oficial salía con CRLF (`autocrlf=true`); ahora se clona con `core.autocrlf=false`.
- Python 3.13 rechaza la CA oficial (no trae `keyUsage`); `contexto_tls()` quita solo
  `VERIFY_X509_STRICT` y mantiene la verificación de cadena y nombre.
- En Git Bash hay que usar `MSYS_NO_PATHCONV=1` con `docker compose exec`.

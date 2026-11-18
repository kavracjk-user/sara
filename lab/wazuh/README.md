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

`crear_lector.py` crea el rol `sara_solo_alertas` (permiso `read` solo sobre
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
**Sin probar contra un servidor real.**

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
6. Formato `syslog`/`json` y rutas de los eventos sintéticos en `agentes/ossec.conf`;
   sintaxis de `restrict` y monitoreo en tiempo real dentro del contenedor.
7. Límites de memoria y la línea `kernelCommandLine` de `.wslconfig`.
8. Registro con id fijo: formato de `client.keys`, que se acepten `099` e IP `any`, que
   la imagen del servidor tenga `curl` y que el agente use `client.keys` con el
   registro automático desactivado.

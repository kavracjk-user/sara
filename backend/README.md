# SARA — prototipo de laboratorio

Sistema de Automatización de Respuesta a Amenazas para apoyar la investigación inicial
de alertas en un laboratorio SOC. **No ejecuta bloqueos, aislamiento ni contención**
(RNF-01); la decisión es siempre del analista (RNF-06).

## Estado

| Parte | Archivo | Estado |
|---|---|---|
| Modelos y estados (Tabla 3.4) | `sara/dominio/models.py` | Probado |
| Normalización (P2, Tabla 4.14) | `sara/adaptadores/wazuh/normalizer.py` | Probado con 8 alertas reales del laboratorio (`tests/fixtures/`) |
| Indicadores (P3) | `sara/dominio/indicators.py` | Probado |
| Prioridad sugerida (P5, Tabla 3.5) | `sara/dominio/priority.py` | Probado; **umbrales 7/12 son una propuesta** |
| Pasos con reintentos y tiempo máximo | `sara/aplicacion/steps.py` | Probado |
| Investigación P2–P5 y decisión P6 | `sara/aplicacion/pipeline.py` | Probado |
| Lectura de Wazuh (P1) | `sara/adaptadores/wazuh/indexador.py` | Probado contra el indexador del laboratorio con el usuario de solo consulta (PR-10 y relacionadas) |
| Persistencia (catálogo y casos) | `sara/adaptadores/postgres/` | Probado contra PostgreSQL 16 del Compose raíz: recorrido alerta real → investigar → guardar → releer → `v_exportacion` |
| Flujo Prefect (fase 3) | `sara/interfaces/flows.py` | Probado con Prefect 3.9.5 en proceso (servidor temporal local) contra Wazuh y PostgreSQL reales: P1 leer → P2–P5 → guardar → releer |
| API del analista (fase 4) | `sara/interfaces/api.py`, `sara/aplicacion/casos.py`, `sara/interfaces/composicion.py` | Probada: 36 pruebas sin servicios y 5 contra Wazuh y PostgreSQL reales; también desde su contenedor. Contrato: `docs/api.md` y `docs/api/openapi.json` |
| Esquema PostgreSQL | `sql/schema.sql` + `sql/seed_catalogo_anexo_c.sql` (Compose los carga al crear el volumen); `sql/migraciones/` para bases existentes | Probado: se aplica al crear el volumen del contenedor. Fase 2 agregó a `caso` el resto de la vista común (IP, usuario, dominio, archivo, id del agente según la alerta) |

## Pruebas

```
python -m venv .venv                                  # desde backend/
.venv/Scripts/python -m pip install -r requirements.txt
.venv/Scripts/python -m pytest -q                     # sin servicios
.venv/Scripts/python -m pytest -m integracion -q -rs  # con lab/wazuh y `docker compose up -d postgres`
```

Con el Python global (sin Prefect) las pruebas del flujo se omiten con el motivo.

Las de integración se omiten (con el motivo) si falta Wazuh o PostgreSQL: una prueba
omitida no es una prueba aprobada.

## Persistencia (fase 2)

- Credenciales de PostgreSQL solo por entorno (`POSTGRES_*`, ver `.env.example`).
- Catálogo de activos: sintético, del Anexo C (propuesta pendiente del tutor). El agente
  099 no está a propósito: sus casos quedan en «Información insuficiente».
- `RepositorioPostgres.guardar` es idempotente; una decisión solo se agrega si cambia y
  `t1` (primera decisión) no se sobrescribe. `v_exportacion` usa la primera decisión.
- Todo caso se guarda con `procedimiento = 'sara'`. **[PENDIENTE — autor]:** cómo se
  registran los casos manuales de la línea base para la evaluación comparativa.
- **[PENDIENTE — autor]:** las columnas nuevas de `caso` cambian el modelo preliminar
  (Tabla 2.4 del perfil); hay que reflejarlo en el perfil.

## Flujo de Prefect (fase 3)

- `investigacion_inicial(id_alerta)` recibe solo el `_id` del índice. Lee con el usuario
  de solo consulta, investiga, guarda en PostgreSQL y devuelve el caso releído.
- Reintentos y tiempo máximo: los de `steps.py` (2 reintentos, 10 s) en cada paso; las
  tareas de Prefect no reintentan por su cuenta.
- Alerta inexistente → P1 «sin resultado»; índice caído → P1 «fallido». En ambos casos
  **no se guarda caso** y la prioridad es «Información insuficiente».
- Fallo de relacionadas o del catálogo → ese paso queda «fallido» y el flujo sigue.
- Fallo al guardar → el flujo falla a la vista (el caso no quedó registrado).
- Sin `PREFECT_API_URL`, Prefect abre un servidor **temporal** en 127.0.0.1 mientras
  dura el proceso (≈ 20 s la primera vez). `flows.py` fija, si el entorno no dice otra
  cosa: `PREFECT_HOME=backend/.prefect` (fuera de Git), sin analítica anónima, sin
  interfaz web y sin métricas de recursos.
- Para correr el flujo fuera de las pruebas, las variables `WAZUH_INDEXER_*`,
  `WAZUH_CA_CERT` y `POSTGRES_*` deben estar en el entorno del proceso (el flujo no lee
  `.env` por sí mismo).

## API (fase 4)

Contrato: `docs/api.md`. OpenAPI: `docs/api/openapi.json` (regenerar con
`.venv/Scripts/python scripts/exportar_openapi.py`; una prueba falla si queda viejo).

```
# Local (desde backend/, con las variables de entorno cargadas en el proceso):
.venv/Scripts/python -m sara.interfaces.composicion          # 127.0.0.1:8000
# Contenedor (desde la raíz; necesita API_KEY_SARA propia en .env):
docker compose --profile api up -d --build api
```

- Lo único que escribe: casos (por el flujo) y decisiones. Wazuh: solo lectura; sin
  rutas de contención. Solo dos rutas POST: `/investigaciones` y `/casos/{id}/decision`.
- Clave `X-API-Key` en todas las rutas (incluida `/salud`); sin `API_KEY_SARA`, 503.
  CORS de un solo origen (`SARA_CORS_ORIGEN`, por defecto `http://localhost:5173`).
- Errores en español con un único esquema; sin trazas ni credenciales (los textos de
  error de los pasos pasan por un filtro de secretos conocidos).
- `api.py` no importa adaptadores; todo se arma en `composicion.py` (único punto).
- El id del caso es el `_id` del índice (`^[A-Za-z0-9_-]{1,64}$`).
- Decisión con analista (columna nueva `analista`, migración
  `sql/migraciones/001_analista_en_decision.sql`, ya aplicada a la base del
  laboratorio). En el piloto, seudónimos (`analista-01`), no nombres reales (RNF-03).
- Contenedor: usuario uid 1000 sin privilegios; Wazuh por `host.docker.internal`
  validando el certificado contra `wazuh.indexer`; publicado solo en 127.0.0.1.

## Ingesta de alertas nuevas (fase 4b)

```
.venv/Scripts/python -m sara.interfaces.ingesta --una-vez     # desde backend/
```

- Lee el índice con el usuario de solo consulta, en orden ascendente de marca de tiempo
  (desempate por el `id` de Wazuh, con `search_after`), desde la marca guardada en
  `ingesta_marca`. Máximo `SARA_INGESTA_LOTE` alertas (100 por defecto).
- Solo las reglas de `SARA_REGLAS_INGESTA` (por defecto `REGLAS_CATALOGADAS`: las 8
  reglas que dispararon en la corrida real). Las demás se omiten y se cuentan.
- Idempotente: una alerta con caso se omite. Un fallo se registra (sin credenciales) y
  el lote sigue; la marca se queda antes del primer fallo para reintentarlo.
- Imprime un resumen JSON: leídas, creadas, omitidas por regla (con detalle), ya
  existentes, con error. Código de salida 1 si hubo errores.
- **t0 hoy:** es el momento en que SARA **investiga** la alerta (lo fija el pipeline al
  crear el caso), no la marca de tiempo de la alerta. Con la ingesta, t0 = momento de la
  ingesta; con `POST /investigaciones`, momento de la petición. **[PENDIENTE — autor y
  tutor]:** decidir si t0 debe ser la hora en que la alerta queda disponible para el
  analista (y cuál es esa hora). No se cambió el comportamiento.
- No se ejecutó contra la base real fuera de las pruebas.

## Lo que NO está probado

- Prefect con servidor propio, despliegues, programación periódica ni la interfaz web
  de Prefect (se dejan para cuando se decida cómo se ejecuta SARA en el piloto).
- El flujo con varias alertas a la vez o en paralelo.
- La API con varios usuarios o peticiones simultáneas; dos decisiones a la vez sobre el
  mismo caso (t1 está protegido por un bloqueo de fila, pero el 409 por decisión
  repetida se comprueba fuera de la transacción).
- Listado y exportación con muchos casos: se cargan todos y se filtran en memoria.
- `POST /investigaciones` tarda lo que el flujo (≈ 20 s la primera vez por el servidor
  temporal de Prefect); no hay cola ni tiempo máximo HTTP propio.
- HTTPS en la propia API (escucha HTTP en 127.0.0.1); rotación de `API_KEY_SARA`.
- El contrato frente a RF-09 a RF-14 y la Tabla 4.18 del perfil (no accesible desde el
  repositorio).
- `uid 1000` en la imagen depende de con qué usuario generó los certificados
  `wazuh-certs-tool` en esta máquina.
- Aviso de Starlette: «Using httpx with starlette.testclient is deprecated; install
  httpx2». No afecta a las pruebas; no se cambió.
- Al cerrar el proceso de pruebas, Prefect imprime «Logging error … I/O operation on
  closed file»: su registro escribe después de que pytest cerró la salida. No afecta a
  los resultados; no se corrigió.
- Esquema nuevo sobre una base con datos (no hay migraciones).
- La regla 5715 (no disparó en la corrida; ver `lab/eventos/README.md`).

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
| Interfaz FastAPI | `sara/interfaces/api.py` | **Sin probar**; almacén en memoria provisional |
| Esquema PostgreSQL | `sql/schema.sql` + `sql/seed_catalogo_anexo_c.sql` (Compose los carga al crear el volumen) | Probado: se aplica al crear el volumen del contenedor. Fase 2 agregó a `caso` el resto de la vista común (IP, usuario, dominio, archivo, id del agente según la alerta) |

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

## Lo que NO está probado

- Prefect con servidor propio, despliegues, programación periódica ni la interfaz web
  de Prefect (se dejan para cuando se decida cómo se ejecuta SARA en el piloto).
- El flujo con varias alertas a la vez o en paralelo.
- La API FastAPI (`sara/interfaces/api.py`): sigue con almacén en memoria y sin probar.
- Al cerrar el proceso de pruebas, Prefect imprime «Logging error … I/O operation on
  closed file»: su registro escribe después de que pytest cerró la salida. No afecta a
  los resultados; no se corrigió.
- Esquema nuevo sobre una base con datos (no hay migraciones).
- La regla 5715 (no disparó en la corrida; ver `lab/eventos/README.md`).

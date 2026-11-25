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
| Flujo Prefect | `sara/interfaces/flows.py` | **Sin probar** (falta instalar `prefect`) |
| Interfaz FastAPI | `sara/interfaces/api.py` | **Sin probar**; almacén en memoria provisional |
| Esquema PostgreSQL | `sql/schema.sql` + `sql/seed_catalogo_anexo_c.sql` (Compose los carga al crear el volumen) | Probado: se aplica al crear el volumen del contenedor. Fase 2 agregó a `caso` el resto de la vista común (IP, usuario, dominio, archivo, id del agente según la alerta) |

## Pruebas

```
pip install -r requirements.txt
python -m pytest -q                       # sin servicios
python -m pytest -m integracion -q -rs    # con lab/wazuh y `docker compose up -d postgres`
```

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

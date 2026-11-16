# SARA — prototipo de laboratorio

Sistema de Automatización de Respuesta a Amenazas para apoyar la investigación inicial
de alertas en un laboratorio SOC. **No ejecuta bloqueos, aislamiento ni contención**
(RNF-01); la decisión es siempre del analista (RNF-06).

## Estado

| Parte | Archivo | Estado |
|---|---|---|
| Modelos y estados (Tabla 3.4) | `sara/dominio/models.py` | Probado |
| Normalización (P2, Tabla 4.14) | `sara/adaptadores/wazuh/normalizer.py` | Probado con documentos simulados; el mapeo de campos se confirma con alertas reales (Sprint 4) |
| Indicadores (P3) | `sara/dominio/indicators.py` | Probado |
| Prioridad sugerida (P5, Tabla 3.5) | `sara/dominio/priority.py` | Probado; **umbrales 7/12 son una propuesta** |
| Pasos con reintentos y tiempo máximo | `sara/aplicacion/steps.py` | Probado |
| Investigación P2–P5 y decisión P6 | `sara/aplicacion/pipeline.py` | Probado |
| Lectura de Wazuh (P1) | `sara/adaptadores/wazuh/indexador.py` | **Sin probar** contra un indexador real |
| Flujo Prefect | `sara/interfaces/flows.py` | **Sin probar** (falta instalar `prefect`) |
| Interfaz FastAPI | `sara/interfaces/api.py` | **Sin probar**; almacén en memoria provisional |
| Esquema PostgreSQL | `sql/schema.sql` (Compose lo carga al crear el volumen) | Probado en PostgreSQL 16 local: se aplica, la vista de exportación calcula minutos y las restricciones rechazan datos inválidos. El contenedor de Compose **no** se ha ejecutado |
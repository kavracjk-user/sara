# SARA — prototipo de laboratorio

Sistema de Automatización de Respuesta a Amenazas para apoyar la investigación inicial
de alertas en un laboratorio SOC. **No ejecuta bloqueos, aislamiento ni contención**
(RNF-01); la decisión es siempre del analista (RNF-06).

## Estado

| Parte | Archivo | Estado |
|---|---|---|
| Modelos y estados (Tabla 3.4) | `sara/models.py` | Probado |
| Normalización (P2, Tabla 4.14) | `sara/normalizer.py` | Probado con documentos simulados; el mapeo de campos se confirma con alertas reales (Sprint 4) |
| Indicadores (P3) | `sara/indicators.py` | Probado |
| Prioridad sugerida (P5, Tabla 3.5) | `sara/priority.py` | Probado; **umbrales 7/12 son una propuesta** |
| Pasos con reintentos y tiempo máximo | `sara/steps.py` | Probado |
| Investigación P2–P5 y decisión P6 | `sara/pipeline.py` | Probado |
| Lectura de Wazuh (P1) | `sara/wazuh_client.py` | **Sin probar** contra un indexador real |
| Flujo Prefect | `sara/flows.py` | **Sin probar** (falta instalar `prefect`) |
| Interfaz FastAPI | `sara/api.py` | **Sin probar**; almacén en memoria provisional |
| Esquema PostgreSQL | `sql/schema.sql` | **Sin probar** (falta PostgreSQL) |

## Ejecutar las pruebas

```
python -m pytest -q          # 45 pruebas, solo biblioteca estándar + pytest
```

## Próximos pasos (según el plan de sprints)

1. **S4** — Conectar `wazuh_client.py` a tu indexador con un usuario de **solo consulta**
   (variables `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASS`,
   `WAZUH_CA_CERT`). Confirmar los nombres reales de campo y corregir `MAPA_CAMPOS`.
   Probar PR-10: que ese usuario NO pueda escribir.
2. **S5** — Instalar Prefect, probar `flows.py`, fijar reintentos y tiempo máximo en
   `steps.py` y justificarlos en la sección 4.5.2.
3. **S6** — Crear la base con `sql/schema.sql`, cargar el catálogo de activos y
   reemplazar el almacén en memoria de `api.py` por PostgreSQL.
4. **S7** — Plantillas HTML (lista, expediente, decisión) y exportación (RF-14).

## Decisiones que NO son del desarrollador

Los umbrales de nivel de alerta (`Umbrales`) y la importancia de cada activo deben
fijarse con el Product Owner **antes** del piloto y no cambiarse después.

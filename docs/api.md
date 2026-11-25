# API de SARA — contrato (fase 4)

Estado: **propuesta**, 2026-11-25. Base para la interfaz del analista (Tabla 4.18).

> **Fuentes.** El perfil (RF-09 a RF-14, Tabla 4.18) está en el Project «sara», que no
> es accesible desde el repositorio. Este contrato se escribió a partir de
> `backend/sara/interfaces/api.py` (fase 0), `backend/sql/schema.sql`, el dominio y la
> especificación de la fase 4. **[PENDIENTE — autor]:** contrastarlo con RF-09 a RF-14 y
> la Tabla 4.18 y registrar cualquier diferencia.

## Principios

- **Solo lectura sobre Wazuh (RNF-02).** La API escribe únicamente en la base de SARA y
  solo dos cosas: casos (por el flujo `investigacion_inicial`) y decisiones del analista.
- **Sin contención (RNF-01).** No hay endpoints de bloqueo, aislamiento ni respuesta activa.
- **La decisión es del analista (RNF-06).** SARA sugiere una prioridad y muestra motivos.
- **Estados distintos (RNF-07).** `con_resultado`, `sin_resultado`, `fallido` y
  `no_aplicable` nunca se mezclan; un dato que falta se muestra como «dato no disponible».
- **Procedencia (RNF-05).** Cada dato de la evidencia indica el campo de origen; cada
  paso, su fuente y su hora.

## Identificador del caso

El id de un caso es el **`_id` del índice de Wazuh** de su alerta (el mismo
identificador que usa todo SARA desde la fase 1). En la URL debe cumplir
`^[A-Za-z0-9_-]{1,64}$`; lo demás se rechaza con 422.

## Seguridad

| Aspecto | Regla |
|---|---|
| Red | Escucha en `127.0.0.1` por defecto (`SARA_API_HOST`, `SARA_API_PORT`=8000). |
| Autenticación | Cabecera `X-API-Key` en **todas** las rutas, incluida `/salud`. Se compara con `API_KEY_SARA` (entorno) en tiempo constante. Falta o es incorrecta: 401. Si `API_KEY_SARA` no está definida, toda petición recibe 503. |
| CORS | Un solo origen: `SARA_CORS_ORIGEN` (por defecto `http://localhost:5173`); métodos GET y POST; cabeceras `X-API-Key` y `Content-Type`. |
| Errores | Nunca incluyen trazas, rutas internas, consultas ni credenciales. Los textos de error de los pasos se filtran antes de salir. |

## Endpoints

### GET /salud
Estado de la API y de sus dependencias, sin detalles internos.

```json
{"estado": "ok", "dependencias": {"indexador": "disponible", "base_de_datos": "disponible"}}
```
`estado` es `ok` si todas están disponibles y `degradado` si alguna no. Siempre 200
(con clave válida): la salud degradada no es un error de la petición.

### POST /investigaciones
Ejecuta el flujo `investigacion_inicial` para una alerta y devuelve el expediente.

Cuerpo: `{"id_alerta": "EFMA7aEBs5MtR6RaAjmP"}`

| Código | Cuándo |
|---|---|
| 201 | Caso creado; cuerpo = expediente (como `GET /casos/{id}`). |
| 404 | La alerta no existe en el índice (P1 «sin resultado»). No se crea caso. |
| 409 | Ya existe un caso para esa alerta (no se re-investiga: cambiaría la evidencia que el analista ya pudo ver). |
| 422 | `id_alerta` con formato inválido. |
| 503 | No se pudo leer la alerta (P1 «fallido») o no se pudo guardar el caso. |

### GET /casos
Lista paginada, de más reciente a más antiguo (`t0`).

Parámetros: `pagina` (≥ 1, por defecto 1), `tamano` (1–100, por defecto 20),
`prioridad` (`Alta`, `Media`, `Baja`, `Información insuficiente`), `con_decision`
(`true`/`false`).

```json
{"pagina": 1, "tamano": 20, "total": 2,
 "casos": [{"id": "...", "tipo_alerta": "autenticacion", "regla_id": "5763",
            "regla_nivel": 10, "agente_id": "001", "agente_nombre": "srv-web",
            "prioridad_sugerida": "Alta", "tiene_decision": false,
            "decision": null, "t0": "...", "t1": null}]}
```

### GET /casos/{id}
Expediente completo.

```json
{
  "id": "...", "t0": "...", "t1": null, "minutos_hasta_decision": null,
  "alerta": {"tipo_alerta": "...", "marca_tiempo": "...", "regla_id": "...",
             "regla_nivel": 10, "regla_descripcion": "...", "agente_id": "001",
             "agente_nombre": "srv-web", "ip_origen": "...", "ip_destino": null,
             "usuario": "...", "dominio": null, "archivo_ruta": null,
             "archivo_hash": null, "evento": null, "campos_ausentes": []},
  "evidencia": [{"dato": "ip_origen", "valor": "203.0.113.10", "procedencia": "data.srcip"}],
  "indicadores": [{"tipo": "ip", "valor": "203.0.113.10", "origen_campo": "ip_origen"}],
  "pasos": [{"paso": "P1_lectura_alerta", "estado": "con_resultado", "inicio": "...",
             "fin": "...", "reintentos": 0, "fuente": "wazuh_indexer",
             "procedencia": "consulta de solo lectura", "error": null}],
  "alertas_relacionadas": ["..."],
  "prioridad": {"nivel": "Alta", "motivos": ["..."], "nivel_alerta": "Medio",
                "importancia": "Alta", "corroborada": true},
  "decisiones": [{"decision": "escalar", "justificacion": "...",
                  "prioridad_considerada": "Alta", "analista": "analista-01",
                  "registrada_en": "..."}]
}
```
`evidencia[].valor` es `"dato no disponible"` cuando la alerta no traía ese dato y
`procedencia` es `null`. `decisiones` va de la más antigua a la más reciente.

| Código | Cuándo |
|---|---|
| 200 | Expediente. |
| 404 | No existe un caso con ese id. |
| 422 | Id con formato inválido. |

### POST /casos/{id}/decision
Registra la decisión del analista.

```json
{"decision": "escalar", "justificacion": "Fallos repetidos y acceso correcto.",
 "prioridad_considerada": "Alta", "analista": "analista-01"}
```
- `decision`: `escalar`, `descartar` o `solicitar_mas_informacion`.
- `justificacion`: obligatoria, no vacía (sin contar espacios), hasta 2000 caracteres.
- `prioridad_considerada`: un nivel de prioridad (la que el analista consideró).
- `analista`: obligatorio, no vacío, hasta 100 caracteres. En el piloto, usar un
  seudónimo (p. ej. `analista-01`), no el nombre real (RNF-03).
- `t1` se fija con la **primera** decisión y no cambia después.

| Código | Cuándo |
|---|---|
| 201 | Decisión registrada; cuerpo = expediente actualizado. |
| 404 | No existe el caso. |
| 409 | Idéntica a la última decisión (mismos decisión, justificación, prioridad considerada y analista): no se duplica. |
| 422 | Valor no permitido, justificación o analista vacíos, id inválido. |

### GET /exportacion
Casos para la evaluación comparativa (RF-14). Parámetro `formato`: `json` (por
defecto) o `csv`.

Columnas: `id`, `tipo_alerta`, `procedimiento`, `t0`, `t1`, `minutos_hasta_decision`,
`prioridad_sugerida`, `decision` (la **primera**), `prioridad_considerada` (de la
primera), `completitud` (% de campos obligatorios del tipo de alerta que se
registraron).

JSON: `{"casos": [ {...}, ... ]}`. CSV: `text/csv; charset=utf-8`, separador `,`,
cabecera en la primera fila, fechas ISO 8601 en UTC.

## Errores

Todas las respuestas de error usan el mismo cuerpo:

```json
{"error": {"codigo": "no_encontrado", "mensaje": "No existe un caso con ese id.",
           "detalles": []}}
```

| HTTP | `codigo` | Mensaje (ejemplo) |
|---|---|---|
| 400 | `peticion_invalida` | «La petición no es válida.» |
| 401 | `no_autorizado` | «Falta la clave de API o no es válida.» |
| 404 | `no_encontrado` | «No existe un caso con ese id.» / «La alerta no existe en el índice.» |
| 409 | `conflicto` | «Ya existe un caso para esa alerta.» / «La decisión es idéntica a la última registrada.» |
| 422 | `datos_invalidos` | «Los datos enviados no son válidos.»; `detalles` = `[{"campo": "justificacion", "problema": "..."}]` (sin repetir el valor enviado). |
| 500 | `error_interno` | «Error interno. El detalle quedó en el registro del servidor.» |
| 503 | `servicio_no_disponible` | «Una dependencia no está disponible.» / «La API no tiene clave configurada.» |

Ningún error incluye trazas, rutas de archivos, consultas SQL, URLs internas ni
credenciales.

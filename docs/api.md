# API de SARA — contrato (fase 4)

Estado: **propuesta**, 2026-11-25. Base para la interfaz del analista (Tabla 4.18).

> **Fuentes.** Escrito a partir de `backend/sara/interfaces/api.py` (fase 0),
> `backend/sql/schema.sql`, el dominio y la especificación de la fase 4. **El autor lo
> contrastó con RF-09 a RF-14, RNF-05 y la Tabla 4.18 del perfil el 25-nov-2026**; las
> cuatro brechas que encontró (hora de obtención, relacionadas con detalle, número de
> caso y tiempo máximo) se cerraron en la fase 4b. Ver «Cobertura del perfil» al final.

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

## Número de caso

Además del id, cada caso tiene `numero_caso` con formato `C-0007`: un correlativo
asignado al crearlo (secuencia de PostgreSQL), que **nunca se reutiliza**, ni siquiera
si se borra un caso. Volver a guardar un caso no cambia su número. Aparece en la lista,
el expediente y la exportación; las URL siguen usando el id. Más de 9999 casos siguen
creciendo (`C-10000`). Un número puede quedar sin usar si una creación falla a mitad de
la transacción (las secuencias no retroceden).

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
| 504 | La investigación superó `SARA_TIMEOUT_INVESTIGACION` (90 s por defecto). No se crea el caso. |

**Tiempo máximo.** El flujo corre con un límite. Si se agota, la API responde 504 sin
esperar más. El flujo puede seguir corriendo en segundo plano, pero recibe el mismo
límite y **no guarda** si ya pasó cuando llega a guardar; guardar es una sola
transacción, así que nunca queda un caso a medias. Caso límite: si el guardado ya había
empezado justo antes del límite, el caso queda completo aunque la respuesta haya sido
504; un reintento recibe entonces 409. La primera investigación tras arrancar la API
tarda más (≈ 20 s) porque Prefect abre su servidor temporal.

### GET /casos
Lista paginada, de más reciente a más antiguo (`t0`).

Parámetros: `pagina` (≥ 1, por defecto 1), `tamano` (1–100, por defecto 20),
`prioridad` (`Alta`, `Media`, `Baja`, `Información insuficiente`), `con_decision`
(`true`/`false`).

```json
{"pagina": 1, "tamano": 20, "total": 2,
 "casos": [{"id": "...", "numero_caso": "C-0007", "tipo_alerta": "autenticacion",
            "regla_id": "5763",
            "regla_nivel": 10, "agente_id": "001", "agente_nombre": "srv-web",
            "prioridad_sugerida": "Alta", "tiene_decision": false,
            "decision": null, "t0": "...", "t1": null}]}
```

### GET /casos/{id}
Expediente completo.

```json
{
  "id": "...", "numero_caso": "C-0007", "t0": "...", "t1": null,
  "minutos_hasta_decision": null,
  "alerta": {"tipo_alerta": "...", "marca_tiempo": "...", "regla_id": "...",
             "regla_nivel": 10, "regla_descripcion": "...", "agente_id": "001",
             "agente_nombre": "srv-web", "ip_origen": "...", "ip_destino": null,
             "usuario": "...", "dominio": null, "archivo_ruta": null,
             "archivo_hash": null, "evento": null, "campos_ausentes": []},
  "evidencia": [{"dato": "ip_origen", "valor": "203.0.113.10", "procedencia": "data.srcip",
                 "obtenida_en": "2026-11-25T17:45:51.006088+00:00"}],
  "indicadores": [{"tipo": "ip", "valor": "203.0.113.10", "origen_campo": "ip_origen"}],
  "pasos": [{"paso": "P1_lectura_alerta", "estado": "con_resultado", "inicio": "...",
             "fin": "...", "reintentos": 0, "fuente": "wazuh_indexer",
             "procedencia": "consulta de solo lectura", "error": null}],
  "alertas_relacionadas": [{"id": "...", "regla_id": "5760",
                            "regla_descripcion": "sshd: authentication failed.",
                            "regla_nivel": 5, "marca_tiempo": "2026-11-18T04:52:36.081Z",
                            "agente_nombre": "srv-web"}],
  "total_relacionadas": 73,
  "prioridad": {"nivel": "Alta", "motivos": ["..."], "nivel_alerta": "Medio",
                "importancia": "Alta", "corroborada": true},
  "decisiones": [{"decision": "escalar", "justificacion": "...",
                  "prioridad_considerada": "Alta", "analista": "analista-01",
                  "registrada_en": "..."}]
}
```
`evidencia[].valor` es `"dato no disponible"` cuando la alerta no traía ese dato y
`procedencia` es `null`. `evidencia[].obtenida_en` (RNF-05) es la hora UTC, ISO 8601, en
que SARA leyó la alerta del índice (fin del paso `P1_lectura_alerta`); la llevan todos
los datos, también los «no disponibles». Es `null` solo si el caso no pasó por P1 (no
ocurre con casos creados por el flujo). `decisiones` va de la más antigua a la más reciente.

`alertas_relacionadas`: alertas que comparten IP de origen o agente con la del caso en
±1 h (sin la propia). Se guardan al investigar y se releen tal como se guardaron: hasta
**50**, ordenadas por `marca_tiempo` ascendente. `total_relacionadas` es el total real
(puede ser mayor que 50). Si la búsqueda de relacionadas falló, la lista está vacía y el
paso `P4_alertas_relacionadas` aparece como `fallido`.

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

Columnas: `id`, `numero_caso`, `tipo_alerta`, `procedimiento`, `t0`, `t1`, `minutos_hasta_decision`,
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
| 504 | `tiempo_agotado` | «La investigación superó el tiempo máximo. No se creó el caso.» |

Ningún error incluye trazas, rutas de archivos, consultas SQL, URLs internas ni
credenciales.

## Cobertura del perfil

Contraste hecho por el autor el 25-nov-2026. El texto de los requisitos está en el perfil
(Project «sara»), no en el repositorio: la columna «Tema» resume solo lo que el
repositorio ya registraba de cada uno (etiquetas de las pruebas de la fase 0).

| Requisito / pantalla | Tema | Endpoint | Campos |
|---|---|---|---|
| RF-09 | Prioridad sugerida (matriz de la Tabla 3.5) | `GET /casos/{id}`, `GET /casos` | `prioridad.nivel`, `prioridad.nivel_alerta`, `prioridad.importancia`, `prioridad.motivos`; en la lista, `prioridad_sugerida` y el filtro `prioridad` |
| RF-10 | Prioridad: alertas relacionadas que corroboran; «Información insuficiente» si falta el nivel o el activo no está catalogado | `GET /casos/{id}` | `prioridad.corroborada`, `alertas_relacionadas[]` (id, regla, nivel, marca de tiempo, agente), `total_relacionadas`, `prioridad.motivos` |
| RF-11 | Decisión del analista con justificación obligatoria y analista | `POST /casos/{id}/decision`, `GET /casos/{id}` | `decision`, `justificacion`, `prioridad_considerada`, `analista`; `decisiones[]` con `registrada_en` |
| RF-12 | **[PENDIENTE — autor]:** no hay referencia a RF-12 en el repositorio; completar desde el perfil | — | — |
| RF-13 | Tiempos de la decisión y completitud | `GET /casos/{id}`, `GET /exportacion` | `t0`, `t1` (primera decisión, no cambia), `minutos_hasta_decision`, `completitud` |
| RF-14 | Exportación para la evaluación comparativa | `GET /exportacion` (`formato=json` o `csv`) | `id`, `numero_caso`, `tipo_alerta`, `procedimiento`, `t0`, `t1`, `minutos_hasta_decision`, `prioridad_sugerida`, `decision` y `prioridad_considerada` de la **primera** decisión, `completitud` |
| RNF-05 | Procedencia y hora de cada dato | `GET /casos/{id}` | `evidencia[].procedencia`, `evidencia[].obtenida_en`; `pasos[].fuente`, `pasos[].procedencia`, `pasos[].inicio`, `pasos[].fin` |
| Tabla 4.18 — Lista de casos | | `GET /casos` | `numero_caso`, `tipo_alerta`, `regla_id`, `regla_nivel`, `agente_nombre`, `prioridad_sugerida`, `tiene_decision`, `decision`, `t0`, `t1`; paginación y filtros `prioridad`, `con_decision` |
| Tabla 4.18 — Expediente | | `GET /casos/{id}` | `numero_caso`, `alerta`, `evidencia`, `indicadores`, `pasos`, `alertas_relacionadas`, `total_relacionadas`, `prioridad`, `decisiones` |
| Tabla 4.18 — Registro de decisión | | `POST /casos/{id}/decision` | cuerpo con `decision`, `justificacion`, `prioridad_considerada`, `analista`; 201 con el expediente, 409 si es idéntica a la última, 422 si falta algo |

Solo dos rutas escriben (`POST /investigaciones` y `POST /casos/{id}/decision`); la
ingesta de alertas nuevas es un comando aparte (`python -m sara.interfaces.ingesta
--una-vez`), no una ruta de la API.


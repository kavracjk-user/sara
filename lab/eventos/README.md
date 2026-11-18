# Eventos sintéticos — guion de 12 pares

Genera, **solo dentro del laboratorio**, los 24 casos del guion de
[docs/anexo-c-guion-casos.md](../../docs/anexo-c-guion-casos.md) (propuesta pendiente
del tutor). Solo biblioteca estándar de Python.

> **Estado (2026-11-18):** los 24 casos se ejecutaron una vez en el laboratorio
> (Wazuh 4.14.10) y sus alertas se capturaron con el usuario de solo consulta. 22 de 24
> disparan todas las reglas esperadas; en el par 2 no aparece 5715 (ver «Limitaciones
> observadas»). Las alertas y los archivos de esa corrida **no se han limpiado**.

## Uso

Desde la raíz del repositorio, con el laboratorio levantado (`lab/wazuh/README.md`):

```
python lab/eventos/sara_eventos.py listar
python lab/eventos/sara_eventos.py --simular ejecutar 06A    # muestra, no ejecuta
python lab/eventos/sara_eventos.py ejecutar 01A
python lab/eventos/sara_eventos.py limpiar 01A
python lab/eventos/sara_eventos.py ejecutar todos            # ~25 min por las pausas
python lab/eventos/sara_eventos.py limpiar todos
```

Cada ejecución o limpieza deja un manifiesto en `lab/corridas/` (fuera de Git) con
caso, agente, id de agente, horas UTC de inicio y fin y las reglas esperadas (hipótesis).
Con esa franja se capturan después las alertas para comparar con `MAPA_CAMPOS`.

## Cómo se produce cada tipo

| Pares | Tipo | Mecanismo | Reglas esperadas (hipótesis) |
|---|---|---|---|
| 1–4 | Autenticación | Líneas con formato `sshd` en `/var/log/lab/auth.log` del agente | 5760, 5763, 5715, 40112 |
| 5–8 | Cambio de archivos | Cambios reales a archivos del contenedor; respaldo previo en `/lab/respaldo` | 550, 554, 553 |
| 9, 11, 12 | Actividad de red | Alertas **sintéticas** con formato Suricata en `/var/log/lab/eve.json` | 86601 |
| 10 | Actividad de red | Líneas **sintéticas** de descarte del cortafuegos en `/var/log/lab/red.log` | 4151 |

Las reglas salen del conjunto oficial de Wazuh v4.14.10. Antes de correr los pares se
comprueban con `wazuh-logtest`, que solo evalúa líneas en el servidor y no escribe nada:

```
python lab/eventos/verificar_logtest.py          # devuelve 1 si algún caso difiere
```

Si la regla real no coincide, se corrige `casos.py` **antes** del piloto, no después de
ver los resultados.

### Resultado de wazuh-logtest (4.14.10, 2026-11-18)

| Casos | Decodificador | Alertas por caso (regla × veces, nivel) |
|---|---|---|
| 01A/B | `sshd` | 5760 × 9 (5), 5763 × 1 (10) |
| 02A/B | `sshd` | 5760 × 9 (5), 5763 × 1 (10), 40112 × 1 (12); **5715 no aparece** |
| 03A/B | `sshd` | 5760 × 1 (5) |
| 04A/B | `sshd` | 5760 × 14 (5), 5763 × 1 (10) |
| 09A/B, 11A/B, 12A/B | `json` | 86601 (3) por cada línea: 5, 3 y 1 |
| 10A/B | `kernel` + `sshd` | 4101 × 21 (5), 4151 × 1 (10), 5760 × 6 (5) |
| 05–08 | — | No aplica a logtest (eventos del FIM del agente). **Confirmados en la corrida real**: 550, 554 y 553 (ver tabla de la corrida). |

Correcciones y observaciones:
- **Par 2:** se esperaba también 5715; el acceso correcto sale como **40112**. La
  hipótesis NO se ajusta (decisión del autor): ver «Limitaciones observadas».
- **Par 10:** 4101 tiene `no_log` en la regla; logtest la muestra como alerta, pero en
  la corrida real **no llegó ninguna 4101 al índice** (0 de 22 por caso). Solo se
  indexa 4151.
- **Campos (para `MAPA_CAMPOS`, objetivo 5):** en las alertas tipo Suricata la IP llega
  como `src_ip`/`dest_ip`; en `sshd` y `kernel`, como `srcip`/`dstip`.
- Logtest no reproduce el orden ni el tiempo reales entre agentes: los conteos de la
  corrida real pueden diferir.

## Corrida real (2026-11-18, 05:00–05:13 UTC)

`python lab/eventos/sara_eventos.py ejecutar todos` y luego
`python lab/eventos/capturar_alertas.py` (usuario `sara_lector`, solo lectura). Alertas
crudas en `lab/capturas/crudas/` (fuera de Git). Ventana de cada caso: desde su inicio
hasta el inicio del caso siguiente.

| Par | Esperadas (hipótesis) | Disparadas en A | Disparadas en B | ¿Coincide? |
|---|---|---|---|---|
| 1 | 5760, 5763 | srv-web: 5760 × 9, 5763 | srv-bd: 5760 × 9, 5763 | Sí |
| 2 | 5760, 5763, 5715, 40112 | srv-web: 5760 × 9, 5763, 40112 | srv-bd: 5760 × 9, 5763, 40112 | **No: falta 5715** |
| 3 | 5760 | pc-lab-01: 5760 | pc-lab-01: 5760 | Sí |
| 4 | 5760, 5763 | pc-analista: 5760 × 9, 5763; srv-web y pc-lab-01: 5760 × 3 | igual que A | Sí |
| 5 | 550 | srv-web: 550 `/etc/passwd` | srv-bd: 550 `/etc/shadow` | Sí |
| 6 | 554 | pc-lab-01: 554 `/tmp/prueba_a.com` | pc-analista: 554 `/tmp/prueba_b.com` | Sí |
| 7 | 550 | srv-web: 550 `nginx.conf` | srv-bd: 550 `pg_hba.conf` | Sí |
| 8 | 553 | srv-web: 553 `/var/log/auth.log` | srv-bd: 553 `/var/log/syslog` | Sí |
| 9 | 86601 | srv-web: 86601 × 5 | srv-bd: 86601 × 5 | Sí |
| 10 | 4151, 5760 | srv-bd: 4151; srv-web y pc-lab-01: 5760 × 3 | srv-web: 4151; srv-bd y pc-lab-01: 5760 × 3 | Sí |
| 11 | 86601 | pc-lab-01: 86601 × 3 | pc-analista: 86601 × 3 | Sí |
| 12 | 86601 | pc-nuevo (099): 86601 | pc-nuevo (099): 86601 | Sí |

Otras observaciones de la corrida:
- Ninguna alerta 4101 llegó al índice (la regla tiene `no_log`): en el par 10 solo se
  indexa 4151. Confirmado, no supuesto.
- Las escrituras en `/var/log/lab/` no generaron alertas de integridad: `restrict`
  limita el FIM a las rutas del guion.
- Campos reales: Suricata → `data.src_ip`/`data.dest_ip`; `sshd` y `kernel` →
  `data.srcip`/`data.dstip`; FIM → `syscheck.path`, `syscheck.event`, `syscheck.sha256_after`.

## Limitaciones observadas

| Caso | Regla esperada | Regla real | Causa probable |
|---|---|---|---|
| 02A, 02B | 5715 (acceso correcto) | ninguna 5715; el acceso correcto produce **40112** (nivel 12) | Wazuh genera una sola alerta por evento: para la línea `Accepted password`, la regla hija 40112 (`if_group authentication_success` + `if_matched_group authentication_failures`, misma IP, 240 s) coincide y reemplaza a 5715. Comprobado igual con `wazuh-logtest` y en el índice. |

Decisión del autor (2026-11-18): si un caso no dispara la regla esperada, **no** se
adapta el caso, el Anexo C ni la pauta; se registra aquí. Solo se corrigen errores de
implementación del script (p. ej. una línea mal formada) y se repite solo ese caso. En
esta corrida no hubo errores de implementación: ningún caso se modificó ni se repitió.

## Límites que hay que declarar

- **Actividad de red sin tráfico.** En los pares 9 a 12 no hay sensor ni paquetes: la
  firma, la categoría y el nivel los escribimos nosotros. Lo que se evalúa es cómo SARA
  investiga esa alerta, no la detección.
- **Pares 5 y 7.** Wazuh produce para ambos el mismo tipo de alerta (archivo
  modificado). «Fuera de la ventana de mantenimiento» frente a «cambio planificado» no
  viene de Wazuh. **[PENDIENTE — autor y tutor]:** de dónde obtiene SARA el calendario
  de cambios. Los scripts solo producen el cambio de archivo.
- **Par 6.** Sin VirusTotal ni ClamAV, Wazuh solo ve «archivo creado» con su hash; no
  sabe que es EICAR. En Windows, el antivirus bloquea el archivo si se crea fuera del
  contenedor (pasó en el ensayo local). Dentro del contenedor **no** lo bloqueó: en la
  corrida real el archivo se creó (68 bytes), sigue ahí y generó la alerta 554.
- **La limpieza no borra alertas.** Deshace los cambios en los contenedores; las
  alertas indexadas quedan (solo lectura y evidencia). Restaurar archivos en los pares
  5, 7 y 8 genera alertas propias; su franja está en el manifiesto `limpiar`.
- **La limpieza también genera alertas** (comprobado el 2026-11-18): restaurar
  `passwd`, `shadow`, `nginx.conf` y `pg_hba.conf` da 550 × 4; recrear `auth.log` y
  `syslog`, 554 × 2; borrar los archivos de `/tmp`, 553 × 2; y vaciar los registros de
  `/var/log/lab/`, **592** («Log file size reduced», nivel 8) × 11. Quedan en el índice
  después de la franja de la corrida; al capturar, usa los manifiestos `ejecutar`.
- **Verificación de la limpieza (2026-11-18):** tras `limpiar todos`, en los cinco
  agentes los 6 archivos del guion tienen el mismo sha256 que su respaldo, los registros
  de `/var/log/lab/` están vacíos y no queda nada en `/tmp/prueba_*.com`. Se compara el
  contenido: la fecha de modificación cambia y los archivos recreados (par 8) tienen
  otro inodo.
- **Pausas.** Entre casos se espera 10, 70 o 250 s para que las reglas de frecuencia
  (`ignore` de 5763 y 4151, ventana de 40112) puedan volver a dispararse.
  `--sin-pausa` las omite, con el riesgo de que no salgan.

## Datos

IP externas solo de documentación (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); IP
internas de la red del laboratorio 10.10.0.0/24 (.21 y .22 son equipos de usuario del
par 3, dato superficial). Dominios `.test`. Usuarios ficticios: `operador`, `ana.lab`,
`luis.lab`. Las pruebas de `lab/tests/test_eventos.py` hacen cumplir todo esto.

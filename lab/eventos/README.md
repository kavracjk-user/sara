# Eventos sintéticos — guion de 12 pares

Genera, **solo dentro del laboratorio**, los 24 casos del guion de
[docs/anexo-c-guion-casos.md](../../docs/anexo-c-guion-casos.md) (propuesta pendiente
del tutor). Solo biblioteca estándar de Python.

> **Estado:** las pruebas sin Docker pasan (`cd lab && python -m pytest -q`) y un ensayo
> local con `sh` confirmó que cada caso cambia solo sus contenedores y que la limpieza
> los deja como estaban. **Nunca se ha ejecutado contra Wazuh**: no sabemos todavía
> qué alertas produce cada caso.

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

Las reglas salen del conjunto oficial de Wazuh v4.14.10. Antes de correr los pares hay
que pasar una línea de cada tipo por `wazuh-logtest` dentro del servidor:

```
docker compose --env-file .env -f lab/wazuh/docker-compose.yml exec wazuh.manager /var/ossec/bin/wazuh-logtest
```

Si la regla real no coincide, se corrige `casos.py` **antes** del piloto, no después de
ver los resultados.

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
  contenedor (pasó en el ensayo local); dentro de WSL 2 no debería, pero está sin probar.
- **La limpieza no borra alertas.** Deshace los cambios en los contenedores; las
  alertas indexadas quedan (solo lectura y evidencia). Restaurar archivos en los pares
  5, 7 y 8 genera alertas propias; su franja está en el manifiesto `limpiar`.
- **Pausas.** Entre casos se espera 10, 70 o 250 s para que las reglas de frecuencia
  (`ignore` de 5763 y 4151, ventana de 40112) puedan volver a dispararse.
  `--sin-pausa` las omite, con el riesgo de que no salgan.

## Datos

IP externas solo de documentación (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); IP
internas de la red del laboratorio 10.10.0.0/24 (.21 y .22 son equipos de usuario del
par 3, dato superficial). Dominios `.test`. Usuarios ficticios: `operador`, `ana.lab`,
`luis.lab`. Las pruebas de `lab/tests/test_eventos.py` hacen cumplir todo esto.

# Anexo C — Catálogo de activos y guion de 12 pares de casos

> **Estado: PROPUESTA pendiente de aprobación del tutor.** Se usa para preparar el
> laboratorio, pero no es definitiva. Copia de lo entregado por el autor el 2026-11-16.

## Catálogo de activos

| Id. agente | Nombre      | Función                       | Importancia   |
|------------|-------------|-------------------------------|---------------|
| 001        | srv-web     | Servidor web de pruebas       | Alta          |
| 002        | srv-bd      | Base de datos de pruebas      | Alta          |
| 003        | pc-analista | Equipo del analista           | Media         |
| 004        | pc-lab-01   | Equipo de laboratorio general | Baja          |
| 099        | pc-nuevo    | NO se registra en el catálogo | No catalogado |

## Datos sintéticos

- IP «externas»: rangos de documentación 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
- Dominios: TLD `.test`.
- Usuarios ficticios.

## Guion

Cada par tiene un caso A y un caso B de dificultad semejante; solo cambian datos
superficiales.

| # | Tipo | Situación | Caso A | Caso B |
|---|------|-----------|--------|--------|
| 1 | Autenticación | Fallos SSH repetidos desde IP externa, SIN acceso correcto posterior | srv-web, IP 203.0.113.10 | srv-bd, IP 198.51.100.20 |
| 2 | Autenticación | Fallos repetidos SEGUIDOS de un acceso correcto, misma IP externa | srv-web, IP 203.0.113.11 | srv-bd, IP 198.51.100.21 |
| 3 | Autenticación | Un único fallo de un usuario legítimo, sin repetición | pc-lab-01, usuario ana.lab | pc-lab-01, usuario luis.lab |
| 4 | Autenticación | Fallos repetidos desde IP interna, con alertas relacionadas en otros 2 equipos | pc-analista, IP interna .31 | pc-analista, IP interna .32 |
| 5 | Cambio de archivos | Modificación de archivo sensible fuera de la ventana de mantenimiento | srv-web, /etc/passwd | srv-bd, /etc/shadow |
| 6 | Cambio de archivos | Creación de archivo de prueba antivirus (cadena EICAR, inofensiva) en directorio temporal | pc-lab-01, /tmp/prueba_a.com | pc-analista, /tmp/prueba_b.com |
| 7 | Cambio de archivos | Modificación esperada de configuración durante un cambio planificado | srv-web, /etc/nginx/nginx.conf | srv-bd, /etc/postgresql/pg_hba.conf |
| 8 | Cambio de archivos | Eliminación de un archivo de registro del sistema | srv-web, /var/log/auth.log | srv-bd, /var/log/syslog |
| 9 | Actividad de red | Conexiones salientes repetidas a IP y puerto no habituales | srv-web -> 203.0.113.50:4444 | srv-bd -> 198.51.100.60:4444 |
| 10 | Actividad de red | Barrido de varios puertos desde IP interna hacia un servidor, con alertas relacionadas | origen .41 -> srv-bd | origen .42 -> srv-web |
| 11 | Actividad de red | Consultas a un dominio de prueba controlado | pc-lab-01, servicio-a.test | pc-analista, servicio-b.test |
| 12 | Actividad de red | Alerta de red sobre un equipo NO catalogado (agente 099) | pc-nuevo, destino 203.0.113.70 | pc-nuevo, destino 198.51.100.80 |

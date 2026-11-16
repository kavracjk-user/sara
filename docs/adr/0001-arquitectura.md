# ADR 0001 — Arquitectura: puertos y adaptadores con Docker Compose

Estado: **propuesta, pendiente de aprobación del Product Owner**. Fecha: 2026-11-16.

## Contexto
SARA integra Wazuh, PostgreSQL, Prefect y una interfaz web, y puede sumar FortiSIEM y
proveedores externos. La evaluación exige que la lógica de prioridad y de estados se
pueda probar y auditar sin depender de esos servicios.

## Decisión
- Núcleo (`dominio`, `aplicacion`) sin dependencias de infraestructura; los servicios
  externos entran por `puertos` y se implementan en `adaptadores`.
- El normalizador es propio de cada fuente y se **inyecta** en el caso de uso.
- Laboratorio completo en Docker Compose.
- Interfaz del analista en React como cliente delgado de la API FastAPI (3 pantallas de
  la Tabla 4.18).

## Consecuencias
- (+) Las reglas se prueban sin Wazuh ni base de datos; agregar fuentes o proveedores no
  toca el núcleo; `test_arquitectura.py` lo hace cumplir.
- (−) Más archivos y una capa de indirección para un proyecto individual.
- **Cambio de alcance:** React sustituye a «FastAPI + plantillas HTML» (perfil 2.3.4 y
  Tabla 2.5). Debe aprobarlo el Product Owner y registrarse (sección 4.1.2) antes de la
  fase 5. Plan B: plantillas servidas por FastAPI sin tocar el núcleo.

## Pendiente
Proveedor externo de inteligencia de amenazas: se decide más adelante; solo existe el
puerto `ProveedorContexto`.

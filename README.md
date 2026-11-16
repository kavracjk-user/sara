# SARA

Sistema de Automatización de Respuesta a Amenazas para apoyar la investigación inicial
de alertas de seguridad en un laboratorio SOC (proyecto de grado, Ingeniería de Sistemas,
FCyT). SARA **no ejecuta contención**: reúne evidencia, sugiere una prioridad con motivos
y deja la decisión al analista.

| Carpeta | Contenido |
|---|---|
| `backend/` | Núcleo, adaptadores, API y flujos (Python). Ver `backend/README.md` |
| `frontend/` | Interfaz del analista (React). Aún sin iniciar |
| `lab/` | Alertas de prueba y scripts del laboratorio (fase 1) |
| `evaluacion/` | Pauta, hojas de medición y matriz. Se congelan antes del piloto |
| `docs/` | Decisiones de arquitectura (ADR) |

Instrucciones de trabajo para Claude: `CLAUDE.md`.

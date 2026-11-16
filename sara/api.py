"""Interfaz local del analista (Tabla 4.18). NO PROBADA en esta sesión:
requiere `pip install fastapi uvicorn jinja2 python-multipart`.

Ejecutar:  uvicorn sara.api:app --reload
Persistencia: aquí se usa un almacén en memoria como marcador; en el Sprint 6 se
reemplaza por PostgreSQL (sql/schema.sql) con credenciales de entorno.
"""
from __future__ import annotations

from fastapi import FastAPI, Form, HTTPException

from .models import Caso, Nivel
from .pipeline import minutos_hasta_decision, registrar_decision

app = FastAPI(title="SARA - interfaz del analista")
CASOS: dict[str, Caso] = {}  # marcador: reemplazar por PostgreSQL


def _resumen(c: Caso) -> dict:
    p = c.prioridad
    return {
        "id_alerta": c.vista.id_alerta,
        "tipo_alerta": c.vista.tipo_alerta.value,
        "prioridad_sugerida": p.nivel.value if p else None,
        "motivos": p.motivos if p else [],
        "pasos": [{"paso": s.paso, "estado": s.estado.value, "error": s.error,
                   "fuente": s.fuente} for s in c.pasos],
        "decision": c.decision,
        "minutos_hasta_decision": minutos_hasta_decision(c),
    }


@app.get("/casos")
def lista_de_casos() -> list[dict]:
    return [_resumen(c) for c in CASOS.values()]


@app.get("/casos/{id_alerta}")
def expediente(id_alerta: str) -> dict:
    if id_alerta not in CASOS:
        raise HTTPException(404, "Caso no encontrado")
    return _resumen(CASOS[id_alerta])


@app.post("/casos/{id_alerta}/decision")
def decidir(id_alerta: str, decision: str = Form(...), justificacion: str = Form(...),
            prioridad_considerada: str = Form(...)) -> dict:
    if id_alerta not in CASOS:
        raise HTTPException(404, "Caso no encontrado")
    try:
        registrar_decision(CASOS[id_alerta], decision, justificacion, Nivel(prioridad_considerada))
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    return _resumen(CASOS[id_alerta])

"""API del analista (fase 4). Contrato: docs/api.md; OpenAPI: docs/api/openapi.json.

Esta capa solo traduce HTTP <-> casos de uso (sara.aplicacion.casos). No crea
adaptadores: los recibe ya armados desde el punto de composición
(sara.interfaces.composicion). Lo único que puede escribir es lo que escribe el caso
de uso: casos (por la investigación) y decisiones. Wazuh es solo lectura (RNF-02) y
no hay ninguna ruta de contención (RNF-01).

Errores: siempre {"error": {"codigo", "mensaje", "detalles"}} en español, sin trazas,
rutas, consultas ni credenciales.
"""
from __future__ import annotations

import csv
import hmac
import io
import logging
from dataclasses import dataclass, field
from typing import Callable, Literal, Optional

from fastapi import Depends, FastAPI, Header, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from sara.aplicacion.casos import (AlertaNoEncontrada, CasoNoEncontrado, Conflicto,
                                   DatosInvalidos, DependenciaNoDisponible, Expediente,
                                   ServicioCasos)
from sara.dominio.models import Nivel

log = logging.getLogger("sara.api")

PATRON_ID = r"^[A-Za-z0-9_-]{1,64}$"
ORIGEN_CORS_POR_DEFECTO = "http://localhost:5173"
DATO_NO_DISPONIBLE = "dato no disponible"
COLUMNAS_EXPORTACION = ("id", "numero_caso", "tipo_alerta", "procedimiento", "t0", "t1",
                        "minutos_hasta_decision", "prioridad_sugerida", "decision",
                        "prioridad_considerada", "completitud")


@dataclass
class ConfiguracionAPI:
    servicio: ServicioCasos
    clave_api: Optional[str]
    salud: dict[str, Callable[[], bool]] = field(default_factory=dict)
    origen_cors: str = ORIGEN_CORS_POR_DEFECTO
    ocultar: Callable[[str], str] = lambda texto: texto


# ---------- modelos (OpenAPI) ----------
class SolicitudInvestigacion(BaseModel):
    id_alerta: str = Field(pattern=PATRON_ID, description="_id de la alerta en el índice")


class SolicitudDecision(BaseModel):
    decision: Literal["escalar", "descartar", "solicitar_mas_informacion"]
    justificacion: str = Field(max_length=2000, description="Obligatoria, no vacía")
    prioridad_considerada: Literal["Alta", "Media", "Baja", "Información insuficiente"]
    analista: str = Field(max_length=100, description="Seudónimo en el piloto (RNF-03)")


class Alerta(BaseModel):
    tipo_alerta: str
    marca_tiempo: Optional[str]
    regla_id: Optional[str]
    regla_nivel: Optional[int]
    regla_descripcion: Optional[str]
    agente_id: Optional[str]
    agente_nombre: Optional[str]
    ip_origen: Optional[str]
    ip_destino: Optional[str]
    usuario: Optional[str]
    dominio: Optional[str]
    archivo_ruta: Optional[str]
    archivo_hash: Optional[str]
    evento: Optional[str]
    campos_ausentes: list[str]


class DatoEvidencia(BaseModel):
    dato: str
    valor: object
    procedencia: Optional[str] = Field(description="Campo de la alerta de donde salió")
    obtenida_en: Optional[str] = Field(
        description="Hora UTC (ISO 8601) en que SARA leyó la alerta (fin de P1, RNF-05)")


class IndicadorSalida(BaseModel):
    tipo: str
    valor: str
    origen_campo: str


class PasoSalida(BaseModel):
    paso: str
    estado: Literal["con_resultado", "sin_resultado", "fallido", "no_aplicable"]
    inicio: str
    fin: str
    reintentos: int
    fuente: Optional[str]
    procedencia: Optional[str]
    error: Optional[str]


class PrioridadSalida(BaseModel):
    nivel: str
    motivos: list[str]
    nivel_alerta: Optional[str]
    importancia: Optional[str]
    corroborada: bool


class DecisionSalida(BaseModel):
    decision: str
    justificacion: str
    prioridad_considerada: str
    analista: Optional[str]
    registrada_en: str


class RelacionadaSalida(BaseModel):
    id: str = Field(description="_id de la alerta en el índice")
    regla_id: Optional[str]
    regla_descripcion: Optional[str]
    regla_nivel: Optional[int]
    marca_tiempo: Optional[str]
    agente_nombre: Optional[str]


class ExpedienteSalida(BaseModel):
    id: str = Field(description="_id de la alerta en el índice (se usa en las URL)")
    numero_caso: Optional[str] = Field(description="Número legible, p. ej. C-0007")
    t0: str
    t1: Optional[str]
    minutos_hasta_decision: Optional[float]
    alerta: Alerta
    evidencia: list[DatoEvidencia]
    indicadores: list[IndicadorSalida]
    pasos: list[PasoSalida]
    alertas_relacionadas: list[RelacionadaSalida] = Field(
        description="Hasta 50, ordenadas por marca de tiempo")
    total_relacionadas: int = Field(description="Total real (puede ser mayor que 50)")
    prioridad: Optional[PrioridadSalida]
    decisiones: list[DecisionSalida]


class ResumenCaso(BaseModel):
    id: str
    numero_caso: Optional[str]
    tipo_alerta: str
    regla_id: Optional[str]
    regla_nivel: Optional[int]
    agente_id: Optional[str]
    agente_nombre: Optional[str]
    prioridad_sugerida: Optional[str]
    tiene_decision: bool
    decision: Optional[str]
    t0: str
    t1: Optional[str]


class ListaCasos(BaseModel):
    pagina: int
    tamano: int
    total: int
    casos: list[ResumenCaso]


class Salud(BaseModel):
    estado: Literal["ok", "degradado"]
    dependencias: dict[str, Literal["disponible", "no disponible"]]


class FilaExportacion(BaseModel):
    id: str
    numero_caso: Optional[str]
    tipo_alerta: str
    procedimiento: Optional[str]
    t0: str
    t1: Optional[str]
    minutos_hasta_decision: Optional[float]
    prioridad_sugerida: Optional[str]
    decision: Optional[str]
    prioridad_considerada: Optional[str]
    completitud: float


class Exportacion(BaseModel):
    casos: list[FilaExportacion]


class DetalleError(BaseModel):
    campo: str
    problema: str


class CuerpoError(BaseModel):
    codigo: str
    mensaje: str
    detalles: list[DetalleError] = []


class RespuestaError(BaseModel):
    error: CuerpoError


_ERRORES = {c: {"model": RespuestaError} for c in (400, 401, 404, 409, 422, 500, 503)}


# ---------- errores ----------
class _ErrorAPI(Exception):
    def __init__(self, estado: int, codigo: str, mensaje: str,
                 detalles: Optional[list[dict]] = None) -> None:
        self.estado, self.codigo, self.mensaje = estado, codigo, mensaje
        self.detalles = detalles or []


def _error(estado: int, codigo: str, mensaje: str,
           detalles: Optional[list[dict]] = None) -> JSONResponse:
    return JSONResponse(status_code=estado, content={
        "error": {"codigo": codigo, "mensaje": mensaje, "detalles": detalles or []}})


_PROBLEMAS = {
    "missing": "falta este dato", "string_pattern_mismatch": "formato no válido",
    "literal_error": "valor no permitido", "string_too_long": "demasiado largo",
    "greater_than_equal": "fuera de rango", "less_than_equal": "fuera de rango",
    "bool_parsing": "debe ser true o false", "int_parsing": "debe ser un número entero",
    "json_invalid": "JSON mal formado", "string_type": "debe ser texto",
    "model_attributes_type": "debe ser un objeto JSON", "enum": "valor no permitido",
}


def _detalles_validacion(exc: RequestValidationError) -> list[dict]:
    """Ubicación y tipo de problema; nunca se repite el valor enviado."""
    salida = []
    for e in exc.errors():
        partes = [str(p) for p in e.get("loc", ()) if p not in ("body", "path", "query", "header")]
        salida.append({"campo": ".".join(partes) or "cuerpo",
                       "problema": _PROBLEMAS.get(e.get("type", ""), "valor no válido")})
    return salida


# ---------- aplicación ----------
def crear_app(cfg: ConfiguracionAPI) -> FastAPI:
    app = FastAPI(
        title="SARA — API del analista",
        version="0.4.0",
        description=("Apoyo a la investigación inicial de alertas. Solo lectura sobre Wazuh; "
                     "sin contención. La decisión es siempre del analista."),
        responses=_ERRORES,
    )
    app.add_middleware(CORSMiddleware, allow_origins=[cfg.origen_cors],
                       allow_methods=["GET", "POST"],
                       allow_headers=["X-API-Key", "Content-Type"])

    @app.exception_handler(_ErrorAPI)
    async def _manejar_error_api(_r: Request, e: _ErrorAPI):
        return _error(e.estado, e.codigo, e.mensaje, e.detalles)

    @app.exception_handler(RequestValidationError)
    async def _manejar_validacion(_r: Request, e: RequestValidationError):
        return _error(422, "datos_invalidos", "Los datos enviados no son válidos.",
                      _detalles_validacion(e))

    @app.exception_handler(StarletteHTTPException)
    async def _manejar_http(_r: Request, e: StarletteHTTPException):
        if e.status_code == 404:
            return _error(404, "no_encontrado", "La ruta no existe.")
        if e.status_code == 405:
            return _error(400, "peticion_invalida", "Método no permitido en esta ruta.")
        return _error(400, "peticion_invalida", "La petición no es válida.")

    @app.exception_handler(Exception)
    async def _manejar_interno(_r: Request, e: Exception):
        log.error("Error interno: %s", type(e).__name__)   # sin mensaje: puede llevar datos
        return _error(500, "error_interno",
                      "Error interno. El detalle quedó en el registro del servidor.")

    def exigir_clave(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")) -> None:
        if not cfg.clave_api:
            raise _ErrorAPI(503, "servicio_no_disponible", "La API no tiene clave configurada.")
        if not x_api_key or not hmac.compare_digest(x_api_key.encode(), cfg.clave_api.encode()):
            raise _ErrorAPI(401, "no_autorizado", "Falta la clave de API o no es válida.")

    def traducir(e: Exception) -> _ErrorAPI:
        if isinstance(e, (CasoNoEncontrado, AlertaNoEncontrada)):
            return _ErrorAPI(404, "no_encontrado", str(e))
        if isinstance(e, Conflicto):
            return _ErrorAPI(409, "conflicto", str(e))
        if isinstance(e, DatosInvalidos):
            return _ErrorAPI(422, "datos_invalidos", "Los datos enviados no son válidos.",
                             [{"campo": e.campo or "cuerpo", "problema": str(e)}])
        if isinstance(e, DependenciaNoDisponible):
            return _ErrorAPI(503, "servicio_no_disponible", str(e))
        raise e

    def a_salida(exp: Expediente) -> dict:
        c, v = exp.caso, exp.caso.vista
        ev = dict(v.evidencia_minima or {})
        procedencia = ev.pop("procedencia", {}) or {}
        obtenida_en = exp.obtenida_en.isoformat() if exp.obtenida_en else None
        return {
            "id": v.id_alerta, "numero_caso": exp.numero_caso, "t0": c.t0.isoformat(),
            "t1": c.t1.isoformat() if c.t1 else None,
            "minutos_hasta_decision": exp.minutos_hasta_decision,
            "alerta": {"tipo_alerta": v.tipo_alerta.value, "marca_tiempo": v.marca_tiempo,
                       "regla_id": v.regla_id, "regla_nivel": v.regla_nivel,
                       "regla_descripcion": v.regla_descripcion, "agente_id": v.agente_id,
                       "agente_nombre": v.agente_nombre, "ip_origen": v.ip_origen,
                       "ip_destino": v.ip_destino, "usuario": v.usuario, "dominio": v.dominio,
                       "archivo_ruta": v.archivo_ruta, "archivo_hash": v.archivo_hash,
                       "evento": v.evento, "campos_ausentes": list(v.campos_ausentes)},
            "evidencia": [{"dato": k, "valor": DATO_NO_DISPONIBLE if val in (None, "") else val,
                           "procedencia": procedencia.get(k), "obtenida_en": obtenida_en}
                          for k, val in ev.items()],
            "indicadores": [{"tipo": i.tipo.value, "valor": i.valor,
                             "origen_campo": i.origen_campo} for i in c.indicadores],
            "pasos": [{"paso": p.paso, "estado": p.estado.value,
                       "inicio": p.inicio.isoformat(), "fin": p.fin.isoformat(),
                       "reintentos": p.reintentos, "fuente": p.fuente,
                       "procedencia": p.procedencia,
                       "error": cfg.ocultar(p.error) if p.error else None} for p in c.pasos],
            "alertas_relacionadas": [{
                "id": a.id, "regla_id": a.regla_id, "regla_descripcion": a.regla_descripcion,
                "regla_nivel": a.regla_nivel, "marca_tiempo": a.marca_tiempo,
                "agente_nombre": a.agente_nombre} for a in exp.relacionadas.alertas],
            "total_relacionadas": exp.relacionadas.total,
            "prioridad": None if c.prioridad is None else {
                "nivel": c.prioridad.nivel.value, "motivos": list(c.prioridad.motivos),
                "nivel_alerta": c.prioridad.nivel_alerta.value if c.prioridad.nivel_alerta else None,
                "importancia": c.prioridad.importancia.value if c.prioridad.importancia else None,
                "corroborada": c.prioridad.corroborada},
            "decisiones": [{"decision": d.decision, "justificacion": d.justificacion,
                            "prioridad_considerada": d.prioridad_considerada.value,
                            "analista": d.analista,
                            "registrada_en": d.registrada_en.isoformat()}
                           for d in exp.decisiones],
        }

    protegido = [Depends(exigir_clave)]
    IdCaso = Path(pattern=PATRON_ID, description="_id de la alerta en el índice de Wazuh")

    @app.get("/salud", response_model=Salud, dependencies=protegido, tags=["sistema"])
    def salud() -> dict:
        estados = {}
        for nombre, comprobar in cfg.salud.items():
            try:
                ok = bool(comprobar())
            except Exception:
                ok = False
            estados[nombre] = "disponible" if ok else "no disponible"
        todo_ok = all(e == "disponible" for e in estados.values())
        return {"estado": "ok" if todo_ok else "degradado", "dependencias": estados}

    @app.post("/investigaciones", response_model=ExpedienteSalida, status_code=201,
              dependencies=protegido, tags=["casos"])
    def investigar(solicitud: SolicitudInvestigacion) -> dict:
        try:
            return a_salida(cfg.servicio.investigar(solicitud.id_alerta))
        except Exception as e:
            raise traducir(e)

    @app.get("/casos", response_model=ListaCasos, dependencies=protegido, tags=["casos"])
    def casos(pagina: int = Query(1, ge=1), tamano: int = Query(20, ge=1, le=100),
              prioridad: Optional[Literal["Alta", "Media", "Baja",
                                          "Información insuficiente"]] = None,
              con_decision: Optional[bool] = None) -> dict:
        try:
            p = cfg.servicio.listar(pagina, tamano, Nivel(prioridad) if prioridad else None,
                                    con_decision)
        except Exception as e:
            raise traducir(e)
        return {"pagina": p.pagina, "tamano": p.tamano, "total": p.total, "casos": [{
            "id": e.caso.vista.id_alerta, "numero_caso": e.numero_caso,
            "tipo_alerta": e.caso.vista.tipo_alerta.value,
            "regla_id": e.caso.vista.regla_id, "regla_nivel": e.caso.vista.regla_nivel,
            "agente_id": e.caso.vista.agente_id, "agente_nombre": e.caso.vista.agente_nombre,
            "prioridad_sugerida": e.caso.prioridad.nivel.value if e.caso.prioridad else None,
            "tiene_decision": bool(e.decisiones),
            "decision": e.decisiones[-1].decision if e.decisiones else None,
            "t0": e.caso.t0.isoformat(),
            "t1": e.caso.t1.isoformat() if e.caso.t1 else None} for e in p.expedientes]}

    @app.get("/casos/{id_caso}", response_model=ExpedienteSalida, dependencies=protegido,
             tags=["casos"])
    def expediente(id_caso: str = IdCaso) -> dict:
        try:
            return a_salida(cfg.servicio.expediente(id_caso))
        except Exception as e:
            raise traducir(e)

    @app.post("/casos/{id_caso}/decision", response_model=ExpedienteSalida, status_code=201,
              dependencies=protegido, tags=["casos"])
    def decidir(solicitud: SolicitudDecision, id_caso: str = IdCaso) -> dict:
        try:
            return a_salida(cfg.servicio.decidir(
                id_caso, solicitud.decision, solicitud.justificacion,
                solicitud.prioridad_considerada, solicitud.analista))
        except Exception as e:
            raise traducir(e)

    @app.get("/exportacion", response_model=Exportacion, dependencies=protegido,
             tags=["evaluación"],
             responses={200: {"content": {"text/csv": {}}}})
    def exportacion(formato: Literal["json", "csv"] = "json"):
        filas = cfg.servicio.exportar()
        if formato == "json":
            return {"casos": filas}
        salida = io.StringIO()
        escritor = csv.DictWriter(salida, fieldnames=COLUMNAS_EXPORTACION, lineterminator="\n")
        escritor.writeheader()
        escritor.writerows(filas)
        return Response(salida.getvalue(), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition":
                                 'attachment; filename="sara_exportacion.csv"'})

    return app

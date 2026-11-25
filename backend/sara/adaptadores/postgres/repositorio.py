"""Puerto RepositorioCasos sobre PostgreSQL (sql/schema.sql).

Guarda el expediente completo de un caso en una sola transacción y lo relee:
vista común, indicadores, pasos con su estado (RNF-07), prioridad sugerida con sus
motivos y decisiones humanas. El caso se identifica por el `_id` del índice de Wazuh.

Reglas:
- `guardar` es idempotente: volver a guardar el mismo caso reemplaza indicadores,
  pasos y prioridad, y solo agrega una decisión si es distinta de la última guardada.
- t1 (primera decisión) nunca se sobrescribe una vez fijado.
- `id_agente` (FK al catálogo) es NULL si el agente no está catalogado; el id que trae
  la alerta se guarda aparte en `agente_id_alerta`.
- Los resultados de los pasos se guardan como JSON plano (serializacion.py).
- procedimiento = 'sara' por defecto (los casos manuales de la línea base no pasan
  por aquí; ver README).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Optional

import psycopg
from psycopg.types.json import Jsonb

from sara.adaptadores.postgres.serializacion import a_json
from sara.puertos import (MAX_RELACIONADAS, AlertasRelacionadas, DecisionRegistrada,
                          ResumenAlerta)
from sara.dominio.models import (Caso, Estado, Importancia, Indicador, Nivel, NivelAlerta,
                                 PrioridadSugerida, RegistroPaso, TipoAlerta,
                                 TipoIndicador, VistaComun)

Conectar = Callable[[], psycopg.Connection]
PASO_RELACIONADAS = "P4_alertas_relacionadas"

_COLUMNAS_VISTA = ("agente_id_alerta", "agente_nombre", "ip_origen", "ip_destino", "usuario",
                   "dominio", "archivo_ruta", "archivo_hash", "evento")


class RepositorioPostgres:
    def __init__(self, conectar: Conectar, procedimiento: str = "sara") -> None:
        if procedimiento not in ("sara", "manual"):
            raise ValueError("procedimiento debe ser 'sara' o 'manual'.")
        self._conectar = conectar
        self.procedimiento_por_defecto = procedimiento

    # ---------- escritura ----------
    def guardar(self, caso: Caso) -> None:
        v = caso.vista
        if not v.id_alerta:
            raise ValueError("El caso no tiene _id de alerta: no se puede guardar.")
        with self._conectar() as con, con.transaction():
            catalogado = v.agente_id and con.execute(
                "SELECT 1 FROM activo WHERE id_agente = %s", (v.agente_id,)).fetchone()
            id_caso = con.execute(
                """
                INSERT INTO caso (id_alerta, tipo_alerta, marca_tiempo, regla_id, regla_nivel,
                    regla_descripcion, id_agente, agente_id_alerta, agente_nombre, ip_origen,
                    ip_destino, usuario, dominio, archivo_ruta, archivo_hash, evento,
                    campos_ausentes, evidencia_minima, procedimiento, t0, t1)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s)
                ON CONFLICT (id_alerta) DO UPDATE SET
                    tipo_alerta = EXCLUDED.tipo_alerta, marca_tiempo = EXCLUDED.marca_tiempo,
                    regla_id = EXCLUDED.regla_id, regla_nivel = EXCLUDED.regla_nivel,
                    regla_descripcion = EXCLUDED.regla_descripcion,
                    id_agente = EXCLUDED.id_agente,
                    agente_id_alerta = EXCLUDED.agente_id_alerta,
                    agente_nombre = EXCLUDED.agente_nombre, ip_origen = EXCLUDED.ip_origen,
                    ip_destino = EXCLUDED.ip_destino, usuario = EXCLUDED.usuario,
                    dominio = EXCLUDED.dominio, archivo_ruta = EXCLUDED.archivo_ruta,
                    archivo_hash = EXCLUDED.archivo_hash, evento = EXCLUDED.evento,
                    campos_ausentes = EXCLUDED.campos_ausentes,
                    evidencia_minima = EXCLUDED.evidencia_minima,
                    t1 = COALESCE(caso.t1, EXCLUDED.t1)
                RETURNING id_caso
                """,
                (v.id_alerta, v.tipo_alerta.value, v.marca_tiempo, v.regla_id, v.regla_nivel,
                 v.regla_descripcion, v.agente_id if catalogado else None, v.agente_id,
                 v.agente_nombre, v.ip_origen, v.ip_destino, v.usuario, v.dominio,
                 v.archivo_ruta, v.archivo_hash, v.evento, list(v.campos_ausentes),
                 Jsonb(a_json(v.evidencia_minima)), self.procedimiento_por_defecto, caso.t0, caso.t1),
            ).fetchone()[0]

            for tabla in ("indicador", "ejecucion_paso", "prioridad_sugerida",
                          "alerta_relacionada"):
                con.execute(f"DELETE FROM {tabla} WHERE id_caso = %s", (id_caso,))
            for i in caso.indicadores:
                con.execute(
                    "INSERT INTO indicador (id_caso, tipo, valor, origen_campo) "
                    "VALUES (%s, %s, %s, %s)", (id_caso, i.tipo.value, i.valor, i.origen_campo))
            for p in caso.pasos:
                con.execute(
                    """INSERT INTO ejecucion_paso (id_caso, paso, estado, inicio, fin,
                           resultado, error, reintentos, fuente, procedencia)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (id_caso, p.paso, p.estado.value, p.inicio, p.fin,
                     None if p.resultado is None else Jsonb(a_json(p.resultado)),
                     p.error, p.reintentos, p.fuente, p.procedencia))
            rel = _relacionadas_del_caso(caso)
            con.execute("UPDATE caso SET total_relacionadas = %s WHERE id_caso = %s",
                        (rel.total if rel is not None else None, id_caso))
            for orden, a in enumerate((rel.alertas if rel else ())[:MAX_RELACIONADAS], 1):
                con.execute(
                    """INSERT INTO alerta_relacionada (id_caso, orden, id_alerta, regla_id,
                           regla_descripcion, regla_nivel, marca_tiempo, agente_nombre)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                    (id_caso, orden, a.id, a.regla_id, a.regla_descripcion, a.regla_nivel,
                     a.marca_tiempo, a.agente_nombre))
            if caso.prioridad:
                pr = caso.prioridad
                con.execute(
                    """INSERT INTO prioridad_sugerida (id_caso, nivel, nivel_alerta,
                           importancia, corroborada, motivos)
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                    (id_caso, pr.nivel.value, pr.nivel_alerta.value if pr.nivel_alerta else None,
                     pr.importancia.value if pr.importancia else None, pr.corroborada,
                     list(pr.motivos)))
            if caso.decision:
                ultima = con.execute(
                    """SELECT decision, justificacion, prioridad_considerada
                       FROM decision_humana WHERE id_caso = %s
                       ORDER BY registrada_en DESC, id_decision DESC LIMIT 1""",
                    (id_caso,)).fetchone()
                nueva = (caso.decision, caso.justificacion,
                         caso.prioridad_considerada.value if caso.prioridad_considerada else None)
                if ultima != nueva:
                    con.execute(
                        """INSERT INTO decision_humana (id_caso, decision,
                               prioridad_considerada, justificacion) VALUES (%s, %s, %s, %s)""",
                        (id_caso, caso.decision, nueva[2], caso.justificacion))

    # ---------- decisiones con analista (fase 4) ----------
    def registrar_decision(self, id_alerta: str, decision: DecisionRegistrada,
                           t1: datetime) -> None:
        """Agrega la decisión y fija t1 solo si estaba vacío, en una transacción con el
        caso bloqueado (dos decisiones simultáneas no pisan t1)."""
        with self._conectar() as con, con.transaction():
            fila = con.execute("SELECT id_caso FROM caso WHERE id_alerta = %s FOR UPDATE",
                               (id_alerta,)).fetchone()
            if fila is None:
                raise LookupError("No existe el caso.")
            con.execute("UPDATE caso SET t1 = COALESCE(t1, %s) WHERE id_caso = %s",
                        (t1, fila[0]))
            con.execute(
                """INSERT INTO decision_humana (id_caso, decision, prioridad_considerada,
                       justificacion, analista, registrada_en)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (fila[0], decision.decision, decision.prioridad_considerada.value,
                 decision.justificacion, decision.analista, decision.registrada_en))

    def decisiones(self, id_alerta: str) -> list[DecisionRegistrada]:
        with self._conectar() as con:
            filas = con.execute(
                """SELECT d.decision, d.justificacion, d.prioridad_considerada, d.analista,
                          d.registrada_en
                   FROM decision_humana d JOIN caso c USING (id_caso)
                   WHERE c.id_alerta = %s ORDER BY d.registrada_en, d.id_decision""",
                (id_alerta,)).fetchall()
        return [DecisionRegistrada(f[0], f[1], Nivel(f[2]), f[3], f[4]) for f in filas]

    def relacionadas_de(self, id_alerta: str) -> AlertasRelacionadas:
        with self._conectar() as con:
            return _leer_relacionadas(con, id_alerta)

    def procedimiento(self, id_alerta: str) -> Optional[str]:
        with self._conectar() as con:
            fila = con.execute("SELECT procedimiento FROM caso WHERE id_alerta = %s",
                               (id_alerta,)).fetchone()
        return fila[0] if fila else None

    # ---------- lectura ----------
    def obtener(self, id_alerta: str) -> Optional[Caso]:
        with self._conectar() as con:
            fila = con.execute(
                f"""SELECT id_caso, tipo_alerta, marca_tiempo, regla_id, regla_nivel,
                        regla_descripcion, {', '.join(_COLUMNAS_VISTA)},
                        campos_ausentes, evidencia_minima, t0, t1
                    FROM caso WHERE id_alerta = %s""", (id_alerta,)).fetchone()
            if fila is None:
                return None
            return self._armar(con, id_alerta, fila)

    def listar(self) -> list[Caso]:
        with self._conectar() as con:
            ids = [f[0] for f in con.execute("SELECT id_alerta FROM caso ORDER BY t0").fetchall()]
        return [c for c in (self.obtener(i) for i in ids) if c is not None]

    def _armar(self, con: psycopg.Connection, id_alerta: str, fila) -> Caso:
        (id_caso, tipo, marca, regla_id, regla_nivel, regla_desc, *resto) = fila
        vista_cols = dict(zip(_COLUMNAS_VISTA, resto[:len(_COLUMNAS_VISTA)]))
        ausentes, evidencia, t0, t1 = resto[len(_COLUMNAS_VISTA):]
        vista = VistaComun(
            id_alerta=id_alerta, marca_tiempo=_iso(marca), regla_id=regla_id,
            regla_nivel=regla_nivel, regla_descripcion=regla_desc,
            agente_id=vista_cols.pop("agente_id_alerta"), tipo_alerta=TipoAlerta(tipo),
            evidencia_minima=evidencia, campos_ausentes=list(ausentes), **vista_cols)
        caso = Caso(vista=vista, t0=t0, t1=t1)

        caso.indicadores = [
            Indicador(TipoIndicador(t), valor, origen) for t, valor, origen in con.execute(
                "SELECT tipo, valor, origen_campo FROM indicador WHERE id_caso = %s "
                "ORDER BY id_indicador", (id_caso,)).fetchall()]
        caso.pasos = [
            RegistroPaso(paso, Estado(estado), inicio, fin, resultado, error, reintentos,
                         fuente, procedencia)
            for paso, estado, inicio, fin, resultado, error, reintentos, fuente, procedencia
            in con.execute(
                """SELECT paso, estado, inicio, fin, resultado, error, reintentos, fuente,
                          procedencia FROM ejecucion_paso WHERE id_caso = %s
                   ORDER BY id_paso""", (id_caso,)).fetchall()]
        caso.alertas_relacionadas = _leer_relacionadas(con, id_alerta).ids

        pr = con.execute(
            """SELECT nivel, nivel_alerta, importancia, corroborada, motivos
               FROM prioridad_sugerida WHERE id_caso = %s""", (id_caso,)).fetchone()
        if pr:
            caso.prioridad = PrioridadSugerida(
                Nivel(pr[0]), list(pr[4]), NivelAlerta(pr[1]) if pr[1] else None,
                Importancia(pr[2]) if pr[2] else None, pr[3])

        dec = con.execute(
            """SELECT decision, justificacion, prioridad_considerada FROM decision_humana
               WHERE id_caso = %s ORDER BY registrada_en DESC, id_decision DESC LIMIT 1""",
            (id_caso,)).fetchone()
        if dec:
            caso.decision, caso.justificacion = dec[0], dec[1]
            caso.prioridad_considerada = Nivel(dec[2])
        return caso


def _iso(valor: Optional[datetime]) -> Optional[str]:
    """TIMESTAMPTZ -> texto ISO 8601 en UTC con «Z», como lo entrega Wazuh."""
    if valor is None:
        return None
    utc = valor.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def _relacionadas_del_caso(caso: Caso) -> Optional[AlertasRelacionadas]:
    """Resultado de P4 tal como lo dejó la investigación. None si P4 no tuvo resultado
    (falló o no se ejecutó): el total queda NULL, no 0 (RNF-07)."""
    paso = next((p for p in caso.pasos if p.paso == PASO_RELACIONADAS), None)
    if paso is None or paso.estado not in (Estado.CON_RESULTADO, Estado.SIN_RESULTADO):
        return None
    r = paso.resultado
    if isinstance(r, AlertasRelacionadas):
        return r
    if isinstance(r, dict):                       # releído de JSON
        return AlertasRelacionadas(int(r.get("total", 0)), tuple(
            ResumenAlerta(**a) for a in r.get("alertas", [])))
    ids = list(r or [])                           # lista de ids (sin detalle)
    return AlertasRelacionadas(len(ids), tuple(ResumenAlerta(i) for i in ids))


def _leer_relacionadas(con: psycopg.Connection, id_alerta: str) -> AlertasRelacionadas:
    fila = con.execute("SELECT id_caso, total_relacionadas FROM caso WHERE id_alerta = %s",
                       (id_alerta,)).fetchone()
    if fila is None:
        return AlertasRelacionadas(0)
    alertas = tuple(
        ResumenAlerta(f[0], f[1], f[2], f[3], _iso(f[4]), f[5]) for f in con.execute(
            """SELECT id_alerta, regla_id, regla_descripcion, regla_nivel, marca_tiempo,
                      agente_nombre FROM alerta_relacionada WHERE id_caso = %s
               ORDER BY orden""", (fila[0],)).fetchall())
    return AlertasRelacionadas(fila[1] if fila[1] is not None else len(alertas), alertas)

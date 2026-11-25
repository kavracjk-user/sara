-- Modelo de datos preliminar de SARA (Tabla 2.4) para PostgreSQL.
-- Se refinará en el incremento I4 al fijar los campos obligatorios del expediente.
-- Credenciales de la aplicación: variables de entorno, nunca en el código (RNF-04).

CREATE TABLE IF NOT EXISTS activo (
    id_agente    TEXT PRIMARY KEY,               -- id del agente de Wazuh
    nombre       TEXT NOT NULL,
    funcion      TEXT NOT NULL,
    importancia  TEXT NOT NULL CHECK (importancia IN ('Alta', 'Media', 'Baja'))
);

CREATE TABLE IF NOT EXISTS caso (
    id_caso            BIGSERIAL PRIMARY KEY,
    id_alerta          TEXT NOT NULL UNIQUE,     -- _id en el indexador de Wazuh
    tipo_alerta        TEXT NOT NULL,
    marca_tiempo       TIMESTAMPTZ,
    regla_id           TEXT,
    regla_nivel        INTEGER,
    regla_descripcion  TEXT,
    id_agente          TEXT REFERENCES activo(id_agente),  -- NULL = no catalogado
    -- Resto de la vista común (Tabla 4.14). Agregado en fase 2 para poder releer el
    -- caso tal como se guardó; NULL = el dato no venía en la alerta.
    agente_id_alerta   TEXT,                     -- id del agente según la alerta (p. ej. 099)
    agente_nombre      TEXT,
    ip_origen          TEXT,
    ip_destino         TEXT,
    usuario            TEXT,
    dominio            TEXT,
    archivo_ruta       TEXT,
    archivo_hash       TEXT,
    evento             TEXT,
    campos_ausentes    TEXT[] NOT NULL DEFAULT '{}',
    evidencia_minima   JSONB NOT NULL,           -- no se pierden campos sin normalizar
    procedimiento      TEXT NOT NULL DEFAULT 'sara'
                       CHECK (procedimiento IN ('sara', 'manual')),  -- línea base y evaluación
    t0                 TIMESTAMPTZ NOT NULL,     -- alerta disponible para el analista
    t1                 TIMESTAMPTZ,              -- primera decisión humana
    total_relacionadas INTEGER,                  -- fase 4b: total real (se guardan hasta 50)
    CHECK (t1 IS NULL OR t1 >= t0)
);

CREATE TABLE IF NOT EXISTS indicador (
    id_indicador BIGSERIAL PRIMARY KEY,
    id_caso      BIGINT NOT NULL REFERENCES caso(id_caso) ON DELETE CASCADE,
    tipo         TEXT NOT NULL CHECK (tipo IN ('ip', 'dominio', 'hash')),
    valor        TEXT NOT NULL,
    origen_campo TEXT NOT NULL,
    UNIQUE (id_caso, tipo, valor)
);

-- Alertas relacionadas tal como se vieron al investigar (fase 4b): hasta 50 por caso,
-- en el orden de su marca de tiempo.
CREATE TABLE IF NOT EXISTS alerta_relacionada (
    id_caso            BIGINT NOT NULL REFERENCES caso(id_caso) ON DELETE CASCADE,
    orden              INTEGER NOT NULL,
    id_alerta          TEXT NOT NULL,            -- _id en el indexador de Wazuh
    regla_id           TEXT,
    regla_descripcion  TEXT,
    regla_nivel        INTEGER,
    marca_tiempo       TIMESTAMPTZ,
    agente_nombre      TEXT,
    PRIMARY KEY (id_caso, orden),
    UNIQUE (id_caso, id_alerta)
);

-- Un resultado negativo, una falla y un dato no aplicable son estados distintos (RNF-07).
CREATE TABLE IF NOT EXISTS ejecucion_paso (
    id_paso      BIGSERIAL PRIMARY KEY,
    id_caso      BIGINT NOT NULL REFERENCES caso(id_caso) ON DELETE CASCADE,
    paso         TEXT NOT NULL,
    estado       TEXT NOT NULL CHECK (estado IN
                 ('con_resultado', 'sin_resultado', 'fallido', 'no_aplicable')),
    inicio       TIMESTAMPTZ NOT NULL,
    fin          TIMESTAMPTZ NOT NULL,
    resultado    JSONB,
    error        TEXT,
    reintentos   INTEGER NOT NULL DEFAULT 0,
    fuente       TEXT,
    procedencia  TEXT,                           -- RNF-05: origen y hora de cada dato
    CHECK (fin >= inicio)
);

CREATE TABLE IF NOT EXISTS prioridad_sugerida (
    id_caso      BIGINT PRIMARY KEY REFERENCES caso(id_caso) ON DELETE CASCADE,
    nivel        TEXT NOT NULL CHECK (nivel IN
                 ('Alta', 'Media', 'Baja', 'Información insuficiente')),
    nivel_alerta TEXT,
    importancia  TEXT,
    corroborada  BOOLEAN NOT NULL DEFAULT FALSE,
    motivos      TEXT[] NOT NULL
);

-- Una o más decisiones por caso; el tiempo se mide con la primera (t1).
CREATE TABLE IF NOT EXISTS decision_humana (
    id_decision           BIGSERIAL PRIMARY KEY,
    id_caso               BIGINT NOT NULL REFERENCES caso(id_caso) ON DELETE CASCADE,
    decision              TEXT NOT NULL CHECK (decision IN
                          ('escalar', 'descartar', 'solicitar_mas_informacion')),
    prioridad_considerada TEXT NOT NULL,
    justificacion         TEXT NOT NULL CHECK (length(btrim(justificacion)) > 0),
    analista              TEXT,                  -- RF-11 (fase 4); seudónimo en el piloto
    registrada_en         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_paso_caso ON ejecucion_paso(id_caso);
CREATE INDEX IF NOT EXISTS ix_decision_caso ON decision_humana(id_caso);

-- Exportación para la evaluación comparativa (RF-14): una fila por caso.
CREATE OR REPLACE VIEW v_exportacion AS
SELECT c.id_caso, c.id_alerta, c.tipo_alerta, c.procedimiento, c.t0, c.t1,
       EXTRACT(EPOCH FROM (c.t1 - c.t0)) / 60.0 AS minutos_hasta_decision,
       p.nivel AS prioridad_sugerida,
       d.decision, d.prioridad_considerada
FROM caso c
LEFT JOIN prioridad_sugerida p USING (id_caso)
LEFT JOIN LATERAL (SELECT * FROM decision_humana
                   WHERE id_caso = c.id_caso ORDER BY registrada_en LIMIT 1) d ON TRUE;

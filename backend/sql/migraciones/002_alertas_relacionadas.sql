-- Fase 4b (2026-11-25): alertas relacionadas con detalle. No destructiva e idempotente.
-- Las bases nuevas ya lo traen en schema.sql.
-- Aplicar:  docker compose exec -T postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < backend/sql/migraciones/002_alertas_relacionadas.sql
ALTER TABLE caso ADD COLUMN IF NOT EXISTS total_relacionadas INTEGER;

CREATE TABLE IF NOT EXISTS alerta_relacionada (
    id_caso            BIGINT NOT NULL REFERENCES caso(id_caso) ON DELETE CASCADE,
    orden              INTEGER NOT NULL,
    id_alerta          TEXT NOT NULL,
    regla_id           TEXT,
    regla_descripcion  TEXT,
    regla_nivel        INTEGER,
    marca_tiempo       TIMESTAMPTZ,
    agente_nombre      TEXT,
    PRIMARY KEY (id_caso, orden),
    UNIQUE (id_caso, id_alerta)
);

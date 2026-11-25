-- Fase 4b (2026-11-25): marca de avance de la ingesta. No destructiva e idempotente.
-- Aplicar:  docker compose exec -T postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < backend/sql/migraciones/004_ingesta_marca.sql
CREATE TABLE IF NOT EXISTS ingesta_marca (
    nombre          TEXT PRIMARY KEY,            -- p. ej. 'wazuh-alertas'
    orden           JSONB NOT NULL,              -- valores de orden de la última alerta
    marca_tiempo    TIMESTAMPTZ,                 -- su marca de tiempo (legible)
    actualizada_en  TIMESTAMPTZ NOT NULL DEFAULT now()
);

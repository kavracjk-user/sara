-- Fase 4 (2026-11-25): nombre del analista en cada decisión (RF-11).
-- Para bases creadas antes de este cambio. No destructiva e idempotente.
-- Las bases nuevas ya la traen en schema.sql. Las decisiones anteriores quedan con NULL.
-- Aplicar:  docker compose exec -T postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < backend/sql/migraciones/001_analista_en_decision.sql
ALTER TABLE decision_humana ADD COLUMN IF NOT EXISTS analista TEXT;

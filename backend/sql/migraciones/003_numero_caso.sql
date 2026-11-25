-- Fase 4b (2026-11-25): número de caso legible. No destructiva e idempotente.
-- Los casos existentes reciben número en el orden de su t0 (empate: id_caso).
-- Aplicar:  docker compose exec -T postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < backend/sql/migraciones/003_numero_caso.sql
CREATE SEQUENCE IF NOT EXISTS caso_numero_seq;
ALTER TABLE caso ADD COLUMN IF NOT EXISTS numero_caso BIGINT;

DO $$
DECLARE r RECORD;
BEGIN
    FOR r IN SELECT id_caso FROM caso WHERE numero_caso IS NULL ORDER BY t0, id_caso LOOP
        UPDATE caso SET numero_caso = nextval('caso_numero_seq') WHERE id_caso = r.id_caso;
    END LOOP;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'caso_numero_caso_key') THEN
        ALTER TABLE caso ADD CONSTRAINT caso_numero_caso_key UNIQUE (numero_caso);
    END IF;
END $$;

ALTER TABLE caso ALTER COLUMN numero_caso SET DEFAULT nextval('caso_numero_seq');
ALTER TABLE caso ALTER COLUMN numero_caso SET NOT NULL;
ALTER SEQUENCE caso_numero_seq OWNED BY caso.numero_caso;

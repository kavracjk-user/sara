-- Catálogo de activos SINTÉTICO del laboratorio (RNF-03), según docs/anexo-c-guion-casos.md.
-- PROPUESTA pendiente de aprobación del tutor. El agente 099 (pc-nuevo) NO se incluye a
-- propósito: es el caso de activo no catalogado.
-- Se ejecuta después de schema.sql (orden alfabético de docker-entrypoint-initdb.d).
INSERT INTO activo (id_agente, nombre, funcion, importancia) VALUES
    ('001', 'srv-web',     'Servidor web de pruebas',       'Alta'),
    ('002', 'srv-bd',      'Base de datos de pruebas',      'Alta'),
    ('003', 'pc-analista', 'Equipo del analista',           'Media'),
    ('004', 'pc-lab-01',   'Equipo de laboratorio general', 'Baja')
ON CONFLICT (id_agente) DO UPDATE
    SET nombre = EXCLUDED.nombre, funcion = EXCLUDED.funcion,
        importancia = EXCLUDED.importancia;

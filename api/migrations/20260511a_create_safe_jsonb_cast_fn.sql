-- try_bytea_to_jsonb: safe bytea → jsonb cast that returns NULL on any
-- conversion error (invalid UTF-8, malformed JSON, etc.) instead of
-- raising. Needed by ImageSecretsTableHandler which reads
-- image_scan_artifacts.content as bytea and used to crash the entire
-- request on a single bad row, since Postgres can evaluate WHERE
-- predicates in any order and a "filter out bad rows first" clause
-- doesn't reliably prevent the cast from running.
--
-- PL/pgSQL EXCEPTION block catches OTHERS — the standard idiom for
-- "best-effort cast or NULL". IMMUTABLE + STRICT lets the planner
-- inline and memoise within a single query plan.

CREATE OR REPLACE FUNCTION try_bytea_to_jsonb(b bytea)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE STRICT
AS $$
BEGIN
    RETURN convert_from(b, 'utf8')::jsonb;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$;

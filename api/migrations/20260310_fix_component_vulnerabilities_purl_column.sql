-- Fix component_vulnerabilities: GORM mapped PURL field to p_url column, but all
-- raw SQL queries use the column name purl. Backfill purl from p_url and fix the index.
DO $$
BEGIN
  -- Backfill purl from p_url where purl is still empty.
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'component_vulnerabilities'
      AND column_name = 'p_url'
  ) THEN
    UPDATE component_vulnerabilities SET purl = p_url WHERE (purl IS NULL OR purl = '') AND p_url IS NOT NULL AND p_url <> '';
  END IF;

  -- Move the index from p_url to purl if it still points at p_url.
  IF EXISTS (
    SELECT 1 FROM pg_indexes
    WHERE tablename = 'component_vulnerabilities'
      AND indexname = 'idx_component_vuln_purl'
      AND indexdef LIKE '%p_url%'
  ) THEN
    DROP INDEX IF EXISTS idx_component_vuln_purl;
    CREATE INDEX idx_component_vuln_purl ON component_vulnerabilities (purl);
  END IF;
END $$;

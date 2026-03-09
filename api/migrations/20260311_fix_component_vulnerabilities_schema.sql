-- Bring component_vulnerabilities into alignment with current code, which expects
-- a `purl` column for OSV cache lookups and batch maintenance.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.tables
    WHERE table_schema = 'public'
      AND table_name = 'component_vulnerabilities'
  ) THEN
    -- Legacy deployments may still have package_url instead of purl.
    IF NOT EXISTS (
      SELECT 1
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'component_vulnerabilities'
        AND column_name = 'purl'
    ) THEN
      IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'component_vulnerabilities'
          AND column_name = 'package_url'
      ) THEN
        ALTER TABLE component_vulnerabilities ADD COLUMN purl text;
        UPDATE component_vulnerabilities
          SET purl = package_url
          WHERE purl IS NULL AND package_url IS NOT NULL;
        UPDATE component_vulnerabilities
          SET package_url = purl
          WHERE package_url IS NULL AND purl IS NOT NULL;
      ELSE
        ALTER TABLE component_vulnerabilities ADD COLUMN purl text;
      END IF;
    END IF;

    IF NOT EXISTS (
      SELECT 1
      FROM pg_indexes
      WHERE tablename = 'component_vulnerabilities'
        AND indexname = 'idx_component_vuln_purl'
    ) THEN
      CREATE INDEX idx_component_vuln_purl ON component_vulnerabilities (purl);
    END IF;
  END IF;
END $$;

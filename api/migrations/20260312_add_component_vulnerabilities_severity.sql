ALTER TABLE component_vulnerabilities
ADD COLUMN IF NOT EXISTS severity TEXT;

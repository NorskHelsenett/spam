-- Add composite index on (type, status) to speed up paginated runs queries
-- that filter WHERE type = 'CREATE_RUN' AND status = ?
CREATE INDEX IF NOT EXISTS idx_jobs_type_status
ON jobs (type, status);

CREATE TABLE IF NOT EXISTS materialized_view_refreshes (
  name TEXT PRIMARY KEY,
  refreshed_at TIMESTAMPTZ NOT NULL
);

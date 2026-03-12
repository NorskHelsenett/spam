CREATE TABLE IF NOT EXISTS vuln_dashboard_snapshots (
    snapshot_date   DATE PRIMARY KEY,
    critical        INT NOT NULL DEFAULT 0,
    high            INT NOT NULL DEFAULT 0,
    medium          INT NOT NULL DEFAULT 0,
    low             INT NOT NULL DEFAULT 0,
    unknown         INT NOT NULL DEFAULT 0,
    total_vulns     INT NOT NULL DEFAULT 0,
    scanned_sboms   INT NOT NULL DEFAULT 0,
    last_scanned_at TIMESTAMPTZ,
    captured_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

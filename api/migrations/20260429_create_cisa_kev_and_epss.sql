-- KEV and EPSS feed tables — bulk-replaced once per day by the
-- FETCH_KEV / FETCH_EPSS jobs. Stored as standalone tables (not
-- columns on vuln_metadata) so feed ingestion is decoupled from
-- per-id enrichment: the CSV/JSON downloads cover CVEs we haven't
-- seen in any scan yet, and queries can JOIN whether or not a
-- vuln_metadata row exists. Truncate-and-insert keeps the surface
-- simple — there is no merge logic to get wrong, and the daily
-- refresh window (~24 h) is small enough that staleness is bounded.

-- CISA Known Exploited Vulnerabilities
-- Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
-- ~1.5k rows; cve_id is the natural key.
CREATE TABLE IF NOT EXISTS cisa_kev_entries (
    cve_id              text        PRIMARY KEY,
    vendor_project      text        NOT NULL DEFAULT '',
    product             text        NOT NULL DEFAULT '',
    vuln_name           text        NOT NULL DEFAULT '',
    short_description   text        NOT NULL DEFAULT '',
    required_action     text        NOT NULL DEFAULT '',
    date_added          date,
    due_date            date,
    known_ransomware    boolean     NOT NULL DEFAULT FALSE,
    notes               text        NOT NULL DEFAULT '',
    fetched_at          timestamptz NOT NULL DEFAULT NOW()
);

-- FIRST.org Exploit Prediction Scoring System
-- Source: https://epss.cyentia.com/epss_scores-current.csv.gz
-- ~250k rows daily; each row scores a CVE's 30-day exploitation
-- probability + percentile rank. Index on score DESC supports the
-- "high-risk first" sort even outside the joined-list query.
CREATE TABLE IF NOT EXISTS epss_entries (
    cve_id              text        PRIMARY KEY,
    score               real        NOT NULL,
    percentile          real        NOT NULL,
    score_date          date,
    fetched_at          timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_epss_entries_score_desc
    ON epss_entries (score DESC);

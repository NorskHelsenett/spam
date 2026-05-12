-- dep_health stores third-party library health metadata fetched
-- from public registries (npm, PyPI, Go modules, RubyGems, crates,
-- NuGet, Maven Central) and their source-repo providers (GitHub,
-- GitLab). One row per (ecosystem, package_name) — versions roll up
-- into versions_behind_* counters rather than getting their own rows
-- because health is a per-package property, not a per-version one.
--
-- The table is read by the asset_risk MV refresh (Phase 3c) to feed
-- per-asset Trust signals: assets depending on archived / deprecated
-- / single-maintainer / many-versions-behind packages get penalised
-- in proportion. fetched_at + etag let the daily fetch job stay
-- cheap (HTTP 304 short-circuits a full sweep).

CREATE TABLE IF NOT EXISTS dep_health (
    ecosystem               text        NOT NULL,
    package_name            text        NOT NULL,
    source_url              text        NOT NULL DEFAULT '',
    source_provider         text        NOT NULL DEFAULT '', -- 'github' | 'gitlab' | ''
    latest_version          text        NOT NULL DEFAULT '',
    last_activity_at        timestamptz,
    commits_90d             int         NOT NULL DEFAULT 0,
    stars                   int         NOT NULL DEFAULT 0,
    open_issues             int         NOT NULL DEFAULT 0,
    is_archived             boolean     NOT NULL DEFAULT FALSE,
    is_deprecated           boolean     NOT NULL DEFAULT FALSE,
    single_maintainer       boolean     NOT NULL DEFAULT FALSE,
    health_score            smallint    NOT NULL DEFAULT 0,
    fetched_at              timestamptz NOT NULL DEFAULT NOW(),
    etag                    text        NOT NULL DEFAULT '',
    error                   text        NOT NULL DEFAULT '',
    PRIMARY KEY (ecosystem, package_name)
);

-- Hot indexes for the asset_risk rollup: filter to packages with
-- known issues so the MV refresh doesn't full-scan dep_health.
CREATE INDEX IF NOT EXISTS idx_dep_health_archived
    ON dep_health (is_archived) WHERE is_archived;
CREATE INDEX IF NOT EXISTS idx_dep_health_deprecated
    ON dep_health (is_deprecated) WHERE is_deprecated;
CREATE INDEX IF NOT EXISTS idx_dep_health_low_score
    ON dep_health (health_score) WHERE health_score < 40;
-- Job's "rows due for refresh" predicate.
CREATE INDEX IF NOT EXISTS idx_dep_health_fetched_at
    ON dep_health (fetched_at);

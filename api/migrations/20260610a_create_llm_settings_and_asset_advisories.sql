-- LLM advisory enrichment: admin-tunable settings per use case +
-- per-asset cache of generated output.
--
-- llm_settings holds one row per use case so prompt/model/sampling
-- can be tuned independently:
--   advisory_summary  2-3 sentence narrative shown at the top of an
--                     expanded triage card.
--   triage_verdict    shadow-mode agent decision (keep/suppress with
--                     justification + confidence). Recorded for
--                     evaluation only — it takes NO action; the
--                     future suppression path is authoring VEX
--                     records, which is deliberately not wired yet.
--   finding_chat      interactive Q&A about a single finding, opened
--                     from the triage card's floating chat window.
--
-- asset_advisories caches the output keyed by (asset_type, asset_id)
-- with the signals_hash that produced it — the worker regenerates a
-- row only when the asset's tier-relevant signals change, so the LLM
-- isn't re-asked the same question daily.
--
-- Seeded prompts are the ones validated against the Open WebUI / vLLM
-- endpoint. max_tokens defaults 0 = unset: the endpoint's own limits
-- govern (the models carry ~256k context); set a value only to cap
-- cost/latency deliberately — the model reasons before answering, so
-- small caps truncate. enabled defaults FALSE — nothing calls the LLM
-- until an admin flips it on.

CREATE TABLE IF NOT EXISTS llm_settings (
    use_case      text        PRIMARY KEY,
    enabled       boolean     NOT NULL DEFAULT FALSE,
    base_url      text        NOT NULL DEFAULT '',
    -- API key is AES-GCM encrypted with the provider secrets key
    -- (same scheme as git provider PATs); api_key_fp keeps a masked
    -- fingerprint so the admin UI can show "****abcd" without a
    -- decrypt round-trip.
    api_key_enc   bytea       NOT NULL DEFAULT ''::bytea,
    api_key_fp    text        NOT NULL DEFAULT '',
    model         text        NOT NULL DEFAULT '',
    system_prompt text        NOT NULL DEFAULT '',
    temperature   real        NOT NULL DEFAULT 0,
    top_k         integer     NOT NULL DEFAULT 0,
    top_p         real        NOT NULL DEFAULT 0,
    max_tokens    integer     NOT NULL DEFAULT 0,
    updated_at    timestamptz NOT NULL DEFAULT NOW(),
    updated_by    text        NOT NULL DEFAULT ''
);

INSERT INTO llm_settings (use_case, base_url, model, system_prompt, temperature)
VALUES
(
    'advisory_summary',
    'http://10.10.10.192:11434/api/chat/completions',
    'nhn-medium',
    'You write advisories for a Kubernetes vulnerability triage dashboard. Given one finding as JSON, write a 2-3 sentence advisory for a dev team lead: what is wrong, why it matters now (use the KEV/EPSS exploitation evidence and exposure, not CVSS), and the single concrete action. If the tier is deprioritized, explain in 1-2 sentences why no action is needed. Do not state impact details that are not present in the data. Plain text, no markdown, no hedging, no preamble.',
    0
),
(
    'triage_verdict',
    'http://10.10.10.192:11434/api/chat/completions',
    'nhn-medium',
    'You are a vulnerability triage agent for a Kubernetes platform. Decide whether a finding could be suppressed as not applicable to this environment. Be conservative: suppress ONLY when the data explicitly rules out the attack precondition. Respond with ONLY a JSON object: {"verdict":"suppress"|"keep","justification":"<one sentence>","confidence":0.0-1.0,"missing_data":["<what you would need to check to be sure>"]}',
    0
),
(
    'finding_chat',
    'http://10.10.10.192:11434/api/chat/completions',
    'nhn-medium',
    'You are a security engineer assistant embedded in a Kubernetes vulnerability triage dashboard. The first user message contains one finding as JSON: the asset, its triage tier, exploitation signals (KEV, EPSS, internet exposure), its top CVEs, and exposed hosts. Answer follow-up questions about this finding: exploitability, prioritization, remediation steps, mitigations, and how to verify applicability. Be concrete and concise. Ground answers in the provided data and well-established public knowledge about the listed CVEs; say plainly when you would need more data. Plain text, no markdown headers.',
    0
)
ON CONFLICT (use_case) DO NOTHING;

CREATE TABLE IF NOT EXISTS asset_advisories (
    asset_type            text        NOT NULL,
    asset_id              text        NOT NULL,
    signals_hash          text        NOT NULL DEFAULT '',
    summary               text        NOT NULL DEFAULT '',
    summary_model         text        NOT NULL DEFAULT '',
    verdict               text        NOT NULL DEFAULT '',
    verdict_justification text        NOT NULL DEFAULT '',
    verdict_confidence    real        NOT NULL DEFAULT 0,
    verdict_missing_data  text        NOT NULL DEFAULT '',
    verdict_model         text        NOT NULL DEFAULT '',
    generated_at          timestamptz NOT NULL DEFAULT NOW(),
    PRIMARY KEY (asset_type, asset_id)
);

-- One advisory backfill at a time: the partial unique index makes a
-- second enqueue hit the constraint instead of double-draining the
-- LLM endpoint.
CREATE UNIQUE INDEX IF NOT EXISTS ux_jobs_advisory_backfill_active
  ON jobs (type)
  WHERE type = 'ADVISORY_BACKFILL'
    AND status IN ('QUEUED', 'RETRY');

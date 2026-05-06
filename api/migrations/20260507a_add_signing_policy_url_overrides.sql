-- Extend signing_policy with optional cosign attestation URL
-- overrides. Cosign accepts up to four endpoint URLs that admins
-- might need to override for self-hosted Sigstore or split-registry
-- signature distribution; we model them as nullable columns so the
-- common case (public Sigstore) leaves them empty and the runner
-- omits the corresponding flags.
--
--   signature_repository  -> --signature-repository
--   fulcio_url            -> --fulcio-url
--   rekor_url             -> --rekor-url
--   tuf_mirror_url        -> --tuf-mirror
--
-- ADD COLUMN IF NOT EXISTS keeps the migration idempotent so a
-- redeploy doesn't error when the columns are already present.

ALTER TABLE signing_policy
    ADD COLUMN IF NOT EXISTS signature_repository text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS fulcio_url           text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS rekor_url            text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS tuf_mirror_url       text NOT NULL DEFAULT '';

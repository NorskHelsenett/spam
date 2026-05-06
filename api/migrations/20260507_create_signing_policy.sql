-- signing_policy holds the cosign verification policy used by the
-- image-scanner to populate image_digests.verified_source honestly.
--
-- Single global policy for now (PK = name = 'cosign'); a follow-up
-- can widen to per-scope-pattern policies once that becomes needed.
-- Until a row exists with enabled=true, the runner treats every
-- image as unverified — same posture as today, just observable.
--
-- key_pem_encrypted is opaque ciphertext produced by
-- providerconfig.EncryptToken (AES-GCM under PROVIDER_SECRETS_KEY).
-- Reusing the same encryption key avoids forcing admins to manage
-- a second secret; the public key isn't secret per se but storing
-- it as bytea uniformly keeps the schema simple. NULL for keyless
-- mode (which is the common case — Sigstore identity comes from
-- issuer + subject_pattern, no key required).

CREATE TABLE IF NOT EXISTS signing_policy (
    name              text          PRIMARY KEY,
    policy_type       text          NOT NULL CHECK (policy_type IN ('keyless', 'key')),
    enabled           boolean       NOT NULL DEFAULT FALSE,
    issuer            text          NOT NULL DEFAULT '',
    subject_pattern   text          NOT NULL DEFAULT '',
    key_pem_encrypted bytea,
    key_fingerprint   text          NOT NULL DEFAULT '',
    created_at        timestamptz   NOT NULL DEFAULT NOW(),
    updated_at        timestamptz   NOT NULL DEFAULT NOW(),
    updated_by        text          NOT NULL DEFAULT ''
);

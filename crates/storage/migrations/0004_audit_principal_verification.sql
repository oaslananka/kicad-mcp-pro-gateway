-- Additive audit provenance for verified principal evidence.
--
-- Existing audit rows predate remote-actor verification and therefore remain
-- explicitly unverified. Only safe post-verification metadata is persisted:
-- never tokens, signatures, certificates, raw proof, or transport bindings.
ALTER TABLE audit_events ADD COLUMN principal_assurance TEXT NOT NULL DEFAULT 'unverified';
ALTER TABLE audit_events ADD COLUMN verified_principal_issuer TEXT;
ALTER TABLE audit_events ADD COLUMN verified_principal_subject TEXT;
ALTER TABLE audit_events ADD COLUMN principal_verification_source TEXT;
ALTER TABLE audit_events ADD COLUMN authentication_strength TEXT;

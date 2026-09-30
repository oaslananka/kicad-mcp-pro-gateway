-- Additive verified-principal metadata for authorization records.
--
-- Existing rows remain unverified: the new JSON columns are nullable and
-- principal_assurance is not rewritten. Verified metadata is safe,
-- non-secret post-verification state only; raw credentials/tokens/signatures
-- must never be stored here.
ALTER TABLE access_grants ADD COLUMN verified_principal TEXT;
ALTER TABLE authorization_leases ADD COLUMN verified_principal TEXT;

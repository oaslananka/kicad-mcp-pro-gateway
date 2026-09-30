-- Additive, immutable dynamic-risk evidence for audit records.
--
-- Historical rows keep their recorded effective risk, but no version/base
-- values are invented. An empty factor list states only that no structured
-- dynamic-risk evidence was recorded by the older schema.
ALTER TABLE audit_events ADD COLUMN risk_policy_version INTEGER;
ALTER TABLE audit_events ADD COLUMN base_risk TEXT;
ALTER TABLE audit_events ADD COLUMN risk_factors_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE vendor_checks ADD COLUMN partial_succeeded_at INTEGER;
ALTER TABLE vendor_checks ADD COLUMN releases_failures INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vendor_checks ADD COLUMN advisories_failures INTEGER NOT NULL DEFAULT 0;
ALTER TABLE observed_versions ADD COLUMN security_reminded_at INTEGER;

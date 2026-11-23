ALTER TABLE vendor_checks ADD COLUMN releases_state TEXT NOT NULL DEFAULT 'unavailable';
ALTER TABLE vendor_checks ADD COLUMN advisories_state TEXT NOT NULL DEFAULT 'unavailable';
ALTER TABLE vendor_checks ADD COLUMN coverage TEXT NOT NULL DEFAULT 'unavailable';

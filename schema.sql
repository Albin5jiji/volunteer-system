PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS donors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    donor_code TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    phone TEXT,
    age INTEGER,
    blood_group TEXT,
    id_document TEXT,
    address TEXT,
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS fingerprint_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    donor_id INTEGER NOT NULL REFERENCES donors(id) ON DELETE CASCADE,
    finger_position TEXT NOT NULL DEFAULT 'unknown',
    template_format TEXT NOT NULL DEFAULT 'ISO',
    template_data TEXT NOT NULL,
    template_sha256 TEXT NOT NULL UNIQUE,
    image_sha256 TEXT,
    image_features TEXT,
    quality INTEGER,
    device_name TEXT,
    captured_at TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1))
);

CREATE TABLE IF NOT EXISTS candidate_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    probe_template_sha256 TEXT,
    outcome TEXT NOT NULL CHECK (
        outcome IN ('screened_clear', 'duplicate_alert', 'matcher_unavailable', 'registered')
    ),
    matched_donor_id INTEGER REFERENCES donors(id) ON DELETE SET NULL,
    matched_template_id INTEGER REFERENCES fingerprint_templates(id) ON DELETE SET NULL,
    match_score INTEGER,
    threshold_used INTEGER NOT NULL,
    matcher_status TEXT NOT NULL,
    quality INTEGER,
    device_name TEXT,
    operator_name TEXT,
    notes TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS donation_visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    donor_id INTEGER REFERENCES donors(id) ON DELETE SET NULL,
    visit_date TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('accepted', 'blocked_duplicate', 'manual_review')
    ),
    check_id INTEGER REFERENCES candidate_checks(id) ON DELETE SET NULL,
    matched_template_id INTEGER REFERENCES fingerprint_templates(id) ON DELETE SET NULL,
    match_score INTEGER,
    threshold_used INTEGER,
    operator_name TEXT,
    notes TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    check_id INTEGER REFERENCES candidate_checks(id) ON DELETE CASCADE,
    donor_id INTEGER REFERENCES donors(id) ON DELETE SET NULL,
    severity TEXT NOT NULL CHECK (severity IN ('warning', 'danger')),
    message TEXT NOT NULL,
    is_resolved INTEGER NOT NULL DEFAULT 0 CHECK (is_resolved IN (0, 1)),
    created_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_donors_name ON donors(full_name);
CREATE INDEX IF NOT EXISTS idx_donors_phone ON donors(phone);
CREATE INDEX IF NOT EXISTS idx_templates_active ON fingerprint_templates(is_active, donor_id);
CREATE INDEX IF NOT EXISTS idx_templates_hash ON fingerprint_templates(template_sha256);
CREATE INDEX IF NOT EXISTS idx_checks_created ON candidate_checks(created_at);
CREATE INDEX IF NOT EXISTS idx_checks_outcome ON candidate_checks(outcome);
CREATE INDEX IF NOT EXISTS idx_visits_donor_date ON donation_visits(donor_id, visit_date);
CREATE INDEX IF NOT EXISTS idx_alerts_open ON alerts(is_resolved, created_at);

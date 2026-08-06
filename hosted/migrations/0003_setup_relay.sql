ALTER TABLE setup_sessions ADD COLUMN apple_account_email TEXT NOT NULL DEFAULT '';
ALTER TABLE setup_sessions ADD COLUMN verification_code TEXT NOT NULL DEFAULT '';
ALTER TABLE setup_sessions ADD COLUMN device_candidates_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE setup_sessions ADD COLUMN selected_candidate_id TEXT NOT NULL DEFAULT '';
ALTER TABLE setup_sessions ADD COLUMN confirmed_test_ring INTEGER NOT NULL DEFAULT 0 CHECK (confirmed_test_ring IN (0, 1));
ALTER TABLE setup_sessions ADD COLUMN runner_started_at TEXT;

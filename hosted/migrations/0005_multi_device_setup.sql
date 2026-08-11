ALTER TABLE setup_sessions ADD COLUMN verification_method TEXT NOT NULL DEFAULT 'sms';
ALTER TABLE setup_sessions ADD COLUMN selected_devices_json TEXT NOT NULL DEFAULT '[]';

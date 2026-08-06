ALTER TABLE devices ADD COLUMN apple_account_email TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN session_bucket TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN session_prefix TEXT NOT NULL DEFAULT '';
ALTER TABLE ring_jobs ADD COLUMN dispatched_at TEXT;
ALTER TABLE ring_jobs ADD COLUMN runner_message_id TEXT NOT NULL DEFAULT '';

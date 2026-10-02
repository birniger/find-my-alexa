-- Sign-in owned by this app, built alongside Auth0 rather than replacing it.
-- Nothing here switches anything over: during the migration window an account
-- can arrive with either an Auth0 token or a session issued below, so a mistake
-- in this code cannot lock anyone out of their own app.

CREATE TABLE account_credentials (
  account_id TEXT PRIMARY KEY,
  -- Self-describing so the cost can be raised later without invalidating
  -- existing passwords: pbkdf2$sha256$<iterations>$<salt hex>$<hash hex>
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

-- The id is a SHA-256 of the cookie value, never the value itself, so a dump of
-- this table yields no usable session.
CREATE TABLE account_sessions (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  user_agent TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT NOT NULL,
  FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

CREATE INDEX idx_account_sessions_account ON account_sessions(account_id);
CREATE INDEX idx_account_sessions_expiry ON account_sessions(expires_at);

-- Single-use links for setting a first password or resetting a forgotten one.
-- Hashed for the same reason as sessions.
CREATE TABLE password_tokens (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  purpose TEXT NOT NULL DEFAULT 'set' CHECK (purpose IN ('set', 'reset')),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

CREATE INDEX idx_password_tokens_account ON password_tokens(account_id);

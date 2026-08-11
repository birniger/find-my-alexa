-- An authorization server for exactly one caller: the Alexa skill.
--
-- Deliberately not a general OAuth provider. There is one confidential client,
-- its redirect URIs are matched exactly, PKCE is mandatory, and there are no
-- scopes and no dynamic registration. Everything this does not support is a
-- thing that cannot be got wrong.
--
-- Codes and tokens are stored as SHA-256 of the value, never the value, so a
-- dump of these tables cannot be replayed against the skill.

CREATE TABLE oauth_codes (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  -- The S256 challenge the client committed to. Redemption must present a
  -- verifier that hashes to this, so an intercepted code is useless alone.
  code_challenge TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

CREATE INDEX idx_oauth_codes_account ON oauth_codes(account_id);

CREATE TABLE oauth_tokens (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
  -- Refresh rotation: redeeming one issues a successor and retires it, so a
  -- replayed refresh token is detectable and already dead.
  replaced_by TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

CREATE INDEX idx_oauth_tokens_account ON oauth_tokens(account_id, kind);
CREATE INDEX idx_oauth_tokens_expiry ON oauth_tokens(expires_at);

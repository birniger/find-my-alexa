-- Owner-controlled settings that must be changeable from the My Builds panel
-- without a redeploy. Anything stored here is readable by whoever holds the
-- Cloudflare API token, so it is a weaker place than a Worker secret; the SMTP
-- password lives here only because setting it from a panel requires that.
-- Values are never returned by any API — the owner endpoints report whether a
-- secret is present, never what it is.
CREATE TABLE app_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

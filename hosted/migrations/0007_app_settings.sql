-- Owner-controlled settings that must be changeable from the My Builds panel
-- without a redeploy. The SMTP password is encrypted with a key held as a
-- Worker secret before it lands here, so a dump of this table does not reveal
-- it. Values are never returned by any API either — the owner endpoints report
-- whether a secret is present, never what it is.
CREATE TABLE app_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

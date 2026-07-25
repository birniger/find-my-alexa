# Security

This repository intentionally contains no Apple password, verification code,
iCloud cookie, authenticated session, selected device ID, AWS account ID,
Alexa skill ID, or deployed Lambda ARN.

Keep `skill-package/skill.json`, `samconfig.toml`, `.env` files, session files,
cookie jars, `target.json`, and `session-bundle.zip` private. The supplied
`.gitignore` excludes these paths and file types.

If an iCloud session is ever exposed, delete it from the deployment bucket,
sign out relevant browser sessions from the Apple Account security page, and
rerun `scripts/authenticate.py`. If an AWS credential is exposed, revoke it
immediately in AWS IAM.

Do not report security issues by attaching credentials or session files to a
public GitHub issue.

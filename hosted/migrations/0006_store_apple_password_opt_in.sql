-- Off by default: an account only holds an Apple password after explicitly
-- ticking the box during setup, so invited friends are never opted in by a
-- decision the owner made for their own account.
ALTER TABLE accounts ADD COLUMN store_apple_password INTEGER NOT NULL DEFAULT 0;

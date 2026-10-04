-- auth-kit tables (Postgres). Add this to the app's migrations once.
-- user_id is text so it works whatever type the app's user ids are. There is
-- no foreign key to the app's users table on purpose: auth-kit does not know
-- its name; the app's deleteUser removes these rows through auth-kit.

-- Security state per user. A user with no row here is treated as existing
-- before auth-kit was added: email verified, no two-factor.
CREATE TABLE IF NOT EXISTS "auth_state" (
  "user_id"             TEXT PRIMARY KEY,
  "email_verified_at"   TIMESTAMPTZ,
  -- Raised to end every session (password change, email change, sign out everywhere).
  "token_version"       INTEGER NOT NULL DEFAULT 0,
  -- Two-factor: the secret (sealed by the app's SecretBox when it has one),
  -- set up first and enabled only once a code from it has been checked.
  "totp_secret"         TEXT,
  "totp_enabled_at"     TIMESTAMPTZ,
  -- The last time step used, so a code can't be used twice.
  "totp_last_step"      BIGINT,
  -- SHA-256 of each unused recovery code.
  "recovery_codes"      TEXT[] NOT NULL DEFAULT '{}',
  "password_changed_at" TIMESTAMPTZ,
  "last_login_at"       TIMESTAMPTZ,
  "created_at"          TIMESTAMPTZ NOT NULL DEFAULT now(),
  "updated_at"          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One-time links. Only the SHA-256 of the token is kept.
CREATE TABLE IF NOT EXISTS "auth_links" (
  "token_hash"  TEXT PRIMARY KEY,
  "user_id"     TEXT NOT NULL,
  "purpose"     TEXT NOT NULL,          -- reset_password | invite | verify_email | change_email
  "new_email"   TEXT,                   -- change_email: the address being moved to
  "created_by"  TEXT,
  "created_at"  TIMESTAMPTZ NOT NULL DEFAULT now(),
  "expires_at"  TIMESTAMPTZ NOT NULL,
  "used_at"     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS "auth_links_user_idx" ON "auth_links" ("user_id");

-- What people asked for and an admin has to act on, when links are not
-- emailed: forgotten passwords and email changes.
CREATE TABLE IF NOT EXISTS "auth_requests" (
  "id"          TEXT PRIMARY KEY,
  "user_id"     TEXT NOT NULL,
  "kind"        TEXT NOT NULL,          -- password_reset | email_change
  "new_email"   TEXT,
  "created_at"  TIMESTAMPTZ NOT NULL DEFAULT now(),
  "handled_at"  TIMESTAMPTZ,
  "handled_by"  TEXT,
  "outcome"     TEXT                    -- link_created | dismissed | superseded
);
CREATE INDEX IF NOT EXISTS "auth_requests_open_idx" ON "auth_requests" ("created_at") WHERE "handled_at" IS NULL;

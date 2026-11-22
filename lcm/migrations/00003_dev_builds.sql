-- +goose Up

-- Registration: the admin UI lists waiting devices, so keep where they came from.
ALTER TABLE registration_requests ADD COLUMN ip inet;
CREATE INDEX registration_requests_pending ON registration_requests (created_at) WHERE status = 'pending';

-- Developer builds (CONFIG_ZIR_DEV_BUILD): stored unsigned, delivered only to
-- developer devices, encrypted with the device's K_ota.
ALTER TABLE builds DROP CONSTRAINT builds_kind_check;
ALTER TABLE builds ADD CONSTRAINT builds_kind_check CHECK (kind IN ('app','www','bootstrap','dev_app'));

-- Developer device: the flag is in the signed config ("dev": true); it lets the
-- device accept unsigned images from the server. Set only by superadmin.
ALTER TABLE devices
  ADD COLUMN dev_mode     bool NOT NULL DEFAULT false,
  ADD COLUMN dev_build_id uuid REFERENCES builds,
  ADD COLUMN dev_critical bool NOT NULL DEFAULT false,
  ADD COLUMN dev_assigned_at timestamptz;

ALTER TABLE update_events ADD COLUMN build_id uuid REFERENCES builds;

-- API tokens for lcmctl push-dev (CI, PlatformIO). Only the hash is stored.
-- The token acts as its user with the user's current roles.
CREATE TABLE api_tokens (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid NOT NULL REFERENCES users ON DELETE CASCADE,
  name         text NOT NULL,
  token_hash   bytea NOT NULL UNIQUE,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  last_used_at timestamptz,
  last_ip      inet,
  revoked_at   timestamptz
);

-- +goose Down
DROP TABLE api_tokens;
ALTER TABLE update_events DROP COLUMN build_id;
ALTER TABLE devices DROP COLUMN dev_assigned_at, DROP COLUMN dev_critical, DROP COLUMN dev_build_id, DROP COLUMN dev_mode;
DELETE FROM builds WHERE kind = 'dev_app';
ALTER TABLE builds DROP CONSTRAINT builds_kind_check;
ALTER TABLE builds ADD CONSTRAINT builds_kind_check CHECK (kind IN ('app','www','bootstrap'));
DROP INDEX registration_requests_pending;
ALTER TABLE registration_requests DROP COLUMN ip;

-- +goose Up

-- Ключи сервера. Приватные части зашифрованы мастер-ключом (envelope, aad "server_key:<kid>").
CREATE TABLE server_keys (
  kid          text PRIMARY KEY,
  purpose      text NOT NULL CHECK (purpose IN ('fw_sign','manifest','config','engtoken','www','telemetry')),
  alg          text NOT NULL CHECK (alg IN ('RSA-3072','P-256')),
  private_enc  bytea NOT NULL,
  public_der   bytea NOT NULL,
  active       bool NOT NULL DEFAULT true,
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX server_keys_active ON server_keys (purpose) WHERE active;

-- Пользователи и доступ
CREATE TABLE users (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  login           text NOT NULL UNIQUE,
  display_name    text NOT NULL DEFAULT '',
  password_hash   text NOT NULL,
  totp_secret_enc bytea,
  totp_enabled    bool NOT NULL DEFAULT false,
  status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  revoked_at      timestamptz, revoked_by uuid, revoke_reason text,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE user_roles (
  user_id uuid NOT NULL REFERENCES users ON DELETE CASCADE,
  role    text NOT NULL CHECK (role IN ('superadmin','admin','manufacturer','engineer')),
  PRIMARY KEY (user_id, role)
);
CREATE TABLE web_sessions (
  id_hash      bytea PRIMARY KEY,
  user_id      uuid NOT NULL REFERENCES users ON DELETE CASCADE,
  csrf         text NOT NULL,
  totp_ok      bool NOT NULL DEFAULT false,      -- второй фактор пройден
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  ip inet, user_agent text
);
CREATE TABLE recovery_codes (
  user_id   uuid NOT NULL REFERENCES users ON DELETE CASCADE,
  code_hash text NOT NULL,
  used_at   timestamptz
);
CREATE TABLE login_failures (
  login text NOT NULL,
  at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX login_failures_login_at ON login_failures (login, at);

-- Профили железа
CREATE TABLE hw_profiles (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code          text NOT NULL UNIQUE,
  name          text NOT NULL,
  description   text NOT NULL DEFAULT '',
  params_schema jsonb NOT NULL,
  default_params jsonb NOT NULL,
  active        bool NOT NULL DEFAULT true,
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- Регистрация
CREATE TABLE registration_requests (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  claim_code        text NOT NULL UNIQUE,
  mac               macaddr NOT NULL,
  chip_rev          text NOT NULL DEFAULT '',
  bootstrap_version text NOT NULL DEFAULT '',
  dev_sign_pub      bytea NOT NULL,
  dev_kex_pub       bytea NOT NULL,
  web_password_enc  bytea NOT NULL,
  status            text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','expired')),
  created_at        timestamptz NOT NULL DEFAULT now(),
  expires_at        timestamptz NOT NULL,
  approved_by       uuid REFERENCES users,
  device_id         uuid,
  result            jsonb                          -- ответ устройству после подтверждения
);
CREATE TABLE claim_failures (
  user_id uuid NOT NULL,
  at      timestamptz NOT NULL DEFAULT now()
);

-- Устройства
CREATE SEQUENCE device_serial_seq START 1;
CREATE TABLE devices (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  serial             text NOT NULL UNIQUE,
  mac                macaddr NOT NULL UNIQUE,
  chip_rev           text NOT NULL DEFAULT '',
  profile_id         uuid NOT NULL REFERENCES hw_profiles,
  status             text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  security_level     text NOT NULL DEFAULT 'L0',
  dev_sign_pub       bytea NOT NULL,
  dev_kex_pub        bytea NOT NULL,
  ota_key_enc        bytea NOT NULL,
  ota_pub_der        bytea NOT NULL,
  flash_key_enc      bytea,
  web_password_enc   bytea,
  web_password_changed_at timestamptz,
  is_test            bool NOT NULL DEFAULT false,
  pinned             bool NOT NULL DEFAULT false,
  pending_release_id uuid,
  current_release_id uuid,
  current_version    text,
  current_app_sha256 bytea,
  current_www_sha256 bytea,
  config_version     int NOT NULL DEFAULT 0,
  registered_by      uuid REFERENCES users,
  registered_at      timestamptz NOT NULL DEFAULT now(),
  last_seen_at       timestamptz,
  last_ip            inet,
  revoked_at timestamptz, revoked_by uuid, revoke_reason text
);
CREATE TABLE device_sessions (
  token_hash bytea PRIMARY KEY,
  device_id  uuid NOT NULL REFERENCES devices ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  ip         inet
);
CREATE TABLE device_challenges (
  nonce      bytea PRIMARY KEY,
  device_id  uuid NOT NULL REFERENCES devices ON DELETE CASCADE,
  expires_at timestamptz NOT NULL
);

-- Конфиги (вся история)
CREATE TABLE device_configs (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id   uuid NOT NULL REFERENCES devices ON DELETE CASCADE,
  version     int NOT NULL,
  hard_params jsonb NOT NULL,
  signed_blob text NOT NULL,
  created_by  uuid REFERENCES users,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (device_id, version)
);

-- Сборки и релизы
CREATE TABLE builds (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind            text NOT NULL CHECK (kind IN ('app','www','bootstrap')),
  source          text NOT NULL DEFAULT 'upload' CHECK (source IN ('upload','github')),
  profile_id      uuid REFERENCES hw_profiles,
  repo text, git_ref text, commit_sha text,
  version         text NOT NULL,
  www_api         int,
  status          text NOT NULL CHECK (status IN ('queued','running','success','failed')),
  log_path        text,
  artifact_path   text,             -- app/bootstrap: подписанный образ; www: www.tar
  elf_path        text,
  zwww_path       text,
  sha256          bytea,            -- app: хеш подписанного образа; www: хеш www.tar
  size            int,
  comparable_hash bytea,
  signed_at       timestamptz,
  created_by      uuid REFERENCES users,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE releases (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  version      text NOT NULL UNIQUE,
  channel      text NOT NULL DEFAULT 'beta' CHECK (channel IN ('beta','stable')),
  critical     bool NOT NULL DEFAULT false,
  www_build_id uuid REFERENCES builds,
  notes        text NOT NULL DEFAULT '',
  created_by   uuid REFERENCES users,
  created_at   timestamptz NOT NULL DEFAULT now(),
  promoted_by  uuid REFERENCES users,
  promoted_at  timestamptz
);
CREATE TABLE release_apps (
  release_id   uuid NOT NULL REFERENCES releases ON DELETE CASCADE,
  profile_id   uuid NOT NULL REFERENCES hw_profiles,
  app_build_id uuid NOT NULL REFERENCES builds,
  PRIMARY KEY (release_id, profile_id)
);
ALTER TABLE devices ADD FOREIGN KEY (pending_release_id) REFERENCES releases;
ALTER TABLE devices ADD FOREIGN KEY (current_release_id) REFERENCES releases;

CREATE TABLE update_events (
  id          bigserial PRIMARY KEY,
  device_id   uuid NOT NULL REFERENCES devices ON DELETE CASCADE,
  release_id  uuid REFERENCES releases,
  initiator   text CHECK (initiator IN ('user','engineer','critical')),
  engineer_id uuid,
  status      text NOT NULL CHECK (status IN ('offered','downloading','installed','failed','rolled_back')),
  details     jsonb,
  at          timestamptz NOT NULL DEFAULT now()
);

-- Инженерный доступ (после MVP)
CREATE TABLE engineer_tokens (
  jti uuid PRIMARY KEY, engineer_id uuid NOT NULL, device_id uuid NOT NULL, nonce bytea NOT NULL,
  issued_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, confirmed_at timestamptz
);

-- Телеметрия
CREATE TABLE telemetry (
  id          bigserial PRIMARY KEY,
  device_id   uuid NOT NULL REFERENCES devices ON DELETE CASCADE,
  seq         bigint NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  device_time timestamptz,
  payload     jsonb NOT NULL,
  UNIQUE (device_id, seq)
);
CREATE TABLE device_counters (
  device_id uuid PRIMARY KEY REFERENCES devices ON DELETE CASCADE,
  last_seq  bigint NOT NULL DEFAULT 0,
  max_on_s  bigint NOT NULL DEFAULT 0,
  last_on_s bigint NOT NULL DEFAULT 0
);
CREATE TABLE coredumps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id uuid NOT NULL REFERENCES devices ON DELETE CASCADE,
  release_id uuid, app_sha256 bytea, path text NOT NULL, size int NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE anomalies (
  id          bigserial PRIMARY KEY,
  device_id   uuid REFERENCES devices ON DELETE CASCADE,
  type        text NOT NULL,
  details     jsonb,
  at          timestamptz NOT NULL DEFAULT now(),
  resolved_by uuid, resolved_at timestamptz
);

-- Аудит (только дописывается; права роли БД — в deploy/)
CREATE TABLE audit_log (
  id          bigserial PRIMARY KEY,
  at          timestamptz NOT NULL DEFAULT now(),
  actor_type  text NOT NULL CHECK (actor_type IN ('user','device','system')),
  actor_id    uuid,
  action      text NOT NULL,
  target_type text,
  target_id   uuid,
  details     jsonb,
  ip          inet
);

-- +goose Down
DROP TABLE audit_log, anomalies, coredumps, device_counters, telemetry, engineer_tokens,
  update_events, release_apps, releases, builds, device_configs, device_challenges,
  device_sessions, devices, claim_failures, registration_requests, hw_profiles,
  login_failures, recovery_codes, web_sessions, user_roles, users, server_keys CASCADE;
DROP SEQUENCE device_serial_seq;

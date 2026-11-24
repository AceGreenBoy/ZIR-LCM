-- +goose Up

-- A developer build may carry its own web UI (www.tar, unsigned, never put in
-- a release): a 'dev_www' build referenced by the 'dev_app' build.
ALTER TABLE builds DROP CONSTRAINT builds_kind_check;
ALTER TABLE builds ADD CONSTRAINT builds_kind_check CHECK (kind IN ('app','www','bootstrap','dev_app','dev_www'));
ALTER TABLE builds ADD COLUMN www_build_id uuid REFERENCES builds;

-- +goose Down
ALTER TABLE builds DROP COLUMN www_build_id;
DELETE FROM builds WHERE kind = 'dev_www';
ALTER TABLE builds DROP CONSTRAINT builds_kind_check;
ALTER TABLE builds ADD CONSTRAINT builds_kind_check CHECK (kind IN ('app','www','bootstrap','dev_app'));

-- +goose Up

-- The web UI assigned to a developer device, separately from the firmware: a
-- dev_www build. Assigning a dev build sets it to the build's own www (or
-- NULL); a web UI pushed alone sets only this and keeps the device's firmware.
ALTER TABLE devices ADD COLUMN dev_www_build_id uuid REFERENCES builds;
UPDATE devices d SET dev_www_build_id = b.www_build_id FROM builds b WHERE b.id = d.dev_build_id;

-- +goose Down
ALTER TABLE devices DROP COLUMN dev_www_build_id;

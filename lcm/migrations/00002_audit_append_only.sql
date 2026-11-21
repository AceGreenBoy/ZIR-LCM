-- +goose Up
-- The audit log is append-only even for the table owner: UPDATE, DELETE and
-- TRUNCATE are rejected by triggers.
-- +goose StatementBegin
CREATE FUNCTION audit_log_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END $$;
-- +goose StatementEnd
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
  FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();

-- +goose Down
DROP TRIGGER audit_log_no_truncate ON audit_log;
DROP TRIGGER audit_log_no_update ON audit_log;
DROP FUNCTION audit_log_immutable();

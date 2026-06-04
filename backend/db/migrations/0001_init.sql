-- 0001_init.sql
-- Schema for the Tenex.ai take-home log analyzer.
-- We use TIMESTAMPTZ everywhere (always UTC at the DB layer) and INET for IP columns
-- so Postgres can validate them. UUID upload IDs let the client/server generate IDs
-- independently without colliding.

CREATE TABLE IF NOT EXISTS users (
  id            SERIAL PRIMARY KEY,
  username      TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS uploads (
  id           UUID PRIMARY KEY,
  user_id      INT NOT NULL REFERENCES users(id),
  filename     TEXT NOT NULL,
  total_rows   INT NOT NULL,
  parsed_rows  INT NOT NULL,
  uploaded_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS log_entries (
  id              BIGSERIAL PRIMARY KEY,
  upload_id       UUID NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
  ts              TIMESTAMPTZ NOT NULL,
  username        TEXT,
  src_ip          INET,
  dst_ip          INET,
  url             TEXT,
  url_category    TEXT,
  action          TEXT,
  threat_name     TEXT,
  threat_category TEXT,
  bytes_in        BIGINT,
  bytes_out       BIGINT,
  user_agent      TEXT,
  referer         TEXT
);
CREATE INDEX IF NOT EXISTS log_entries_upload_idx ON log_entries(upload_id);
CREATE INDEX IF NOT EXISTS log_entries_ts_idx     ON log_entries(upload_id, ts);

CREATE TABLE IF NOT EXISTS anomalies (
  id            BIGSERIAL PRIMARY KEY,
  upload_id     UUID NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
  log_entry_id  BIGINT REFERENCES log_entries(id) ON DELETE CASCADE,
  rule_name     TEXT NOT NULL,
  explanation   TEXT NOT NULL,
  confidence    REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1)
);
CREATE INDEX IF NOT EXISTS anomalies_upload_idx ON anomalies(upload_id);
CREATE INDEX IF NOT EXISTS anomalies_entry_idx  ON anomalies(log_entry_id);

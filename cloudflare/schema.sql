CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions (expires);
CREATE TABLE IF NOT EXISTS login_failures (ip_hash TEXT PRIMARY KEY, attempts INTEGER NOT NULL, first_attempt INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  url TEXT NOT NULL UNIQUE,
  permission TEXT NOT NULL,
  valid_until TEXT NOT NULL,
  created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  target_id INTEGER NOT NULL,
  url TEXT NOT NULL,
  tools TEXT NOT NULL,
  mode TEXT NOT NULL,
  status TEXT NOT NULL,
  started INTEGER NOT NULL,
  updated INTEGER NOT NULL,
  run_id INTEGER,
  report TEXT,
  error TEXT,
  last_synced INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY(target_id) REFERENCES targets(id)
);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

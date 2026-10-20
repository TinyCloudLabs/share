CREATE TABLE IF NOT EXISTS note_index (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  summary TEXT
);

CREATE INDEX IF NOT EXISTS idx_note_index_updated_at
  ON note_index(updated_at);

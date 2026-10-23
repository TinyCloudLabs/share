CREATE TABLE links (
  id TEXT PRIMARY KEY,
  ciphertext BLOB NOT NULL,
  cid TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  delete_hash TEXT NOT NULL,
  size INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  deleted_at INTEGER
);

CREATE INDEX links_expires ON links(expires_at);

CREATE TABLE rl (
  k TEXT PRIMARY KEY,
  n INTEGER NOT NULL,
  exp INTEGER NOT NULL
);

CREATE INDEX rl_exp ON rl(exp);

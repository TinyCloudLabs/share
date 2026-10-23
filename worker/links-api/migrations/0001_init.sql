-- links API storage (contract section 9.1). The same file is applied to D1 and to the self-host SQLite file.

CREATE TABLE links (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  issuer TEXT NOT NULL,
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  size INTEGER NOT NULL,
  body_cid TEXT NOT NULL,
  header_jcs TEXT NOT NULL,
  signature TEXT,
  body BLOB NOT NULL,
  address_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX links_expires ON links(expires_at);
CREATE INDEX links_type_live ON links(type, expires_at, size);
CREATE INDEX links_address_live ON links(address_hash, expires_at, size);

CREATE TABLE rl (
  k TEXT PRIMARY KEY,
  n INTEGER NOT NULL,
  exp INTEGER NOT NULL
);

CREATE INDEX rl_exp ON rl(exp);

CREATE TABLE nonces (
  scope TEXT NOT NULL,
  nonce_hash TEXT NOT NULL,
  exp INTEGER NOT NULL,
  PRIMARY KEY (scope, nonce_hash)
);

CREATE INDEX nonces_exp ON nonces(exp);

CREATE TABLE blocked (
  kind TEXT NOT NULL,
  key TEXT NOT NULL,
  since INTEGER NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (kind, key)
);

CREATE TABLE api_keys (
  key_id TEXT PRIMARY KEY,
  service TEXT NOT NULL,
  allowed_types TEXT NOT NULL,
  secret_sha256 TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE TABLE metrics (
  name TEXT PRIMARY KEY,
  n INTEGER NOT NULL
);

CREATE TABLE usage_daily (
  day TEXT NOT NULL,
  metric TEXT NOT NULL,
  n INTEGER NOT NULL DEFAULT 0,
  alerted INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, metric)
);

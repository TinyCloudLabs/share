-- One row per delivery authorization. `idempotency_key` is the Node's `jti`,
-- which the Node itself already refuses to reissue, so the primary key is the
-- replay boundary on both sides.
--
-- No mailbox address, share URL or document name is stored: `recipient_digest`
-- is SHA-256(lowercased address), base64url, which answers "did this delivery
-- happen" without making this table a PII store.
CREATE TABLE IF NOT EXISTS share_email_deliveries (
  idempotency_key    TEXT PRIMARY KEY,
  share_cid          TEXT NOT NULL,
  recipient_digest   TEXT NOT NULL,
  status             TEXT NOT NULL CHECK (status IN ('pending', 'sent', 'failed')),
  provider_message_id TEXT,
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS share_email_deliveries_created_at
  ON share_email_deliveries (created_at);

---
type: TinyCloud App
title: Notes
description: Notes with KV documents and SQLite search metadata.
tinycloud:
  app: com.example.notes
  profile: tinycloud.app.v1
  containsSecretValue: false
---

# Notes

Notes stores user-authored documents in KV and derived search metadata in one
SQLite database.

## Resources

- [KV](kv.md) - Note documents under `documents/*`.
- [SQL](sql.md) - Search metadata in `main`.
- [Secrets](secrets.md) - Optional model provider key.
- [Operations](operations.md) - Install and repair notes.

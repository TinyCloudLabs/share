---
type: TinyCloud SQL
title: SQL
description: SQLite search metadata.
tinycloud:
  app: com.example.notes
  service: sql
  profile: tinycloud.app.v1
  sensitivity: derived
  containsSecretValue: false
---

# SQL

Database: `main`

Engine: SQLite

Purpose: Stores derived search and summary metadata for notes.

Setup: Apply migrations with `tc.sql.db("main").migrations.apply(...)` before
serving user traffic.

Required capabilities:

| Capability | Why |
| --- | --- |
| `tinycloud.sql/read` | Read search metadata. |
| `tinycloud.sql/write` | Update derived index rows. |
| `tinycloud.sql/schema` | Apply schema migrations. |

## Tables

| Table | Purpose | Agent Notes |
| --- | --- | --- |
| `note_index` | Search metadata for KV note documents. | Can be rebuilt from KV documents. |

## Migrations

| Migration | Purpose |
| --- | --- |
| `001_initial_note_index` | Create the rebuildable note search index. |

## Schema

```sql
CREATE TABLE IF NOT EXISTS note_index (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  summary TEXT
);
```

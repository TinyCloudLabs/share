---
type: TinyCloud Operations
title: Operations
description: Install and repair notes.
tinycloud:
  app: com.example.notes
  service: operations
  profile: tinycloud.app.v1
  containsSecretValue: false
---

# Operations

## Install

1. Validate `manifest.json`.
2. Apply migrations to the `main` SQLite database.
3. Create KV documents lazily when users save notes.

Do not run cold DDL in request paths. Use migrations during install, startup, or
app registration, then use cheap readiness checks.

## Repair

The SQL index is derived from KV documents. If the index is corrupt, rebuild it
from `documents/*`.

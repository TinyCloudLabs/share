---
type: TinyCloud KV
title: KV
description: Note document keyspaces.
tinycloud:
  app: com.example.notes
  service: kv
  profile: tinycloud.app.v1
  sensitivity: user-data
  containsSecretValue: false
---

# KV

## Documents

Prefix: `documents/*`

Purpose: User-authored note documents.

Agent notes:

- Preserve unknown JSON fields.
- Do not delete documents unless the user explicitly asks.

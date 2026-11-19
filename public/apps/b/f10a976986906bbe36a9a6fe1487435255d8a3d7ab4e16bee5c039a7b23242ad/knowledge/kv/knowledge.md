---
type: "KV Prefix"
title: knowledge/
description: "Read and update the app's knowledge bundle so an agent can pick up where you left off."
resource: tinycloud.kv:applications:xyz.tinycloud.sample.healthlog/knowledge/
generated: { by: tinycloud-app-kit/okf }
tinycloud:
  app: xyz.tinycloud.sample.healthlog
  service: kv
  profile: tinycloud.app.v1
  containsSecretValue: false
---

Read and update the app's knowledge bundle so an agent can pick up where you left off.

# Keys

Every key beginning with `xyz.tinycloud.sample.healthlog/knowledge/` in space `applications`.

This is where this knowledge bundle itself lives in your space.

# Access

The manifest grants `get`, `put`, `list`.

<!-- keep -->
| Key | Description |
| --- | --- |
| `knowledge/index.md` | Entry point: links only. |
| `knowledge/app.md` | What the app is and the rules for operating it. |
| `knowledge/tables/*.md`, `knowledge/views/*.md`, `knowledge/kv/*.md` | One concept per table, view and KV prefix. |
| `knowledge/log.md` | Dated change history. |

Keep it true: when you change a table, a prefix or the rules in `app.md`, update the concept and add a `log.md` entry.
<!-- /keep -->

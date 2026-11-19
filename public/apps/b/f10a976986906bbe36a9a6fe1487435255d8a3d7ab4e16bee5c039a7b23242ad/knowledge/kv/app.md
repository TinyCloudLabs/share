---
type: "KV Prefix"
title: app/
description: "Read the installed copy of the app (schema)."
resource: tinycloud.kv:applications:xyz.tinycloud.sample.healthlog/app/
generated: { by: tinycloud-app-kit/okf }
tinycloud:
  app: xyz.tinycloud.sample.healthlog
  service: kv
  profile: tinycloud.app.v1
  containsSecretValue: false
---

Read the installed copy of the app (schema). The app cannot change its own code.

# Keys

Every key beginning with `xyz.tinycloud.sample.healthlog/app/` in space `applications`.

# Access

The manifest grants `get`. This app only reads here: do not write to it.

<!-- keep -->
| Key | Description |
| --- | --- |
| `app/app.jsx` | The app's code (React + recharts + Tailwind). |
| `app/manifest.json` | The manifest the runner signs. Changing it can widen what the app may do; the user sees and approves it. |
| `app/schema.sql` | Idempotent DDL. The app runs it on first open if the tables are missing. |
| `app/release.json` | File list with sha256 of the shipped bundle. |

Install writes this prefix create-only, so a reinstall never overwrites the user's own edits. The app itself cannot
write here. The user's agent may rewrite these files when the user asks; afterwards update the affected concepts and
add an entry to `log.md`.
<!-- /keep -->

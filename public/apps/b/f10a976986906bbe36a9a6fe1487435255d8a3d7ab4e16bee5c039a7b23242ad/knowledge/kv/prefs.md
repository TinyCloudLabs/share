---
type: "KV Prefix"
title: prefs/
description: "Read and change the app's settings (daily calorie target)."
resource: tinycloud.kv:applications:xyz.tinycloud.sample.healthlog/prefs/
generated: { by: tinycloud-app-kit/okf }
tinycloud:
  app: xyz.tinycloud.sample.healthlog
  service: kv
  profile: tinycloud.app.v1
  containsSecretValue: false
---

Read and change the app's settings (daily calorie target).

# Keys

Every key beginning with `xyz.tinycloud.sample.healthlog/prefs/` in space `applications`.

# Access

The manifest grants `get`, `put`.

<!-- keep -->
| Key | Content type | Description |
| --- | --- | --- |
| `prefs/goals.json` | application/json | `{"kcal": <integer 500..10000>}`: the daily calorie target shown on the today card. Absent means 2000. |

Preserve unknown JSON fields when editing.
<!-- /keep -->

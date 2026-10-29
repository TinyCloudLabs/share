---
type: "KV Prefix"
title: settings/
description: "Save your timezone when you open the app, so an agent logging meals for you uses your day."
resource: tinycloud.kv:applications:xyz.tinycloud.sample.healthlog/settings/
generated: { by: tinycloud-app-kit/okf }
tinycloud:
  app: xyz.tinycloud.sample.healthlog
  service: kv
  profile: tinycloud.app.v1
  containsSecretValue: false
---

Save your timezone when you open the app, so an agent logging meals for you uses your day.

# Keys

Every key beginning with `xyz.tinycloud.sample.healthlog/settings/` in space `applications`.

# Access

The manifest grants `get`, `put`.

<!-- keep -->
| Key | Content type | Description |
| --- | --- | --- |
| `settings/timezone` | text/plain | The owner's IANA timezone, for example `Pacific/Kiritimati`. The page writes it each time it opens. |
<!-- /keep -->

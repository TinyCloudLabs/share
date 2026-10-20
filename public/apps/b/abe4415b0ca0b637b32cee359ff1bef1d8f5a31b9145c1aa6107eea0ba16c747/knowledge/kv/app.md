---
type: "KV Prefix"
title: app/
description: "Read the installed copy of the app's schema."
resource: tinycloud.kv:applications:xyz.tinycloud.sample.recipes/app/
generated: { by: tinycloud-app-kit/okf }
tinycloud:
  app: xyz.tinycloud.sample.recipes
  service: kv
  profile: tinycloud.app.v1
  containsSecretValue: false
---

Read the installed copy of the app's schema. The app cannot change its own code.

# Keys

Every key beginning with `xyz.tinycloud.sample.recipes/app/` in space `applications`.

# Access

The manifest grants `get`. This app only reads here: do not write to it.

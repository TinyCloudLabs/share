---
type: "KV Prefix"
title: knowledge/
description: "Read and update the app's knowledge bundle so an agent can pick up where you left off."
resource: tinycloud.kv:applications:xyz.tinycloud.sample.recipes/knowledge/
generated: { by: tinycloud-app-kit/okf }
tinycloud:
  app: xyz.tinycloud.sample.recipes
  service: kv
  profile: tinycloud.app.v1
  containsSecretValue: false
---

Read and update the app's knowledge bundle so an agent can pick up where you left off.

# Keys

Every key beginning with `xyz.tinycloud.sample.recipes/knowledge/` in space `applications`.

This is where this knowledge bundle itself lives in your space.

# Access

The manifest grants `get`, `put`, `list`.

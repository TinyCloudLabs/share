---
type: "KV Prefix"
title: prefs/
description: "Read and change the app's one settings file (sort order, last shelf)."
resource: tinycloud.kv:applications:xyz.tinycloud.sample.recipes/prefs/
generated: { by: tinycloud-app-kit/okf }
tinycloud:
  app: xyz.tinycloud.sample.recipes
  service: kv
  profile: tinycloud.app.v1
  containsSecretValue: false
---

Read and change the app's one settings file (sort order, last shelf).

# Keys

Every key beginning with `xyz.tinycloud.sample.recipes/prefs/` in space `applications`.

# Access

The manifest grants `get`, `put`.

<!-- keep -->
## Keys in use

* `prefs/ui.json`: JSON `{"sort": "updated" | "title", "shelf": "<shelf id>" | null}`. `sort` is how the recipe list is ordered; `shelf` is the shelf the list is filtered to (null: all recipes). It is only a view setting: nothing else reads it, and it is safe to delete.
<!-- /keep -->

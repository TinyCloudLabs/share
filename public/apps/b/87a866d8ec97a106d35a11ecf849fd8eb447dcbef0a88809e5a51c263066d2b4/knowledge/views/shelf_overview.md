---
type: "SQLite View"
title: shelf_overview
description: "One row per shelf with the number of recipes on it."
resource: tinycloud.sql:applications:xyz.tinycloud.sample.recipes/recipes
view: shelf_overview
generated: { by: tinycloud-app-kit/okf }
tinycloud:
  app: xyz.tinycloud.sample.recipes
  service: sql
  profile: tinycloud.app.v1
  containsSecretValue: false
---

One row per shelf with the number of recipes on it.

View `shelf_overview` in SQLite database `xyz.tinycloud.sample.recipes/recipes` (space `applications`).

# Schema

| Column |
| --- |
| `id` |
| `name` |
| `description` |
| `position` |
| `recipe_count` |

# Reads

* [recipe_shelf](/tables/recipe_shelf.md)
* [shelf](/tables/shelf.md)

# Definition

```sql
CREATE VIEW IF NOT EXISTS shelf_overview AS
SELECT
  s.id AS id,
  s.name AS name,
  s.description AS description,
  s.position AS position,
  (SELECT COUNT(*) FROM recipe_shelf rs WHERE rs.shelf_id = s.id) AS recipe_count
FROM shelf s
```

# Access

Query it with the `read` action; the manifest grants `read`, `write`, `schema`.

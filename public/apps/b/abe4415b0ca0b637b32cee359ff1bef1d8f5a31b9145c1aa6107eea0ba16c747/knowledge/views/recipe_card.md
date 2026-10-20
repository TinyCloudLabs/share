---
type: "SQLite View"
title: recipe_card
description: "One row per recipe with its shelf and linked-meal counts; the list screen reads this."
resource: tinycloud.sql:applications:xyz.tinycloud.sample.recipes/recipes
view: recipe_card
generated: { by: tinycloud-app-kit/okf }
tinycloud:
  app: xyz.tinycloud.sample.recipes
  service: sql
  profile: tinycloud.app.v1
  containsSecretValue: false
---

One row per recipe with its shelf and linked-meal counts; the list screen reads this.

View `recipe_card` in SQLite database `xyz.tinycloud.sample.recipes/recipes` (space `applications`).

# Schema

| Column |
| --- |
| `id` |
| `title` |
| `origin` |
| `summary` |
| `servings` |
| `kcal` |
| `protein_g` |
| `carbs_g` |
| `fat_g` |
| `favorite` |
| `updated_at` |
| `shelf_count` |
| `meal_count` |

# Reads

* [recipe_shelf](/tables/recipe_shelf.md)
* [meal_link](/tables/meal_link.md)
* [recipe](/tables/recipe.md)

# Definition

```sql
CREATE VIEW IF NOT EXISTS recipe_card AS
SELECT
  r.id AS id,
  r.title AS title,
  r.origin AS origin,
  r.summary AS summary,
  r.servings AS servings,
  r.kcal AS kcal,
  r.protein_g AS protein_g,
  r.carbs_g AS carbs_g,
  r.fat_g AS fat_g,
  r.favorite AS favorite,
  r.updated_at AS updated_at,
  (SELECT COUNT(*) FROM recipe_shelf rs WHERE rs.recipe_id = r.id) AS shelf_count,
  (SELECT COUNT(*) FROM meal_link ml WHERE ml.recipe_id = r.id) AS meal_count
FROM recipe r
```

# Access

Query it with the `read` action; the manifest grants `read`, `write`, `schema`.

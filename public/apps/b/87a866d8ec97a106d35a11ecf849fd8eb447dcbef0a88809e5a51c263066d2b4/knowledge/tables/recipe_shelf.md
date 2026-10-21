---
type: "SQLite Table"
title: recipe_shelf
description: "Which recipes are on which shelf (many to many)."
resource: tinycloud.sql:applications:xyz.tinycloud.sample.recipes/recipes
table: recipe_shelf
generated: { by: tinycloud-app-kit/okf }
tinycloud:
  app: xyz.tinycloud.sample.recipes
  service: sql
  profile: tinycloud.app.v1
  containsSecretValue: false
---

Which recipes are on which shelf (many to many). Deleting a shelf removes only its rows here.

Table `recipe_shelf` in SQLite database `xyz.tinycloud.sample.recipes/recipes` (space `applications`).

# Schema

| Column | Type | Constraints | Description |
| --- | --- | --- | --- |
| `recipe_id` | TEXT | part of primary key; not null; references [recipe](/tables/recipe.md) `(id)` on delete cascade | - |
| `shelf_id` | TEXT | part of primary key; not null; references [shelf](/tables/shelf.md) `(id)` on delete cascade | - |
| `added_at` | TEXT | not null | - |

# Table constraints

* Primary key: `(recipe_id, shelf_id)`

# Indexes

* `idx_recipe_shelf_shelf` on `(shelf_id)`

# Read by views

* [recipe_card](/views/recipe_card.md)
* [shelf_overview](/views/shelf_overview.md)

# Access

The manifest grants `read`, `write`, `schema`.

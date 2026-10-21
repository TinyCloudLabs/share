---
type: "SQLite Table"
title: meal_link
description: "Links a recipe to a meal in the Health Log sample (app xyz.tinycloud.sample.healthlog, database healthlog, table meal)."
resource: tinycloud.sql:applications:xyz.tinycloud.sample.recipes/recipes
table: meal_link
generated: { by: tinycloud-app-kit/okf }
tinycloud:
  app: xyz.tinycloud.sample.recipes
  service: sql
  profile: tinycloud.app.v1
  containsSecretValue: false
---

Links a recipe to a meal in the Health Log sample (app xyz.tinycloud.sample.healthlog, database healthlog, table meal). This app only reads that table; the link lives here, never there. The meal_* columns are a snapshot taken at link time so the list renders without reading the other app.

Table `meal_link` in SQLite database `xyz.tinycloud.sample.recipes/recipes` (space `applications`).

# Schema

| Column | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | TEXT | primary key | lnk_ + time + random |
| `recipe_id` | TEXT | not null; references [recipe](/tables/recipe.md) `(id)` on delete cascade | - |
| `health_meal_id` | INTEGER | not null | meal.id in the Health Log database; may point at a meal that was later deleted there |
| `meal_day` | TEXT | - | snapshot of meal.day (YYYY-MM-DD) |
| `meal_name` | TEXT | - | snapshot of meal.name |
| `meal_kcal` | INTEGER | - | snapshot of meal.kcal |
| `created_at` | TEXT | not null | - |

# Table constraints

* Unique: `(recipe_id, health_meal_id)`

# Indexes

* `idx_meal_link_meal` on `(health_meal_id)`

# Read by views

* [recipe_card](/views/recipe_card.md)

# Access

The manifest grants `read`, `write`, `schema`.

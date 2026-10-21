---
type: "SQLite Table"
title: recipe
description: "A recipe."
resource: tinycloud.sql:applications:xyz.tinycloud.sample.recipes/recipes
table: recipe
generated: { by: tinycloud-app-kit/okf }
tinycloud:
  app: xyz.tinycloud.sample.recipes
  service: sql
  profile: tinycloud.app.v1
  containsSecretValue: false
---

A recipe. Nutrition is per serving and optional; when any nutrition number is set, nutrition_basis says where it came from.

Table `recipe` in SQLite database `xyz.tinycloud.sample.recipes/recipes` (space `applications`).

# Schema

| Column | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | TEXT | primary key | rcp_ + time + random, made by the app |
| `title` | TEXT | not null; check `length(title) BETWEEN 1 AND 200` | - |
| `origin` | TEXT | not null; default `'own'`; one of `own`, `adapted`, `from_meal` | own: written by the user; adapted: changed from someone else's; from_meal: started from a Health Log meal |
| `summary` | TEXT | check `summary IS NULL OR length(summary) <= 1000` | one or two lines shown on the list card |
| `servings` | REAL | not null; default `1`; check `servings > 0 AND servings <= 1000` | - |
| `prep_min` | INTEGER | check `prep_min IS NULL OR prep_min BETWEEN 0 AND 10080` | one week, in minutes |
| `cook_min` | INTEGER | check `cook_min IS NULL OR cook_min BETWEEN 0 AND 10080` | - |
| `ingredients_json` | TEXT | not null; default `'[]'`; check `length(ingredients_json) <= 100000` | JSON array of {"qty": "200 g", "item": "flour"}; qty is free text and may be empty |
| `steps_json` | TEXT | not null; default `'[]'`; check `length(steps_json) <= 100000` | JSON array of strings, one per step, in order |
| `kcal` | INTEGER | check `kcal IS NULL OR kcal BETWEEN 0 AND 5000` | per serving; NULL: not entered |
| `protein_g` | REAL | check `protein_g IS NULL OR protein_g BETWEEN 0 AND 10000` | per serving |
| `carbs_g` | REAL | check `carbs_g IS NULL OR carbs_g BETWEEN 0 AND 10000` | per serving |
| `fat_g` | REAL | check `fat_g IS NULL OR fat_g BETWEEN 0 AND 10000` | per serving |
| `nutrition_basis` | TEXT | check `nutrition_basis IS NULL OR nutrition_basis IN ('label', 'estimate', 'copied_from_meal')` | label: read off a package; estimate: the user's guess; copied_from_meal: copied from a Health Log meal |
| `favorite` | INTEGER | not null; default `0`; one of `0`, `1` | - |
| `created_at` | TEXT | not null | ISO 8601 UTC |
| `updated_at` | TEXT | not null | ISO 8601 UTC; the list sorts by this |

# Indexes

* `idx_recipe_updated` on `(updated_at)`

# Read by views

* [recipe_card](/views/recipe_card.md)

# Access

The manifest grants `read`, `write`, `schema`.

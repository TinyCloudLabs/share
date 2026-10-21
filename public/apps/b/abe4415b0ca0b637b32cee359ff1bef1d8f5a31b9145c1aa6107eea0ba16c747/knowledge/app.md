---
type: "TinyCloud App"
title: "Recipes (sample)"
description: "A small recipe book."
generated: { by: tinycloud-app-kit/okf }
tinycloud: { app: xyz.tinycloud.sample.recipes, profile: tinycloud.app.v1, containsSecretValue: false }
---

A small recipe book: shelves, recipes, and recipes started from a meal in the Health Log sample. Sample tiny app, written from scratch for TinyCloud.

# What it holds

* One SQLite database, `xyz.tinycloud.sample.recipes/recipes`: `recipe`, `shelf`, `recipe_shelf` (which recipe is on which shelf) and `meal_link` (which Health Log meal a recipe was started from). The `recipe_card` and `shelf_overview` views are what the screens read.
* Settings in KV under `prefs/`. The installed app (`app.jsx`, `manifest.json`, `schema.sql`) is under `app/`.
* It has read access to the whole Health Log database (`xyz.tinycloud.sample.healthlog/healthlog`): meals (`meal`), body weight (`weight`) and the daily summary views (`day_card`, `week_rollup`). SQL grants are per database, not per table, so all of that is readable. The app only queries `meal` and never touches the rest. That is another app's data and this app has read access only.

# Working rules

* Ids are text the writer makes up with a prefix: `rcp_`, `shf_`, `lnk_`, then the time in base 36 and a few random characters. Reusing an id never creates a second row.
* Set `created_at` and `updated_at` as ISO 8601 UTC text. Set `updated_at` on every change to a recipe: the list is sorted by it.
* `ingredients_json` is a JSON array of `{"qty": "200 g", "item": "flour"}` (`qty` is free text and may be empty). `steps_json` is a JSON array of strings in order. Both default to `[]`.
* Nutrition is per serving. If you set any of `kcal`, `protein_g`, `carbs_g` or `fat_g`, also set `nutrition_basis` (`label`, `estimate` or `copied_from_meal`). The schema does not enforce that pairing; the app does.
* Foreign keys are declared but the node does not enforce them. To delete a recipe, delete its `recipe_shelf` and `meal_link` rows first, then the `recipe` row. To delete a shelf, delete its `recipe_shelf` rows first; its recipes stay.
* `origin = 'from_meal'` means the recipe was started from a Health Log meal. Copy that meal's macros into the recipe, set `nutrition_basis = 'copied_from_meal'`, and add a `meal_link` row with `health_meal_id` set to the meal's `id` and the `meal_day`, `meal_name` and `meal_kcal` snapshot. One meal can be linked to a recipe only once.
* Never write to `xyz.tinycloud.sample.healthlog/`. The grant is read only and the node refuses writes there. If a meal is missing, tell the user to log it in the Health Log.
* Before you read the Health Log's data, read its own knowledge: `xyz.tinycloud.sample.healthlog/knowledge/index.md`. This app has no KV grant there, so an agent needs its own grant to read it.
* If you change a table's columns, update that table's concept and add a dated line to `log.md`.

# Resources

* Tables: [recipe](/tables/recipe.md), [shelf](/tables/shelf.md), [recipe_shelf](/tables/recipe_shelf.md), [meal_link](/tables/meal_link.md)
* Views: [recipe_card](/views/recipe_card.md), [shelf_overview](/views/shelf_overview.md)
* KV prefixes: [prefs/](/kv/prefs.md), [app/](/kv/app.md), [knowledge/](/kv/knowledge.md)

# Permissions

Space `applications`, app prefix `xyz.tinycloud.sample.recipes`. Each resource below is in the form the CLI `--cap` flag takes (add `:<actions>`).

| Resource | Actions | Why |
| --- | --- | --- |
| `tinycloud.sql:applications:xyz.tinycloud.sample.recipes/recipes` | read, write, schema | Read and change your recipes, shelves and meal links (database xyz.tinycloud.sample.recipes/recipes). schema lets the app create its own tables on first open. |
| `tinycloud.kv:applications:xyz.tinycloud.sample.recipes/prefs/` | get, put | Read and change the app's one settings file (sort order, last shelf). |
| `tinycloud.kv:applications:xyz.tinycloud.sample.recipes/app/` | get | Read the installed copy of the app's schema. The app cannot change its own code. |
| `tinycloud.kv:applications:xyz.tinycloud.sample.recipes/knowledge/` | get, put, list | Read and update the app's knowledge bundle so an agent can pick up where you left off. |
| `tinycloud.sql:applications:xyz.tinycloud.sample.healthlog/healthlog` | read | Read access to the whole Health Log database (xyz.tinycloud.sample.healthlog/healthlog): its meals, its body-weight entries and its daily summaries. This app only reads meals, so you can start a recipe from one. Read only: it cannot change anything in your Health Log. |

# Other apps' data

These grants point at data owned by other apps:

* `tinycloud.sql:applications:xyz.tinycloud.sample.healthlog/healthlog`: read (read only)

# Getting access

An agent needs a delegation from the owner that covers the resources it touches. Ask for one with `tinycloud auth request --cap <resource>:<actions> --grant`, for example `--cap tinycloud.sql:applications:xyz.tinycloud.sample.recipes/recipes:read,write,schema`.

<!-- keep -->
Hand-written notes for agents go here. Text between the keep markers survives regeneration.
<!-- /keep -->

---
okf_version: "0.2"
---

# App

* [Recipes (sample)](app.md) - A small recipe book.

# Tables

* [recipe](tables/recipe.md) - A recipe.
* [shelf](tables/shelf.md) - A named group of recipes ("Weeknight dinners").
* [recipe_shelf](tables/recipe_shelf.md) - Which recipes are on which shelf (many to many).
* [meal_link](tables/meal_link.md) - Links a recipe to a meal in the Health Log sample (app xyz.tinycloud.sample.healthlog, database healthlog, table meal).

# Views

* [recipe_card](views/recipe_card.md) - One row per recipe with its shelf and linked-meal counts; the list screen reads this.
* [shelf_overview](views/shelf_overview.md) - One row per shelf with the number of recipes on it.

# KV prefixes

* [prefs/](kv/prefs.md) - Read and change the app's one settings file (sort order, last shelf).
* [app/](kv/app.md) - Read the installed copy of the app's schema.
* [knowledge/](kv/knowledge.md) - Read and update the app's knowledge bundle so an agent can pick up where you left off.

# History

* [Update log](log.md) - Dated history of changes to this bundle.

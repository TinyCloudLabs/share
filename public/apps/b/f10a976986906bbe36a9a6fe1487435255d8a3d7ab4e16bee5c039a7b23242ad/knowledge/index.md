---
okf_version: "0.2"
---

# App

* [Health Log](app.md) - A small health log: meals with macros, body weight, a today card and a last-7-days chart.

# Tables

* [meal](tables/meal.md) - One row per logged meal, with calories and macros.
* [weight](tables/weight.md) - One row per logged body weight.

# Views

* [day_card](views/day_card.md) - Per-day totals of meals plus the latest weight, one row per day that has a meal or a weight.
* [week_rollup](views/week_rollup.md) - day_card plus trailing 7-day averages (kcal_avg7, weight_avg7), averaged over days that have data.

# KV prefixes

* [prefs/](kv/prefs.md) - Read and change the app's settings (daily calorie target).
* [settings/](kv/settings.md) - Save your timezone when you open the app, so an agent logging meals for you uses your day.
* [app/](kv/app.md) - Read the installed copy of the app (schema).
* [knowledge/](kv/knowledge.md) - Read and update the app's knowledge bundle so an agent can pick up where you left off.

# History

* [Update log](log.md) - Dated history of changes to this bundle.

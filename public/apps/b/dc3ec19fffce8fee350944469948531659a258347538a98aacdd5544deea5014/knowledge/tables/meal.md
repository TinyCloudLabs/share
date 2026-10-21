---
type: "SQLite Table"
title: meal
description: "One row per logged meal, with calories and macros."
resource: tinycloud.sql:applications:xyz.tinycloud.sample.healthlog/healthlog
table: meal
generated: { by: tinycloud-app-kit/okf }
tinycloud:
  app: xyz.tinycloud.sample.healthlog
  service: sql
  profile: tinycloud.app.v1
  containsSecretValue: false
---

One row per logged meal, with calories and macros. Every write carries a client-generated op_id (UNIQUE): replaying an operation never creates a second row.

Table `meal` in SQLite database `xyz.tinycloud.sample.healthlog/healthlog` (space `applications`).

# Schema

| Column | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | INTEGER | primary key | Row id. |
| `op_id` | TEXT | not null; unique | Client-generated operation id; the idempotency key. |
| `day` | TEXT | not null; check `day = date(day)` | The user's local calendar date, YYYY-MM-DD (not the UTC date). |
| `slot` | TEXT | not null; one of `breakfast`, `lunch`, `dinner`, `snack` | Which meal of the day. |
| `name` | TEXT | not null; check `length(name) BETWEEN 1 AND 200` | What was eaten, 1 to 200 characters. |
| `kcal` | INTEGER | not null; check `kcal BETWEEN 0 AND 5000` | Calories, a whole number from 0 to 5000. |
| `protein_g` | REAL | not null; default `0`; check `protein_g >= 0` | Protein in grams. |
| `carbs_g` | REAL | not null; default `0`; check `carbs_g >= 0` | Carbohydrate in grams. |
| `fat_g` | REAL | not null; default `0`; check `fat_g >= 0` | Fat in grams. |
| `note` | TEXT | - | Optional free text. |
| `source` | TEXT | not null; default `'app'`; one of `app`, `agent`, `import` | Who wrote the row. Agents write 'agent'. |
| `logged_at` | TEXT | not null | ISO 8601 UTC instant of the write. |

# Indexes

* `idx_meal_day` on `(day)`

# Read by views

* [day_card](/views/day_card.md)

# Access

The manifest grants `read`, `write`, `schema`.

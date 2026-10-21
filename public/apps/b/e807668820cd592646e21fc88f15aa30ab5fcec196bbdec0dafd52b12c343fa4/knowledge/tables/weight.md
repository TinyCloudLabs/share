---
type: "SQLite Table"
title: weight
description: "One row per logged body weight."
resource: tinycloud.sql:applications:xyz.tinycloud.sample.healthlog/healthlog
table: weight
generated: { by: tinycloud-app-kit/okf }
tinycloud:
  app: xyz.tinycloud.sample.healthlog
  service: sql
  profile: tinycloud.app.v1
  containsSecretValue: false
---

One row per logged body weight. Several per day are allowed; day_card shows the latest. Same op_id protocol as meal.

Table `weight` in SQLite database `xyz.tinycloud.sample.healthlog/healthlog` (space `applications`).

# Schema

| Column | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | INTEGER | primary key | Row id. |
| `op_id` | TEXT | not null; unique | Client-generated operation id; the idempotency key. |
| `day` | TEXT | not null; check `day = date(day)` | The user's local calendar date, YYYY-MM-DD (not the UTC date). |
| `weight_kg` | REAL | not null; check `weight_kg BETWEEN 20 AND 500` | Body weight in kilograms, 20 to 500. |
| `note` | TEXT | - | Optional free text. |
| `source` | TEXT | not null; default `'app'`; one of `app`, `agent`, `import` | Who wrote the row. Agents write 'agent'. |
| `logged_at` | TEXT | not null | ISO 8601 UTC instant of the write. |

# Indexes

* `idx_weight_day` on `(day)`

# Read by views

* [day_card](/views/day_card.md)

# Access

The manifest grants `read`, `write`, `schema`.

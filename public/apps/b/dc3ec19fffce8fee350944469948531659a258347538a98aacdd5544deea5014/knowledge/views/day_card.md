---
type: "SQLite View"
title: day_card
description: "Per-day totals of meals plus the latest weight, one row per day that has a meal or a weight."
resource: tinycloud.sql:applications:xyz.tinycloud.sample.healthlog/healthlog
view: day_card
generated: { by: tinycloud-app-kit/okf }
tinycloud:
  app: xyz.tinycloud.sample.healthlog
  service: sql
  profile: tinycloud.app.v1
  containsSecretValue: false
---

Per-day totals of meals plus the latest weight, one row per day that has a meal or a weight. Read only. The app's today card is SELECT * FROM day_card WHERE day = ?; no row means an empty day.

View `day_card` in SQLite database `xyz.tinycloud.sample.healthlog/healthlog` (space `applications`).

# Schema

| Column |
| --- |
| `day` |
| `kcal` |
| `protein_g` |
| `carbs_g` |
| `fat_g` |
| `meals` |
| `weight_kg` |

# Reads

* [meal](/tables/meal.md)
* [weight](/tables/weight.md)

# Read by views

* [week_rollup](/views/week_rollup.md)

# Definition

```sql
CREATE VIEW IF NOT EXISTS day_card AS
SELECT
  d.day AS day,
  COALESCE((SELECT SUM(m.kcal)      FROM meal m WHERE m.day = d.day), 0) AS kcal,
  COALESCE((SELECT SUM(m.protein_g) FROM meal m WHERE m.day = d.day), 0) AS protein_g,
  COALESCE((SELECT SUM(m.carbs_g)   FROM meal m WHERE m.day = d.day), 0) AS carbs_g,
  COALESCE((SELECT SUM(m.fat_g)     FROM meal m WHERE m.day = d.day), 0) AS fat_g,
  (SELECT COUNT(*) FROM meal m WHERE m.day = d.day) AS meals,
  (SELECT w.weight_kg FROM weight w WHERE w.day = d.day
     ORDER BY w.logged_at DESC, w.id DESC LIMIT 1) AS weight_kg
FROM (SELECT day FROM meal UNION SELECT day FROM weight) AS d
```

# Access

Query it with the `read` action; the manifest grants `read`, `write`, `schema`.

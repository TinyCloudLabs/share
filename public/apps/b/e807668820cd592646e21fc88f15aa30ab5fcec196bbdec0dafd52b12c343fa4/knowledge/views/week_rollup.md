---
type: "SQLite View"
title: week_rollup
description: "day_card plus trailing 7-day averages (kcal_avg7, weight_avg7), averaged over days that have data."
resource: tinycloud.sql:applications:xyz.tinycloud.sample.healthlog/healthlog
view: week_rollup
generated: { by: tinycloud-app-kit/okf }
tinycloud:
  app: xyz.tinycloud.sample.healthlog
  service: sql
  profile: tinycloud.app.v1
  containsSecretValue: false
---

day_card plus trailing 7-day averages (kcal_avg7, weight_avg7), averaged over days that have data. Read only. A view cannot know today's date: query it with WHERE day BETWEEN ? AND ? ORDER BY day. Days without data have no row.

View `week_rollup` in SQLite database `xyz.tinycloud.sample.healthlog/healthlog` (space `applications`).

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
| `kcal_avg7` |
| `weight_avg7` |

# Reads

* [day_card](/views/day_card.md)

# Definition

```sql
CREATE VIEW IF NOT EXISTS week_rollup AS
SELECT
  c.day AS day,
  c.kcal AS kcal,
  c.protein_g AS protein_g,
  c.carbs_g AS carbs_g,
  c.fat_g AS fat_g,
  c.meals AS meals,
  c.weight_kg AS weight_kg,
  (SELECT ROUND(AVG(p.kcal), 0) FROM day_card p
     WHERE p.meals > 0 AND p.day BETWEEN date(c.day, '-6 days') AND c.day) AS kcal_avg7,
  (SELECT ROUND(AVG(p.weight_kg), 2) FROM day_card p
     WHERE p.weight_kg IS NOT NULL AND p.day BETWEEN date(c.day, '-6 days') AND c.day) AS weight_avg7
FROM day_card c
```

# Access

Query it with the `read` action; the manifest grants `read`, `write`, `schema`.

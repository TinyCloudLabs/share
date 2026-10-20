---
type: "SQLite Table"
title: shelf
description: "A named group of recipes (\"Weeknight dinners\")."
resource: tinycloud.sql:applications:xyz.tinycloud.sample.recipes/recipes
table: shelf
generated: { by: tinycloud-app-kit/okf }
tinycloud:
  app: xyz.tinycloud.sample.recipes
  service: sql
  profile: tinycloud.app.v1
  containsSecretValue: false
---

A named group of recipes ("Weeknight dinners"). A recipe can sit on several shelves.

Table `shelf` in SQLite database `xyz.tinycloud.sample.recipes/recipes` (space `applications`).

# Schema

| Column | Type | Constraints | Description |
| --- | --- | --- | --- |
| `id` | TEXT | primary key | shf_ + time + random |
| `name` | TEXT | not null; unique; check `length(name) BETWEEN 1 AND 80` | - |
| `description` | TEXT | - | - |
| `position` | INTEGER | not null; default `0` | display order, lowest first |
| `created_at` | TEXT | not null | - |

# Read by views

* [shelf_overview](/views/shelf_overview.md)

# Access

The manifest grants `read`, `write`, `schema`.

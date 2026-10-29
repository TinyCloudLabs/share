---
type: "TinyCloud App"
title: "Health Log"
description: "A small health log: meals with macros, body weight, a today card and a last-7-days chart."
generated: { by: tinycloud-app-kit/okf }
tinycloud: { app: xyz.tinycloud.sample.healthlog, profile: tinycloud.app.v1, containsSecretValue: false }
tags: [health, food, weight]
---

A small health log: meals with macros, body weight, a today card and a last-7-days chart.

The user logs meals (slot, name, kcal, protein/carbs/fat) and body weight. The
app shows a **today card** (from `day_card`) and a **last 7 days** chart (from `week_rollup`). It has no network
access, no other storage and no side effects beyond the resources listed below. It is original work, not a fork.

# How to operate it (rules for agents)

1. Read this file, then only the concept you need. To see today: `SELECT * FROM day_card WHERE day = '<YYYY-MM-DD>'`.
2. **Every write carries an operation id.** Make a fresh unique `op_id` (for example `op_<time>_<random>`) per
   logical entry. Write with `INSERT ... ON CONFLICT(op_id) DO NOTHING`, then **read the row back** with
   `SELECT ... WHERE op_id = ?`. If the write times out, read back before retrying and reuse the same `op_id`.
   Never insert without an `op_id`.
3. Agents set `source = 'agent'`. `day` is the user's local calendar date (`YYYY-MM-DD`), not the UTC date. The page
   saves the user's IANA timezone at `settings/timezone` when it opens. `logged_at` is an ISO 8601 UTC instant.
4. Write only `meal` and `weight`. `day_card` and `week_rollup` are views and update by themselves.
5. Values: `slot` is one of `breakfast|lunch|dinner|snack`; `kcal` is a whole number 0 to 5000; macros are grams
   (>= 0); `weight_kg` is 20 to 500. The schema enforces these with CHECK constraints.
6. Do not delete or edit the user's rows unless the user asked. Never touch other apps' prefixes.
7. The user's copy is theirs: if the user asks you to change the app you may rewrite it (`app/`). Then update the
   affected concepts here and add a dated entry to `log.md`.

# Reading from the command line

```
tinycloud sql query "SELECT * FROM day_card WHERE day = ?" --db xyz.tinycloud.sample.healthlog/healthlog --space applications --params '["2026-10-20"]'
tinycloud kv get xyz.tinycloud.sample.healthlog/knowledge/index.md --space applications
```

The capability to request for a concept is its `resource:` value plus actions (`read,write` for SQL,
`get,put,list` for KV).

# Resources

* Tables: [meal](/tables/meal.md), [weight](/tables/weight.md)
* Views: [day_card](/views/day_card.md), [week_rollup](/views/week_rollup.md)
* KV prefixes: [prefs/](/kv/prefs.md), [settings/](/kv/settings.md), [app/](/kv/app.md), [knowledge/](/kv/knowledge.md)

# Permissions

Space `applications`, app prefix `xyz.tinycloud.sample.healthlog`. Each resource below is in the form the CLI `--cap` flag takes (add `:<actions>`).

| Resource | Actions | Why |
| --- | --- | --- |
| `tinycloud.sql:applications:xyz.tinycloud.sample.healthlog/healthlog` | read, write, schema | Read and change your meal and weight log (database xyz.tinycloud.sample.healthlog/healthlog). schema lets the app create its own tables on first open. |
| `tinycloud.kv:applications:xyz.tinycloud.sample.healthlog/prefs/` | get, put | Read and change the app's settings (daily calorie target). |
| `tinycloud.kv:applications:xyz.tinycloud.sample.healthlog/settings/` | get, put | Save your timezone when you open the app, so an agent logging meals for you uses your day. |
| `tinycloud.kv:applications:xyz.tinycloud.sample.healthlog/app/` | get | Read the installed copy of the app (schema). The app cannot change its own code. |
| `tinycloud.kv:applications:xyz.tinycloud.sample.healthlog/knowledge/` | get, put, list | Read and update the app's knowledge bundle so an agent can pick up where you left off. |

# Getting access

An agent needs a delegation from the owner that covers the resources it touches. Ask for one with `tinycloud auth request --cap <resource>:<actions> --grant`, for example `--cap tinycloud.sql:applications:xyz.tinycloud.sample.healthlog/healthlog:read,write,schema`.

<!-- keep -->
Hand-written notes for agents go here. Text between the keep markers survives regeneration.
<!-- /keep -->

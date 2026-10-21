-- Recipes: xyz.tinycloud.sample.recipes
-- One SQLite database, `recipes`, in the user's `applications` space.
-- Every statement is idempotent (IF NOT EXISTS) so the app can re-run this file.
-- Ids are client-generated text (rcp_..., shf_..., lnk_...): replaying an
-- operation with the same id can never create a second row.
-- Foreign keys are declared for documentation. The node does not enforce them,
-- so the app deletes child rows (recipe_shelf, meal_link) before the parent.

-- A recipe. Nutrition is per serving and optional; when any nutrition number is set, nutrition_basis says where it came from.
CREATE TABLE IF NOT EXISTS recipe (
  id               TEXT    PRIMARY KEY,          -- rcp_ + time + random, made by the app
  title            TEXT    NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
  origin           TEXT    NOT NULL DEFAULT 'own' CHECK (origin IN ('own', 'adapted', 'from_meal')), -- own: written by the user; adapted: changed from someone else's; from_meal: started from a Health Log meal
  summary          TEXT    CHECK (summary IS NULL OR length(summary) <= 1000), -- one or two lines shown on the list card
  servings         REAL    NOT NULL DEFAULT 1 CHECK (servings > 0 AND servings <= 1000),
  prep_min         INTEGER CHECK (prep_min IS NULL OR prep_min BETWEEN 0 AND 10080), -- one week, in minutes
  cook_min         INTEGER CHECK (cook_min IS NULL OR cook_min BETWEEN 0 AND 10080),
  ingredients_json TEXT    NOT NULL DEFAULT '[]' CHECK (length(ingredients_json) <= 100000), -- JSON array of {"qty": "200 g", "item": "flour"}; qty is free text and may be empty
  steps_json       TEXT    NOT NULL DEFAULT '[]' CHECK (length(steps_json) <= 100000), -- JSON array of strings, one per step, in order
  kcal             INTEGER CHECK (kcal IS NULL OR kcal BETWEEN 0 AND 5000), -- per serving; NULL: not entered
  protein_g        REAL    CHECK (protein_g IS NULL OR protein_g BETWEEN 0 AND 10000), -- per serving
  carbs_g          REAL    CHECK (carbs_g IS NULL OR carbs_g BETWEEN 0 AND 10000),     -- per serving
  fat_g            REAL    CHECK (fat_g IS NULL OR fat_g BETWEEN 0 AND 10000),         -- per serving
  nutrition_basis  TEXT    CHECK (nutrition_basis IS NULL OR nutrition_basis IN ('label', 'estimate', 'copied_from_meal')), -- label: read off a package; estimate: the user's guess; copied_from_meal: copied from a Health Log meal
  favorite         INTEGER NOT NULL DEFAULT 0 CHECK (favorite IN (0, 1)),
  created_at       TEXT    NOT NULL,             -- ISO 8601 UTC
  updated_at       TEXT    NOT NULL              -- ISO 8601 UTC; the list sorts by this
);

CREATE INDEX IF NOT EXISTS idx_recipe_updated ON recipe(updated_at);

-- A named group of recipes ("Weeknight dinners"). A recipe can sit on several shelves.
CREATE TABLE IF NOT EXISTS shelf (
  id          TEXT    PRIMARY KEY,               -- shf_ + time + random
  name        TEXT    NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 80),
  description TEXT,
  position    INTEGER NOT NULL DEFAULT 0,        -- display order, lowest first
  created_at  TEXT    NOT NULL
);

-- Which recipes are on which shelf (many to many). Deleting a shelf removes only its rows here.
CREATE TABLE IF NOT EXISTS recipe_shelf (
  recipe_id TEXT NOT NULL REFERENCES recipe(id) ON DELETE CASCADE,
  shelf_id  TEXT NOT NULL REFERENCES shelf(id)  ON DELETE CASCADE,
  added_at  TEXT NOT NULL,
  PRIMARY KEY (recipe_id, shelf_id)
);

CREATE INDEX IF NOT EXISTS idx_recipe_shelf_shelf ON recipe_shelf(shelf_id);

-- Links a recipe to a meal in the Health Log (app xyz.tinycloud.sample.healthlog, database healthlog, table meal). This app only reads that table; the link lives here, never there. The meal_* columns are a snapshot taken at link time so the list renders without reading the other app.
CREATE TABLE IF NOT EXISTS meal_link (
  id             TEXT    PRIMARY KEY,            -- lnk_ + time + random
  recipe_id      TEXT    NOT NULL REFERENCES recipe(id) ON DELETE CASCADE,
  health_meal_id INTEGER NOT NULL,               -- meal.id in the Health Log database; may point at a meal that was later deleted there
  meal_day       TEXT,                           -- snapshot of meal.day (YYYY-MM-DD)
  meal_name      TEXT,                           -- snapshot of meal.name
  meal_kcal      INTEGER,                        -- snapshot of meal.kcal
  created_at     TEXT    NOT NULL,
  UNIQUE (recipe_id, health_meal_id)
);

CREATE INDEX IF NOT EXISTS idx_meal_link_meal ON meal_link(health_meal_id);

-- One row per recipe with its shelf and linked-meal counts; the list screen reads this.
CREATE VIEW IF NOT EXISTS recipe_card AS
SELECT
  r.id AS id,
  r.title AS title,
  r.origin AS origin,
  r.summary AS summary,
  r.servings AS servings,
  r.kcal AS kcal,
  r.protein_g AS protein_g,
  r.carbs_g AS carbs_g,
  r.fat_g AS fat_g,
  r.favorite AS favorite,
  r.updated_at AS updated_at,
  (SELECT COUNT(*) FROM recipe_shelf rs WHERE rs.recipe_id = r.id) AS shelf_count,
  (SELECT COUNT(*) FROM meal_link ml WHERE ml.recipe_id = r.id) AS meal_count
FROM recipe r;

-- One row per shelf with the number of recipes on it.
CREATE VIEW IF NOT EXISTS shelf_overview AS
SELECT
  s.id AS id,
  s.name AS name,
  s.description AS description,
  s.position AS position,
  (SELECT COUNT(*) FROM recipe_shelf rs WHERE rs.shelf_id = s.id) AS recipe_count
FROM shelf s;

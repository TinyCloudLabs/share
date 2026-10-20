// Recipes (sample): xyz.tinycloud.sample.recipes
//
// A tiny app for TinyCloud: shelves, a recipe list and detail view, add/edit,
// and "start from a meal" which reads the Health Log sample's `meal` table
// through a READ-ONLY cross-app grant (see manifest.json).
//
// Runs sealed in the share sandbox: the only things it imports are React and
// the `@tinycloud/app` bridge. No fetch, no storage, no eval, no keys.

import React, { useCallback, useEffect, useState } from "react";
import { sql, kv } from "@tinycloud/app";

// Database names are relative to this app's id ("recipes" is
// xyz.tinycloud.sample.recipes/recipes). A leading "/" is an absolute path in the
// space: the Health Log's database is reachable only because manifest.json grants
// it with skipPrefix (read only).
const DB = "recipes";
const HEALTH_DB = "/xyz.tinycloud.sample.healthlog/healthlog";

const ORIGINS = { own: "Mine", adapted: "Adapted", from_meal: "From a meal" };
const BASES = {
  label: "From a label",
  estimate: "My estimate",
  copied_from_meal: "Copied from a meal",
};

// ---------------------------------------------------------------- data layer

class DataError extends Error {
  constructor(err) {
    super(errText(err));
    this.code = err && typeof err === "object" ? err.code : undefined;
  }
}

function errText(err) {
  if (!err) return "Something went wrong.";
  if (typeof err === "string") return err;
  return err.message || err.code || "Something went wrong.";
}

function isStorageFull(err) {
  const code = err && typeof err === "object" ? err.code : "";
  return (
    code === "STORAGE_QUOTA_EXCEEDED" ||
    code === "STORAGE_LIMIT_REACHED" ||
    /storage quota exceeded|write exceeds remaining storage/i.test(errText(err))
  );
}

export const REQUIRED_OBJECTS = ["recipe", "shelf", "recipe_shelf", "meal_link", "recipe_card", "shelf_overview"];

// The bridge answers a query with { columns, rows: [[...]] }; make row objects.
function toObjects(res) {
  return res.rows.map((row) => Object.fromEntries(res.columns.map((c, i) => [c, row[i]])));
}

async function query(db, text, params = []) {
  const res = await sql.query(db, text, params);
  if (!res || !res.ok) throw new DataError(res && res.error);
  return toObjects(res);
}

async function exec(db, text, params = []) {
  const res = await sql.execute(db, text, params);
  if (!res || !res.ok) throw new DataError(res && res.error);
  return res;
}

function decodeBytes(bytes) {
  return new TextDecoder().decode(bytes);
}

function safeJson(text, fallback) {
  try {
    const value = JSON.parse(text);
    return Array.isArray(fallback) && !Array.isArray(value) ? fallback : value;
  } catch {
    return fallback;
  }
}

function splitSql(text) {
  const clean = text
    .split("\n")
    .map((line) => line.replace(/--.*$/, ""))
    .join("\n");
  return clean
    .split(/;\s*(?:\n|$)/)
    .map((s) => s.trim())
    .filter(Boolean);
}

const OBJECT_NAME = /^CREATE\s+(?:UNIQUE\s+)?(?:TABLE|VIEW|INDEX)\s+IF\s+NOT\s+EXISTS\s+([A-Za-z_]\w*)/i;

// Read first, write only when something is missing (a full account refuses
// writes but must still open and read). The statements come from the installed
// copy of schema.sql, so there is one source of truth for the layout.
export async function ensureSchema() {
  const have = await sql.query(
    DB,
    `SELECT name FROM sqlite_master WHERE name IN (${REQUIRED_OBJECTS.map(() => "?").join(", ")})`,
    REQUIRED_OBJECTS,
  );
  if (have && have.ok && have.rows.length === REQUIRED_OBJECTS.length) return false;
  // A failed read is treated as "not created yet" except when the bridge itself
  // is refusing us; any real problem resurfaces from the statements below.
  if (have && !have.ok && ["PERMISSION_DENIED", "NOT_CONNECTED", "BUSY", "TIMEOUT"].includes(have.error && have.error.code)) {
    throw new DataError(have.error);
  }
  const file = await kv.get("app/schema.sql");
  if (!file || !file.ok) {
    throw new DataError(file && file.error ? file.error : "app/schema.sql is missing from the installed copy.");
  }
  for (const statement of splitSql(decodeBytes(file.bytes))) await exec(DB, statement);
  return true;
}

const now = () => new Date().toISOString();
const uid = (prefix) => `${prefix}_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;

export async function loadPrefs() {
  const res = await kv.get("prefs/ui.json");
  if (!res || !res.ok) return {};
  return safeJson(decodeBytes(res.bytes), {});
}

// Saves are chained: the bridge runs up to four calls at once and does not order
// them, so two quick changes could otherwise land with the older one last.
let prefsQueue = Promise.resolve();
export function savePrefs(prefs) {
  const run = async () => {
    const res = await kv.put("prefs/ui.json", JSON.stringify(prefs));
    if (!res || !res.ok) throw new DataError(res && res.error);
  };
  const result = prefsQueue.then(run);
  prefsQueue = result.catch(() => {});
  return result;
}

export const listShelves = () => query(DB, "SELECT id, name, description, recipe_count FROM shelf_overview ORDER BY position, name");

export function listRecipes({ shelfId, search, favoritesOnly, sort } = {}) {
  const where = [];
  const params = [];
  if (shelfId) {
    where.push("c.id IN (SELECT recipe_id FROM recipe_shelf WHERE shelf_id = ?)");
    params.push(shelfId);
  }
  if (search) {
    where.push("c.title LIKE ? ESCAPE '\\'");
    params.push(`%${search.replace(/[\\%_]/g, (m) => `\\${m}`)}%`);
  }
  if (favoritesOnly) where.push("c.favorite = 1");
  const order = sort === "title" ? "c.title COLLATE NOCASE ASC" : "c.updated_at DESC";
  return query(
    DB,
    `SELECT c.* FROM recipe_card c ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY ${order}, c.id LIMIT 200`,
    params,
  );
}

export async function loadRecipe(id) {
  const rows = await query(DB, "SELECT * FROM recipe WHERE id = ?", [id]);
  if (rows.length === 0) return null;
  const recipe = rows[0];
  const shelves = await query(
    DB,
    "SELECT s.id, s.name FROM shelf s JOIN recipe_shelf rs ON rs.shelf_id = s.id WHERE rs.recipe_id = ? ORDER BY s.position, s.name",
    [id],
  );
  const links = await query(
    DB,
    "SELECT id, health_meal_id, meal_day, meal_name, meal_kcal FROM meal_link WHERE recipe_id = ? ORDER BY created_at",
    [id],
  );
  return {
    ...recipe,
    ingredients: safeJson(recipe.ingredients_json, []),
    steps: safeJson(recipe.steps_json, []),
    shelves,
    links,
  };
}

// Writes are plain sequential statements (the bridge has no transaction), so a
// failure part-way leaves earlier statements stored. Say which part failed.
export async function saveRecipe({ id, fields, shelfIds, links }) {
  const isNew = !id;
  const rid = id || uid("rcp");
  const stamp = now();
  const values = [
    fields.title,
    fields.origin,
    fields.summary,
    fields.servings,
    fields.prep_min,
    fields.cook_min,
    JSON.stringify(fields.ingredients),
    JSON.stringify(fields.steps),
    fields.kcal,
    fields.protein_g,
    fields.carbs_g,
    fields.fat_g,
    fields.nutrition_basis,
    fields.favorite ? 1 : 0,
  ];
  if (isNew) {
    await exec(
      DB,
      `INSERT INTO recipe (title, origin, summary, servings, prep_min, cook_min, ingredients_json, steps_json,
         kcal, protein_g, carbs_g, fat_g, nutrition_basis, favorite, id, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [...values, rid, stamp, stamp],
    );
  } else {
    await exec(
      DB,
      `UPDATE recipe SET title = ?, origin = ?, summary = ?, servings = ?, prep_min = ?, cook_min = ?,
         ingredients_json = ?, steps_json = ?, kcal = ?, protein_g = ?, carbs_g = ?, fat_g = ?,
         nutrition_basis = ?, favorite = ?, updated_at = ? WHERE id = ?`,
      [...values, stamp, rid],
    );
  }
  try {
    await exec(DB, "DELETE FROM recipe_shelf WHERE recipe_id = ?", [rid]);
    for (const shelfId of shelfIds) {
      await exec(DB, "INSERT INTO recipe_shelf (recipe_id, shelf_id, added_at) VALUES (?, ?, ?)", [rid, shelfId, stamp]);
    }
    for (const link of links.filter((l) => !l.id)) {
      await exec(
        DB,
        `INSERT INTO meal_link (id, recipe_id, health_meal_id, meal_day, meal_name, meal_kcal, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [uid("lnk"), rid, link.health_meal_id, link.meal_day, link.meal_name, link.meal_kcal, stamp],
      );
    }
  } catch (err) {
    const e = new DataError(err);
    e.message = `The recipe was saved, but its shelves or meal link were not: ${e.message}`;
    e.partialId = rid;
    throw e;
  }
  return rid;
}

export async function deleteRecipe(id) {
  await exec(DB, "DELETE FROM recipe_shelf WHERE recipe_id = ?", [id]);
  await exec(DB, "DELETE FROM meal_link WHERE recipe_id = ?", [id]);
  await exec(DB, "DELETE FROM recipe WHERE id = ?", [id]);
}

export async function setFavorite(id, favorite) {
  await exec(DB, "UPDATE recipe SET favorite = ?, updated_at = ? WHERE id = ?", [favorite ? 1 : 0, now(), id]);
}

export async function createShelf(name) {
  const [{ next }] = await query(DB, "SELECT COALESCE(MAX(position), 0) + 1 AS next FROM shelf");
  await exec(DB, "INSERT INTO shelf (id, name, description, position, created_at) VALUES (?, ?, NULL, ?, ?)", [
    uid("shf"),
    name,
    next,
    now(),
  ]);
}

export async function renameShelf(id, name) {
  await exec(DB, "UPDATE shelf SET name = ? WHERE id = ?", [name, id]);
}

export async function deleteShelf(id) {
  await exec(DB, "DELETE FROM recipe_shelf WHERE shelf_id = ?", [id]);
  await exec(DB, "DELETE FROM shelf WHERE id = ?", [id]);
}

// Health Log meals, newest first. Read-only: the manifest grants `read` only.
export function listHealthMeals() {
  return query(
    HEALTH_DB,
    "SELECT id, day, slot, name, kcal, protein_g, carbs_g, fat_g FROM meal ORDER BY day DESC, id DESC LIMIT 40",
  );
}

export const linkedMealIds = async () =>
  new Set((await query(DB, "SELECT DISTINCT health_meal_id FROM meal_link")).map((r) => r.health_meal_id));

// ------------------------------------------------------------------ form model

export const blankForm = () => ({
  title: "",
  summary: "",
  origin: "own",
  servings: "2",
  prep_min: "",
  cook_min: "",
  ingredients: [{ qty: "", item: "" }],
  steps: "",
  kcal: "",
  protein_g: "",
  carbs_g: "",
  fat_g: "",
  nutrition_basis: "",
  favorite: false,
  shelfIds: [],
  links: [],
});

const textOf = (v) => (v === null || v === undefined ? "" : String(v));

export function formFromRecipe(recipe) {
  return {
    title: recipe.title,
    summary: textOf(recipe.summary),
    origin: recipe.origin,
    servings: textOf(recipe.servings),
    prep_min: textOf(recipe.prep_min),
    cook_min: textOf(recipe.cook_min),
    ingredients: recipe.ingredients.length ? recipe.ingredients.map((i) => ({ qty: textOf(i.qty), item: textOf(i.item) })) : [{ qty: "", item: "" }],
    steps: recipe.steps.join("\n"),
    kcal: textOf(recipe.kcal),
    protein_g: textOf(recipe.protein_g),
    carbs_g: textOf(recipe.carbs_g),
    fat_g: textOf(recipe.fat_g),
    nutrition_basis: textOf(recipe.nutrition_basis),
    favorite: recipe.favorite === 1,
    shelfIds: recipe.shelves.map((s) => s.id),
    links: recipe.links,
  };
}

export function formFromMeal(meal) {
  return {
    ...blankForm(),
    title: meal.name,
    origin: "from_meal",
    servings: "1",
    summary: `Started from ${meal.slot} on ${meal.day}.`,
    kcal: textOf(meal.kcal),
    protein_g: textOf(meal.protein_g),
    carbs_g: textOf(meal.carbs_g),
    fat_g: textOf(meal.fat_g),
    nutrition_basis: "copied_from_meal",
    links: [{ health_meal_id: meal.id, meal_day: meal.day, meal_name: meal.name, meal_kcal: meal.kcal }],
  };
}

// Plain decimal digits only: Number() would also accept "0x10", "1e3" and "Infinity".
const PLAIN_NUMBER = /^(?:\d+\.?\d*|\.\d+)$/;

// Upper bounds, the same ones schema.sql enforces with CHECKs.
// steps/ingredients limits keep the stored JSON well under the 100000-character CHECKs on steps_json and
// ingredients_json (a character can grow to 6 in JSON, and every entry adds a few more).
export const MAX = { servings: 1000, minutes: 10080, kcal: 5000, grams: 10000, summary: 1000, steps: 10000, ingredients: 50, qty: 60, item: 150 };

function parseNumber(text, label, { integer = false, min = 0, max }) {
  const trimmed = text.trim();
  const n = PLAIN_NUMBER.test(trimmed) ? Number(trimmed) : NaN;
  if (!Number.isFinite(n) || n < min || n > max || (integer && !Number.isInteger(n))) {
    return { error: `${label} must be ${integer ? "a whole number" : "a number"} from ${min} to ${max}.` };
  }
  return { value: n };
}

function optionalNumber(text, label, opts) {
  return text.trim() === "" ? { value: null } : parseNumber(text, label, opts);
}

export function validateForm(form) {
  const title = form.title.trim();
  if (!title) return { error: "Give the recipe a title." };
  if (title.length > 200) return { error: "The title is limited to 200 characters." };
  if (form.summary.trim().length > MAX.summary) return { error: `The summary is limited to ${MAX.summary} characters.` };
  if (form.steps.length > MAX.steps) return { error: `The steps are limited to ${MAX.steps} characters.` };
  const servings = PLAIN_NUMBER.test(form.servings.trim()) ? Number(form.servings.trim()) : NaN;
  if (!(servings > 0 && servings <= MAX.servings)) return { error: `Servings must be a number above 0, up to ${MAX.servings}.` };
  const numbers = {};
  for (const [key, label, opts] of [
    ["prep_min", "Prep minutes", { integer: true, max: MAX.minutes }],
    ["cook_min", "Cook minutes", { integer: true, max: MAX.minutes }],
    ["kcal", "Calories", { integer: true, max: MAX.kcal }],
    ["protein_g", "Protein", { max: MAX.grams }],
    ["carbs_g", "Carbs", { max: MAX.grams }],
    ["fat_g", "Fat", { max: MAX.grams }],
  ]) {
    const parsed = optionalNumber(form[key], label, opts);
    if (parsed.error) return { error: parsed.error };
    numbers[key] = parsed.value;
  }
  const hasNutrition = ["kcal", "protein_g", "carbs_g", "fat_g"].some((k) => numbers[k] !== null);
  if (hasNutrition && !form.nutrition_basis) return { error: "Say where the nutrition numbers come from." };
  const ingredients = form.ingredients.map((i) => ({ qty: i.qty.trim(), item: i.item.trim() })).filter((i) => i.item || i.qty);
  if (ingredients.length > MAX.ingredients) return { error: `A recipe can have at most ${MAX.ingredients} ingredients.` };
  if (ingredients.some((i) => i.qty.length > MAX.qty)) return { error: `An ingredient amount is limited to ${MAX.qty} characters.` };
  if (ingredients.some((i) => i.item.length > MAX.item)) return { error: `An ingredient name is limited to ${MAX.item} characters.` };
  return {
    fields: {
      title,
      origin: form.origin,
      summary: form.summary.trim() || null,
      servings,
      ...numbers,
      ingredients,
      steps: form.steps
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean),
      nutrition_basis: hasNutrition ? form.nutrition_basis : null,
      favorite: form.favorite,
    },
  };
}

// -------------------------------------------------------------------- UI bits

const btn = "rounded-md px-3 py-1.5 text-sm font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500";
const btnPrimary = `${btn} whitespace-nowrap bg-emerald-600 text-white hover:bg-emerald-700 disabled:opacity-50`;
const btnPlain = `${btn} whitespace-nowrap border border-stone-300 bg-white text-stone-800 hover:bg-stone-50 dark:border-stone-600 dark:bg-stone-900 dark:text-stone-200 dark:hover:bg-stone-800`;
const btnDanger = `${btn} whitespace-nowrap border border-red-300 bg-white text-red-700 hover:bg-red-50 dark:border-red-800 dark:bg-stone-900 dark:text-red-300 dark:hover:bg-red-950`;
const field = "w-full rounded-md border border-stone-300 bg-white px-2 py-1.5 text-sm text-stone-900 dark:border-stone-600 dark:bg-stone-900 dark:text-stone-100";

function Macros({ recipe }) {
  const parts = [];
  if (recipe.kcal !== null && recipe.kcal !== undefined) parts.push(`${recipe.kcal} kcal`);
  if (recipe.protein_g !== null && recipe.protein_g !== undefined) parts.push(`${recipe.protein_g} g protein`);
  if (recipe.carbs_g !== null && recipe.carbs_g !== undefined) parts.push(`${recipe.carbs_g} g carbs`);
  if (recipe.fat_g !== null && recipe.fat_g !== undefined) parts.push(`${recipe.fat_g} g fat`);
  if (parts.length === 0) return <span className="text-stone-500 dark:text-stone-400">No nutrition entered</span>;
  return <span>{parts.join(" · ")}</span>;
}

function Banner({ tone = "info", children }) {
  const colors = tone === "error" ? "border-red-300 bg-red-50 text-red-900 dark:border-red-800 dark:bg-red-950 dark:text-red-200" : "border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-200";
  return (
    <div role={tone === "error" ? "alert" : "status"} className={`rounded-md border px-3 py-2 text-sm ${colors}`}>
      {children}
    </div>
  );
}

function ErrorLine({ error }) {
  if (!error) return null;
  return <Banner tone="error">{error}</Banner>;
}

// --------------------------------------------------------------------- screens

function RecipeList({ shelves, prefs, onPrefs, onOpen, onAdd, onFromMeal, onShelves, reportError }) {
  const [recipes, setRecipes] = useState(null);
  const [search, setSearch] = useState("");
  const [favoritesOnly, setFavoritesOnly] = useState(false);
  const shelfId = prefs.shelf || null;
  const sort = prefs.sort === "title" ? "title" : "updated";

  useEffect(() => {
    let live = true;
    listRecipes({ shelfId, search: search.trim(), favoritesOnly, sort })
      .then((rows) => live && setRecipes(rows))
      .catch((err) => live && (setRecipes([]), reportError(err)));
    return () => {
      live = false;
    };
  }, [shelfId, search, favoritesOnly, sort, reportError]);

  return (
    <section aria-label="Recipes" className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <button className={btnPrimary} onClick={onAdd}>
          Add recipe
        </button>
        <button className={btnPlain} onClick={onFromMeal}>
          From a health-log entry
        </button>
        <button className={btnPlain} onClick={onShelves}>
          Manage shelves
        </button>
      </div>

      <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Shelves">
        <button
          className={`${btn} ${shelfId === null ? "bg-stone-800 text-white dark:bg-stone-100 dark:text-stone-900" : "bg-stone-100 text-stone-800 dark:bg-stone-800 dark:text-stone-200"}`}
          aria-pressed={shelfId === null}
          onClick={() => onPrefs({ shelf: null })}
        >
          All recipes
        </button>
        {shelves.map((s) => (
          <button
            key={s.id}
            className={`${btn} ${shelfId === s.id ? "bg-stone-800 text-white dark:bg-stone-100 dark:text-stone-900" : "bg-stone-100 text-stone-800 dark:bg-stone-800 dark:text-stone-200"}`}
            aria-pressed={shelfId === s.id}
            onClick={() => onPrefs({ shelf: s.id })}
          >
            {s.name} <span className="text-xs opacity-70">{s.recipe_count}</span>
          </button>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 text-sm">
          <span className="sr-only">Search recipes</span>
          <input className={`${field} w-56`} type="search" placeholder="Search titles" value={search} onChange={(e) => setSearch(e.target.value)} />
        </label>
        <label className="flex items-center gap-1 whitespace-nowrap text-sm">
          <input type="checkbox" checked={favoritesOnly} onChange={(e) => setFavoritesOnly(e.target.checked)} />
          Favorites only
        </label>
        <label className="flex items-center gap-1 whitespace-nowrap text-sm">
          Sort
          <select className={`${field} w-auto`} value={sort} onChange={(e) => onPrefs({ sort: e.target.value })}>
            <option value="updated">Recently changed</option>
            <option value="title">Title</option>
          </select>
        </label>
      </div>

      {recipes === null ? (
        <p className="text-sm text-stone-500 dark:text-stone-400">Loading recipes…</p>
      ) : recipes.length === 0 ? (
        <p className="rounded-md border border-dashed border-stone-300 dark:border-stone-600 p-6 text-center text-sm text-stone-600 dark:text-stone-400">
          No recipes here yet. Add one, or start from a meal in your health log.
        </p>
      ) : (
        <ul className="grid gap-3 sm:grid-cols-2" aria-label="Recipe list">
          {recipes.map((r) => (
            <li key={r.id}>
              <button
                className="w-full rounded-lg border border-stone-200 bg-white p-3 text-left shadow-sm hover:border-emerald-400 dark:border-stone-700 dark:bg-stone-900"
                onClick={() => onOpen(r.id)}
              >
                <div className="flex items-start justify-between gap-2">
                  <span className="font-semibold text-stone-900 dark:text-stone-100">{r.title}</span>
                  {r.favorite === 1 ? <span aria-label="Favorite" className="text-amber-500">★</span> : null}
                </div>
                {r.summary ? <p className="mt-1 line-clamp-2 text-sm text-stone-600 dark:text-stone-400">{r.summary}</p> : null}
                <p className="mt-2 text-xs text-stone-600 dark:text-stone-400">
                  <Macros recipe={r} />
                </p>
                <p className="mt-1 text-xs text-stone-500 dark:text-stone-400">
                  {ORIGINS[r.origin] || r.origin}
                  {r.shelf_count > 0 ? ` · on ${r.shelf_count} ${r.shelf_count === 1 ? "shelf" : "shelves"}` : ""}
                  {r.meal_count > 0 ? ` · linked to ${r.meal_count} meal${r.meal_count === 1 ? "" : "s"}` : ""}
                </p>
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function RecipeDetail({ id, onBack, onEdit, onChanged, reportError }) {
  const [recipe, setRecipe] = useState(undefined);
  const [confirming, setConfirming] = useState(false);

  const load = useCallback(() => {
    loadRecipe(id)
      .then(setRecipe)
      .catch((err) => (setRecipe(null), reportError(err)));
  }, [id, reportError]);
  useEffect(load, [load]);

  if (recipe === undefined) return <p className="text-sm text-stone-500 dark:text-stone-400">Loading recipe…</p>;
  if (recipe === null) {
    return (
      <div className="space-y-3">
        <p>That recipe is not there any more.</p>
        <button className={btnPlain} onClick={onBack}>
          Back to recipes
        </button>
      </div>
    );
  }

  return (
    <article className="space-y-4" aria-label={recipe.title}>
      <button className={btnPlain} onClick={onBack}>
        Back to recipes
      </button>
      <header className="space-y-1">
        <h2 className="text-2xl font-semibold text-stone-900 dark:text-stone-100">{recipe.title}</h2>
        {recipe.summary ? <p className="text-stone-700 dark:text-stone-300">{recipe.summary}</p> : null}
        <p className="text-sm text-stone-600 dark:text-stone-400">
          {ORIGINS[recipe.origin] || recipe.origin} · serves {recipe.servings}
          {recipe.prep_min !== null ? ` · prep ${recipe.prep_min} min` : ""}
          {recipe.cook_min !== null ? ` · cook ${recipe.cook_min} min` : ""}
        </p>
        <p className="text-sm text-stone-700 dark:text-stone-300">
          Per serving: <Macros recipe={recipe} />
          {recipe.nutrition_basis ? <span className="text-stone-500 dark:text-stone-400"> ({BASES[recipe.nutrition_basis]})</span> : null}
        </p>
      </header>

      <div className="flex flex-wrap gap-2">
        <button className={btnPlain} onClick={() => onEdit(recipe)}>
          Edit
        </button>
        <button
          className={btnPlain}
          aria-pressed={recipe.favorite === 1}
          onClick={() =>
            setFavorite(id, recipe.favorite !== 1)
              .then(() => (load(), onChanged()))
              .catch(reportError)
          }
        >
          {recipe.favorite === 1 ? "Remove from favorites" : "Add to favorites"}
        </button>
        {confirming ? (
          <>
            <button
              className={btnDanger}
              onClick={() =>
                deleteRecipe(id)
                  .then(() => (onChanged(), onBack()))
                  .catch((err) => (setConfirming(false), reportError(err)))
              }
            >
              Yes, delete it
            </button>
            <button className={btnPlain} onClick={() => setConfirming(false)}>
              Keep it
            </button>
          </>
        ) : (
          <button className={btnDanger} onClick={() => setConfirming(true)}>
            Delete
          </button>
        )}
      </div>

      <section aria-label="Shelves for this recipe">
        <h3 className="font-semibold">Shelves</h3>
        {recipe.shelves.length ? (
          <ul className="mt-1 flex flex-wrap gap-2">
            {recipe.shelves.map((s) => (
              <li key={s.id} className="rounded-full bg-stone-100 dark:bg-stone-800 px-3 py-0.5 text-sm">
                {s.name}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-stone-500 dark:text-stone-400">Not on a shelf.</p>
        )}
      </section>

      <section aria-label="Ingredients">
        <h3 className="font-semibold">Ingredients</h3>
        {recipe.ingredients.length ? (
          <ul className="mt-1 list-disc pl-5">
            {recipe.ingredients.map((i, n) => (
              <li key={n}>{[i.qty, i.item].filter(Boolean).join(" ")}</li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-stone-500 dark:text-stone-400">No ingredients yet.</p>
        )}
      </section>

      <section aria-label="Steps">
        <h3 className="font-semibold">Steps</h3>
        {recipe.steps.length ? (
          <ol className="mt-1 list-decimal space-y-1 pl-5">
            {recipe.steps.map((s, n) => (
              <li key={n}>{s}</li>
            ))}
          </ol>
        ) : (
          <p className="text-sm text-stone-500 dark:text-stone-400">No steps yet.</p>
        )}
      </section>

      {recipe.links.length ? (
        <section aria-label="Linked meals">
          <h3 className="font-semibold">Health-log meals</h3>
          <ul className="mt-1 space-y-1 text-sm">
            {recipe.links.map((l) => (
              <li key={l.id}>
                {l.meal_name || "Meal"} on {l.meal_day || "an unknown day"}
                {l.meal_kcal !== null && l.meal_kcal !== undefined ? ` · ${l.meal_kcal} kcal` : ""}
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </article>
  );
}

function RecipeForm({ id, initial, shelves, onDone, onCancel, reportError }) {
  const [form, setForm] = useState(initial);
  const [error, setError] = useState(null);
  const [saving, setSaving] = useState(false);
  const set = (patch) => setForm((f) => ({ ...f, ...patch }));
  const setIngredient = (n, patch) => set({ ingredients: form.ingredients.map((row, i) => (i === n ? { ...row, ...patch } : row)) });

  const submit = (event) => {
    event.preventDefault();
    const checked = validateForm(form);
    if (checked.error) return setError(checked.error);
    setError(null);
    setSaving(true);
    saveRecipe({ id, fields: checked.fields, shelfIds: form.shelfIds, links: form.links })
      .then(onDone)
      .catch((err) => {
        setSaving(false);
        if (err.partialId) {
          // The recipe row is stored; open it and say which part is missing.
          reportError(err);
          onDone(err.partialId);
        } else if (isStorageFull(err)) reportError(err);
        else setError(errText(err));
      });
  };

  return (
    <form className="space-y-4" onSubmit={submit} aria-label={id ? "Edit recipe" : "Add recipe"}>
      <h2 className="text-xl font-semibold">{id ? "Edit recipe" : "Add recipe"}</h2>
      <ErrorLine error={error} />
      {form.links.length ? (
        <Banner>
          Linked to your health log: {form.links.map((l) => `${l.meal_name || "meal"} (${l.meal_day || "?"})`).join(", ")}
        </Banner>
      ) : null}

      <label className="block text-sm">
        Title
        <input className={field} value={form.title} onChange={(e) => set({ title: e.target.value })} />
      </label>
      <label className="block text-sm">
        Summary
        <textarea className={field} rows={2} value={form.summary} onChange={(e) => set({ summary: e.target.value })} />
      </label>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <label className="block text-sm">
          Servings
          <input className={field} inputMode="decimal" value={form.servings} onChange={(e) => set({ servings: e.target.value })} />
        </label>
        <label className="block text-sm">
          Prep minutes
          <input className={field} inputMode="numeric" value={form.prep_min} onChange={(e) => set({ prep_min: e.target.value })} />
        </label>
        <label className="block text-sm">
          Cook minutes
          <input className={field} inputMode="numeric" value={form.cook_min} onChange={(e) => set({ cook_min: e.target.value })} />
        </label>
        <label className="block text-sm">
          Kind
          <select className={field} value={form.origin} onChange={(e) => set({ origin: e.target.value })}>
            {Object.entries(ORIGINS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
      </div>

      <fieldset className="space-y-2">
        <legend className="text-sm font-medium">Ingredients</legend>
        {form.ingredients.map((row, n) => (
          <div key={n} className="flex gap-2">
            <input
              aria-label={`Ingredient ${n + 1} amount`}
              className={`${field} w-28`}
              placeholder="200 g"
              value={row.qty}
              onChange={(e) => setIngredient(n, { qty: e.target.value })}
            />
            <input
              aria-label={`Ingredient ${n + 1} name`}
              className={field}
              placeholder="flour"
              value={row.item}
              onChange={(e) => setIngredient(n, { item: e.target.value })}
            />
            <button
              type="button"
              className={btnPlain}
              aria-label={`Remove ingredient ${n + 1}`}
              onClick={() => set({ ingredients: form.ingredients.filter((_, i) => i !== n) })}
            >
              Remove
            </button>
          </div>
        ))}
        <button type="button" className={btnPlain} onClick={() => set({ ingredients: [...form.ingredients, { qty: "", item: "" }] })}>
          Add ingredient
        </button>
      </fieldset>

      <label className="block text-sm">
        Steps (one per line)
        <textarea className={field} rows={5} value={form.steps} onChange={(e) => set({ steps: e.target.value })} />
      </label>

      <fieldset className="space-y-2">
        <legend className="text-sm font-medium">Nutrition per serving</legend>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <label className="block text-sm">
            Calories
            <input className={field} inputMode="numeric" value={form.kcal} onChange={(e) => set({ kcal: e.target.value })} />
          </label>
          <label className="block text-sm">
            Protein (g)
            <input className={field} inputMode="decimal" value={form.protein_g} onChange={(e) => set({ protein_g: e.target.value })} />
          </label>
          <label className="block text-sm">
            Carbs (g)
            <input className={field} inputMode="decimal" value={form.carbs_g} onChange={(e) => set({ carbs_g: e.target.value })} />
          </label>
          <label className="block text-sm">
            Fat (g)
            <input className={field} inputMode="decimal" value={form.fat_g} onChange={(e) => set({ fat_g: e.target.value })} />
          </label>
          <label className="col-span-2 block text-sm sm:col-span-4">
            Numbers come from
            <select className={field} value={form.nutrition_basis} onChange={(e) => set({ nutrition_basis: e.target.value })}>
              <option value="">Not set</option>
              {Object.entries(BASES).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
        </div>
      </fieldset>

      {shelves.length ? (
        <fieldset className="space-y-1">
          <legend className="text-sm font-medium">Shelves</legend>
          {shelves.map((s) => (
            <label key={s.id} className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={form.shelfIds.includes(s.id)}
                onChange={(e) => set({ shelfIds: e.target.checked ? [...form.shelfIds, s.id] : form.shelfIds.filter((x) => x !== s.id) })}
              />
              {s.name}
            </label>
          ))}
        </fieldset>
      ) : null}

      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={form.favorite} onChange={(e) => set({ favorite: e.target.checked })} />
        Favorite
      </label>

      <div className="flex gap-2">
        <button type="submit" className={btnPrimary} disabled={saving}>
          {saving ? "Saving…" : "Save recipe"}
        </button>
        <button type="button" className={btnPlain} onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function MealPicker({ onPick, onCancel }) {
  const [state, setState] = useState({ status: "loading" });

  useEffect(() => {
    let live = true;
    Promise.all([listHealthMeals(), linkedMealIds()])
      .then(([meals, linked]) => live && setState({ status: "ready", meals, linked }))
      .catch((err) => live && setState({ status: "error", message: errText(err) }));
    return () => {
      live = false;
    };
  }, []);

  return (
    <section aria-label="Start from a health-log entry" className="space-y-3">
      <h2 className="text-xl font-semibold">Start from a health-log entry</h2>
      <p className="text-sm text-stone-600 dark:text-stone-400">Pick a meal you logged. This app only reads your health log; it never changes it.</p>
      {state.status === "loading" ? <p className="text-sm text-stone-500 dark:text-stone-400">Loading your meals…</p> : null}
      {state.status === "error" ? (
        <Banner tone="error">
          Your health log is not available to this app ({state.message}). Install the Health Log sample, or check that this app may read it.
        </Banner>
      ) : null}
      {state.status === "ready" && state.meals.length === 0 ? <p className="text-sm text-stone-600 dark:text-stone-400">No meals logged yet.</p> : null}
      {state.status === "ready" ? (
        <ul className="divide-y divide-stone-200 rounded-md border border-stone-200 bg-white dark:divide-stone-700 dark:border-stone-700 dark:bg-stone-900">
          {state.meals.map((m) => (
            <li key={m.id} className="flex items-center justify-between gap-3 p-3">
              <div className="text-sm">
                <div className="font-medium">{m.name}</div>
                <div className="text-stone-600 dark:text-stone-400">
                  {m.day} · {m.slot} · {m.kcal} kcal
                  {state.linked.has(m.id) ? " · already has a recipe" : ""}
                </div>
              </div>
              <button className={`${btnPlain} shrink-0`} aria-label={`Use ${m.name} on ${m.day}`} onClick={() => onPick(m)}>
                Use this meal
              </button>
            </li>
          ))}
        </ul>
      ) : null}
      <button className={btnPlain} onClick={onCancel}>
        Back to recipes
      </button>
    </section>
  );
}

function ShelfManager({ shelves, onChanged, onBack, reportError }) {
  const [name, setName] = useState("");
  const [renaming, setRenaming] = useState(null);
  const [error, setError] = useState(null);
  const act = (promise) =>
    promise
      .then(() => (setError(null), onChanged()))
      .catch((err) => (isStorageFull(err) ? reportError(err) : setError(errText(err))));

  return (
    <section aria-label="Manage shelves" className="space-y-3">
      <h2 className="text-xl font-semibold">Shelves</h2>
      <ErrorLine error={error} />
      <form
        className="flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (!name.trim()) return setError("Give the shelf a name.");
          act(createShelf(name.trim()).then(() => setName("")));
        }}
      >
        <label className="flex-1 text-sm">
          <span className="sr-only">New shelf name</span>
          <input className={field} placeholder="New shelf, e.g. Weeknight dinners" value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <button type="submit" className={btnPrimary}>
          Add shelf
        </button>
      </form>
      <ul className="divide-y divide-stone-200 rounded-md border border-stone-200 bg-white dark:divide-stone-700 dark:border-stone-700 dark:bg-stone-900">
        {shelves.map((s) => (
          <li key={s.id} className="flex items-center justify-between gap-2 p-3 text-sm">
            {renaming && renaming.id === s.id ? (
              <form
                className="flex flex-1 gap-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!renaming.name.trim()) return setError("Give the shelf a name.");
                  act(renameShelf(s.id, renaming.name.trim()).then(() => setRenaming(null)));
                }}
              >
                <input aria-label={`New name for ${s.name}`} className={field} value={renaming.name} onChange={(e) => setRenaming({ id: s.id, name: e.target.value })} />
                <button type="submit" className={btnPrimary}>
                  Save
                </button>
                <button type="button" className={btnPlain} onClick={() => setRenaming(null)}>
                  Cancel
                </button>
              </form>
            ) : (
              <>
                <span>
                  {s.name} <span className="text-stone-500 dark:text-stone-400">({s.recipe_count})</span>
                </span>
                <span className="flex gap-2">
                  <button className={btnPlain} aria-label={`Rename ${s.name}`} onClick={() => setRenaming({ id: s.id, name: s.name })}>
                    Rename
                  </button>
                  <button className={btnDanger} aria-label={`Delete shelf ${s.name}`} onClick={() => act(deleteShelf(s.id))}>
                    Delete
                  </button>
                </span>
              </>
            )}
          </li>
        ))}
        {shelves.length === 0 ? <li className="p-3 text-sm text-stone-500 dark:text-stone-400">No shelves yet.</li> : null}
      </ul>
      <p className="text-xs text-stone-500 dark:text-stone-400">Deleting a shelf keeps its recipes; they just come off the shelf.</p>
      <button className={btnPlain} onClick={onBack}>
        Back to recipes
      </button>
    </section>
  );
}

// ------------------------------------------------------------------------ app

export default function App() {
  const [boot, setBoot] = useState({ status: "loading" });
  const [route, setRoute] = useState({ name: "list" });
  const [shelves, setShelves] = useState([]);
  const [prefs, setPrefs] = useState({});
  const [storageFull, setStorageFull] = useState(false);
  const [problem, setProblem] = useState(null);
  const [version, setVersion] = useState(0);

  const reportError = useCallback((err) => {
    const full = isStorageFull(err);
    if (full) setStorageFull(true);
    if (!full || (err && err.partialId)) setProblem(errText(err));
  }, []);

  const refreshShelves = useCallback(() => listShelves().then(setShelves).catch(reportError), [reportError]);

  useEffect(() => {
    let live = true;
    (async () => {
      try {
        await ensureSchema();
      } catch (err) {
        if (isStorageFull(err)) setStorageFull(true);
        else return live && setBoot({ status: "error", message: errText(err) });
      }
      const loaded = await loadPrefs().catch(() => ({}));
      if (!live) return;
      setPrefs(loaded);
      await refreshShelves();
      if (live) setBoot({ status: "ready" });
    })();
    return () => {
      live = false;
    };
  }, [refreshShelves]);

  const changePrefs = (patch) => {
    const next = { ...prefs, ...patch };
    setPrefs(next);
    savePrefs(next).catch(reportError);
  };

  const changed = () => {
    setVersion((v) => v + 1);
    refreshShelves();
  };
  const toList = () => setRoute({ name: "list" });

  let screen;
  if (boot.status === "loading") screen = <p className="text-sm text-stone-500 dark:text-stone-400">Opening your recipe book…</p>;
  else if (boot.status === "error") {
    screen = <Banner tone="error">Could not open your recipe book: {boot.message}</Banner>;
  } else if (route.name === "detail") {
    screen = (
      <RecipeDetail
        key={`${route.id}:${version}`}
        id={route.id}
        onBack={toList}
        onChanged={changed}
        onEdit={(recipe) => setRoute({ name: "form", id: route.id, initial: formFromRecipe(recipe) })}
        reportError={reportError}
      />
    );
  } else if (route.name === "form") {
    screen = (
      <RecipeForm
        id={route.id}
        initial={route.initial}
        shelves={shelves}
        reportError={reportError}
        onCancel={() => (route.id ? setRoute({ name: "detail", id: route.id }) : toList())}
        onDone={(rid) => (changed(), setRoute({ name: "detail", id: rid }))}
      />
    );
  } else if (route.name === "meals") {
    screen = <MealPicker onCancel={toList} onPick={(meal) => setRoute({ name: "form", initial: formFromMeal(meal) })} />;
  } else if (route.name === "shelves") {
    screen = <ShelfManager shelves={shelves} onChanged={changed} onBack={toList} reportError={reportError} />;
  } else {
    screen = (
      <RecipeList
        key={version}
        shelves={shelves}
        prefs={prefs}
        onPrefs={changePrefs}
        onOpen={(id) => setRoute({ name: "detail", id })}
        onAdd={() => setRoute({ name: "form", initial: blankForm() })}
        onFromMeal={() => setRoute({ name: "meals" })}
        onShelves={() => setRoute({ name: "shelves" })}
        reportError={reportError}
      />
    );
  }

  return (
    <main className="mx-auto max-w-3xl space-y-4 p-4 text-stone-900 [overflow-wrap:anywhere] dark:text-stone-100">
      <h1 className="text-3xl font-bold">Recipes</h1>
      {storageFull ? (
        <Banner>
          <strong>Storage full: read-only.</strong> Your TinyCloud storage, shared by all your TinyCloud apps, is full. You can still view and copy your data.
          Saving changes is paused until you free up space or upgrade your plan.
        </Banner>
      ) : null}
      {problem ? (
        <div className="flex items-start justify-between gap-2">
          <ErrorLine error={problem} />
          <button className={btnPlain} onClick={() => setProblem(null)}>
            Dismiss
          </button>
        </div>
      ) : null}
      {screen}
    </main>
  );
}

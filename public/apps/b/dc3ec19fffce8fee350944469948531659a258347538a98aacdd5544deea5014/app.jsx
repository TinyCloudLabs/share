// Health Log: xyz.tinycloud.sample.healthlog
//
// A tiny app: this one file plus manifest.json, schema.sql and knowledge/.
// It runs sealed in the sandbox (no network, no eval, no storage of its own).
// Its only door to data is the bridge: import { sql, kv } from "@tinycloud/app".
//
// Writes follow one protocol: the client makes an operation id (op_id) once per
// submission, INSERTs with ON CONFLICT(op_id) DO NOTHING, then ALWAYS reads the
// row back by op_id. Replays, double clicks and lost responses cannot create a
// second row, and a "timed out" write is only reported as failed when the
// read-back also finds nothing.

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Bar,
  CartesianGrid,
  ComposedChart,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { kv as bridgeKv, sql as bridgeSql } from "@tinycloud/app";

// ---------------------------------------------------------------------------
// Constants

export const DB = "healthlog";
export const SLOTS = ["breakfast", "lunch", "dinner", "snack"];
export const DEFAULT_GOALS = { kcal: 2000 };
const GOALS_KEY = "prefs/goals.json";

// The bridge allows 4 calls in flight and refuses the rest. The app keeps itself
// under that: at most 3 at a time, the others wait their turn here.
const MAX_CONCURRENT = 3;
let active = 0;
const waiting = [];
function gated(fn) {
  return new Promise((resolve) => {
    const run = async () => {
      active += 1;
      try {
        resolve(await fn());
      } catch (e) {
        resolve({ ok: false, error: { code: "INTERNAL", message: String(e?.message ?? e) } });
      } finally {
        active -= 1;
        waiting.shift()?.();
      }
    };
    if (active < MAX_CONCURRENT) run();
    else waiting.push(run);
  });
}
const sql = {
  query: (...a) => gated(() => bridgeSql.query(...a)),
  execute: (...a) => gated(() => bridgeSql.execute(...a)),
};
const kv = {
  get: (...a) => gated(() => bridgeKv.get(...a)),
  put: (...a) => gated(() => bridgeKv.put(...a)),
  list: (...a) => gated(() => bridgeKv.list(...a)),
  del: (...a) => gated(() => bridgeKv.del(...a)),
};
const SCHEMA_KEY = "app/schema.sql";
const REQUIRED_OBJECTS = ["meal", "weight", "day_card", "week_rollup"];
const RETRYABLE = new Set(["TIMEOUT", "BUSY", "INTERNAL"]);

// ---------------------------------------------------------------------------
// Small helpers (pure)

const pad = (n) => String(n).padStart(2, "0");

/** Local calendar day as YYYY-MM-DD. */
export function localDay(date = new Date()) {
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

/** Calendar arithmetic on YYYY-MM-DD strings (no timezone involved). */
export function addDays(day, n) {
  const [y, m, d] = day.split("-").map(Number);
  const t = new Date(Date.UTC(y, m - 1, d + n));
  return `${t.getUTCFullYear()}-${pad(t.getUTCMonth() + 1)}-${pad(t.getUTCDate())}`;
}

/** The n days ending at endDay, oldest first. */
export function lastNDays(endDay, n = 7) {
  return Array.from({ length: n }, (_, i) => addDays(endDay, i - (n - 1)));
}

const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
export function weekdayLabel(day) {
  const [y, m, d] = day.split("-").map(Number);
  return WEEKDAYS[new Date(Date.UTC(y, m - 1, d)).getUTCDay()];
}

/** Client-generated operation id: sortable time prefix + 96 random bits. */
export function newOpId() {
  const bytes = new Uint8Array(12);
  globalThis.crypto.getRandomValues(bytes);
  const rand = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `op_${Date.now().toString(36)}_${rand}`;
}

const fmt = (n, digits = 0) =>
  Number(n ?? 0).toLocaleString("en-US", { maximumFractionDigits: digits, minimumFractionDigits: 0 });

/** Rows of arrays + column names -> array of objects. */
export function toObjects(result) {
  return result.rows.map((row) => Object.fromEntries(result.columns.map((c, i) => [c, row[i]])));
}

function invalid(message) {
  return { ok: false, error: { code: "INVALID", message } };
}

function num(value, fallback = 0) {
  if (value === "" || value === null || value === undefined) return fallback;
  const n = Number(value);
  return Number.isFinite(n) ? n : NaN;
}

export function validateMeal(input) {
  const name = String(input?.name ?? "").trim();
  if (name.length < 1 || name.length > 200) return invalid("Name must be 1 to 200 characters.");
  if (!SLOTS.includes(input?.slot)) return invalid(`Slot must be one of ${SLOTS.join(", ")}.`);
  const kcal = num(input?.kcal, NaN);
  if (!Number.isInteger(kcal) || kcal < 0 || kcal > 5000) return invalid("Calories must be a whole number from 0 to 5000.");
  const macros = {};
  for (const key of ["protein_g", "carbs_g", "fat_g"]) {
    const v = num(input?.[key]);
    if (!(v >= 0) || v > 2000) return invalid(`${key.replace("_g", "")} must be a number from 0 to 2000 grams.`);
    macros[key] = v;
  }
  const note = String(input?.note ?? "").trim().slice(0, 500) || null;
  return { ok: true, value: { name, slot: input.slot, kcal, ...macros, note } };
}

export function validateWeight(input) {
  const weight_kg = num(input?.weight_kg, NaN);
  if (!(weight_kg >= 20 && weight_kg <= 500)) return invalid("Weight must be between 20 and 500 kg.");
  const note = String(input?.note ?? "").trim().slice(0, 500) || null;
  return { ok: true, value: { weight_kg, note } };
}

/** Split a SQL file into statements (handles -- comments and 'quoted;' text). */
export function splitSql(text) {
  const out = [];
  let cur = "";
  let quote = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quote) {
      cur += ch;
      if (ch === "'") quote = false;
    } else if (ch === "'") {
      quote = true;
      cur += ch;
    } else if (ch === "-" && text[i + 1] === "-") {
      while (i < text.length && text[i] !== "\n") i += 1;
      cur += "\n";
    } else if (ch === ";") {
      if (cur.trim()) out.push(cur.trim());
      cur = "";
    } else {
      cur += ch;
    }
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

// ---------------------------------------------------------------------------
// Data access (every call goes through the bridge; nothing throws)

const decoder = new TextDecoder();

/** Make sure the tables and views exist; reads the installed app/schema.sql if not. */
export async function ensureSchema() {
  const have = await sql.query(
    DB,
    "SELECT name FROM sqlite_master WHERE type IN ('table', 'view') AND name IN (?, ?, ?, ?)",
    REQUIRED_OBJECTS,
  );
  if (have.ok && have.rows.length === REQUIRED_OBJECTS.length) return { ok: true, created: false };
  const file = await kv.get(SCHEMA_KEY);
  if (!file.ok) return { ok: false, error: { ...file.error, message: `Cannot read ${SCHEMA_KEY}: ${file.error.message}` } };
  for (const statement of splitSql(decoder.decode(file.bytes))) {
    const r = await sql.execute(DB, statement);
    if (!r.ok) return r;
  }
  return { ok: true, created: true };
}

export const GOAL_MESSAGE = "Daily target must be a whole number from 500 to 10000 kcal.";

/** A usable daily target: a whole number of kcal from 500 to 10000. */
export function isValidGoal(kcal) {
  return Number.isInteger(kcal) && kcal >= 500 && kcal <= 10000;
}

export async function loadGoals() {
  const r = await kv.get(GOALS_KEY);
  if (!r.ok) return { ...DEFAULT_GOALS };
  try {
    const parsed = JSON.parse(decoder.decode(r.bytes));
    return isValidGoal(parsed?.kcal) ? { ...DEFAULT_GOALS, kcal: parsed.kcal } : { ...DEFAULT_GOALS };
  } catch {
    return { ...DEFAULT_GOALS };
  }
}

export async function saveGoals(goals) {
  const kcal = typeof goals?.kcal === "number" ? goals.kcal : NaN;
  if (!isValidGoal(kcal)) return invalid(GOAL_MESSAGE);
  return kv.put(GOALS_KEY, JSON.stringify({ kcal }), { contentType: "application/json" });
}

const CARD_COLUMNS = "day, kcal, protein_g, carbs_g, fat_g, meals, weight_kg";

/** Today's totals (from the day_card view) and the meals behind them. */
export async function loadToday(day) {
  const [card, meals] = await Promise.all([
    sql.query(DB, `SELECT ${CARD_COLUMNS} FROM day_card WHERE day = ?`, [day]),
    sql.query(
      DB,
      "SELECT id, slot, name, kcal, protein_g, carbs_g, fat_g FROM meal WHERE day = ? ORDER BY logged_at, id",
      [day],
    ),
  ]);
  if (!card.ok) return card;
  if (!meals.ok) return meals;
  return { ok: true, card: card.rows.length ? toObjects(card)[0] : null, meals: toObjects(meals) };
}

/** The last 7 days (from week_rollup), with empty days filled in. */
export async function loadWeek(endDay, n = 7) {
  const days = lastNDays(endDay, n);
  const r = await sql.query(
    DB,
    `SELECT ${CARD_COLUMNS}, kcal_avg7, weight_avg7 FROM week_rollup WHERE day BETWEEN ? AND ? ORDER BY day`,
    [days[0], days[days.length - 1]],
  );
  if (!r.ok) return r;
  const byDay = new Map(toObjects(r).map((row) => [row.day, row]));
  const rows = days.map((day) => ({
    day,
    label: weekdayLabel(day),
    ...(byDay.get(day) ?? { kcal: 0, protein_g: 0, carbs_g: 0, fat_g: 0, meals: 0, weight_kg: null }),
  }));
  return { ok: true, rows };
}

/**
 * Insert-then-read-back. Safe to call again with the same opId.
 * Returns { ok, opId, duplicate, row } or { ok: false, opId, error }.
 */
async function writeWithReadBack({ table, columns, values, opId, readColumns }) {
  let error;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const w = await sql.execute(
      DB,
      `INSERT INTO ${table} (${columns.join(", ")}) VALUES (${columns.map(() => "?").join(", ")}) ON CONFLICT(op_id) DO NOTHING`,
      values,
    );
    // Read back even if the write reported a failure: a timeout can hide a success.
    const r = await sql.query(DB, `SELECT ${readColumns} FROM ${table} WHERE op_id = ?`, [opId]);
    if (r.ok && r.rows.length === 1) {
      return { ok: true, opId, duplicate: w.ok && w.changes === 0, row: toObjects(r)[0] };
    }
    error = !w.ok ? w.error : !r.ok ? r.error : { code: "READBACK_MISSING", message: "The write was accepted but the row cannot be read back." };
    if (!RETRYABLE.has(error.code)) break;
  }
  return { ok: false, opId, error };
}

export async function logMeal(input, { opId = newOpId(), now = new Date(), day = localDay(now), source = "app" } = {}) {
  const v = validateMeal(input);
  if (!v.ok) return { ...v, opId };
  const m = v.value;
  return writeWithReadBack({
    table: "meal",
    columns: ["op_id", "day", "slot", "name", "kcal", "protein_g", "carbs_g", "fat_g", "note", "source", "logged_at"],
    values: [opId, day, m.slot, m.name, m.kcal, m.protein_g, m.carbs_g, m.fat_g, m.note, source, now.toISOString()],
    opId,
    readColumns: "id, op_id, day, slot, name, kcal, protein_g, carbs_g, fat_g, logged_at",
  });
}

export async function logWeight(input, { opId = newOpId(), now = new Date(), day = localDay(now), source = "app" } = {}) {
  const v = validateWeight(input);
  if (!v.ok) return { ...v, opId };
  const w = v.value;
  return writeWithReadBack({
    table: "weight",
    columns: ["op_id", "day", "weight_kg", "note", "source", "logged_at"],
    values: [opId, day, w.weight_kg, w.note, source, now.toISOString()],
    opId,
    readColumns: "id, op_id, day, weight_kg, logged_at",
  });
}

// ---------------------------------------------------------------------------
// Components

const card = "rounded-2xl border border-neutral-200 bg-white p-4 shadow-sm dark:border-neutral-800 dark:bg-neutral-900";
const input =
  "w-full rounded-lg border border-neutral-300 bg-white px-3 py-2 text-sm text-neutral-900 outline-none focus:border-emerald-500 dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-100";
const button =
  "rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-700 disabled:opacity-50";

function Macro({ label, value, testId }) {
  return (
    <div className="rounded-xl bg-neutral-100 px-3 py-2 text-center dark:bg-neutral-800">
      <div className="text-xs uppercase tracking-wide text-neutral-500">{label}</div>
      <div className="text-lg font-semibold" data-testid={testId}>
        {fmt(value)} g
      </div>
    </div>
  );
}

export function TodayCard({ day, card: dayCard, meals = [], goals = DEFAULT_GOALS, onGoal }) {
  const kcal = dayCard?.kcal ?? 0;
  const pct = isValidGoal(goals.kcal) ? Math.min(100, Math.round((kcal / goals.kcal) * 100)) : 0;
  const [goalText, setGoalText] = useState(String(goals.kcal));
  const [goalError, setGoalError] = useState(null);
  useEffect(() => setGoalText(String(goals.kcal)), [goals.kcal]);

  // Commit on blur. An invalid value is never stored and never kept on screen: the
  // field goes back to the current target and an alert says why.
  async function commitGoal() {
    const text = goalText.trim();
    if (text === String(goals.kcal)) return setGoalError(null);
    const n = /^\d+$/.test(text) ? Number(text) : NaN;
    if (!isValidGoal(n)) {
      setGoalError(GOAL_MESSAGE);
      setGoalText(String(goals.kcal));
      return;
    }
    const r = await onGoal?.(n);
    if (r && !r.ok) {
      setGoalError(r.error?.message ?? "Could not save the daily target.");
      setGoalText(String(goals.kcal));
    } else {
      setGoalError(null);
    }
  }
  return (
    <section className={card} data-testid="today-card" aria-label="Today">
      <div className="flex items-baseline justify-between">
        <h2 className="text-lg font-semibold">Today</h2>
        <span className="text-sm text-neutral-500" data-testid="today-day">{day}</span>
      </div>
      <div className="mt-3 flex items-end justify-between">
        <div>
          <span className="text-4xl font-bold" data-testid="today-kcal">{fmt(kcal)}</span>
          <span className="ml-1 text-sm text-neutral-500">kcal</span>
        </div>
        <label className="text-xs text-neutral-500">
          Target
          <input
            aria-label="Daily target kcal"
            className={`${input} mt-1 w-24`}
            inputMode="numeric"
            value={goalText}
            onChange={(e) => {
              setGoalText(e.target.value);
              setGoalError(null);
            }}
            onBlur={commitGoal}
            aria-invalid={goalError ? "true" : undefined}
          />
        </label>
      </div>
      {goalError && (
        <p role="alert" className="mt-1 text-sm text-red-600 dark:text-red-400" data-testid="goal-error">
          {goalError}
        </p>
      )}
      <div className="mt-2 h-2 overflow-hidden rounded-full bg-neutral-200 dark:bg-neutral-800" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
        <div className="h-full bg-emerald-500" style={{ width: `${pct}%` }} data-testid="today-progress" />
      </div>
      <div className="mt-4 grid grid-cols-3 gap-2">
        <Macro label="Protein" value={dayCard?.protein_g} testId="today-protein" />
        <Macro label="Carbs" value={dayCard?.carbs_g} testId="today-carbs" />
        <Macro label="Fat" value={dayCard?.fat_g} testId="today-fat" />
      </div>
      <div className="mt-4 flex items-center justify-between text-sm">
        <span data-testid="today-meals-count">{dayCard?.meals ?? 0} {dayCard?.meals === 1 ? "meal" : "meals"}</span>
        <span data-testid="today-weight">
          {dayCard?.weight_kg != null ? `${fmt(dayCard.weight_kg, 1)} kg` : "No weight yet"}
        </span>
      </div>
      {meals.length > 0 && (
        <ul className="mt-3 divide-y divide-neutral-200 text-sm dark:divide-neutral-800" data-testid="today-meals">
          {meals.map((m) => (
            <li key={m.id} className="flex justify-between py-1.5">
              <span>
                <span className="mr-2 text-xs uppercase text-neutral-500">{m.slot}</span>
                {m.name}
              </span>
              <span className="tabular-nums">{fmt(m.kcal)} kcal</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

const EMPTY_MEAL = { slot: "breakfast", name: "", kcal: "", protein_g: "", carbs_g: "", fat_g: "" };

export function MealForm({ onSubmit }) {
  const [form, setForm] = useState(EMPTY_MEAL);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);
  // One op id per submission: a retry (double click, re-submit after an error) reuses it.
  const opId = useRef(newOpId());
  const submitting = useRef(false); // a ref, not state: two submits in one tick must not both run
  const set = (key) => (e) => setForm((f) => ({ ...f, [key]: e.target.value }));

  async function submit(e) {
    e.preventDefault();
    if (submitting.current) return;
    submitting.current = true;
    setBusy(true);
    const r = await onSubmit(form, opId.current);
    submitting.current = false;
    setBusy(false);
    if (r.ok) {
      setMessage({ ok: true, text: r.duplicate ? "Already logged." : "Meal logged." });
      setForm(EMPTY_MEAL);
      opId.current = newOpId();
    } else {
      setMessage({ ok: false, text: r.error?.message ?? "Could not log the meal." });
    }
  }

  return (
    <form className={card} onSubmit={submit} data-testid="meal-form">
      <h2 className="text-lg font-semibold">Log a meal</h2>
      <div className="mt-3 grid grid-cols-2 gap-2">
        <select aria-label="Slot" className={input} value={form.slot} onChange={set("slot")}>
          {SLOTS.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <input aria-label="Calories" className={input} inputMode="numeric" placeholder="kcal" value={form.kcal} onChange={set("kcal")} />
        <input aria-label="Meal name" className={`${input} col-span-2`} placeholder="What did you eat?" value={form.name} onChange={set("name")} />
        <input aria-label="Protein (g)" className={input} inputMode="decimal" placeholder="protein g" value={form.protein_g} onChange={set("protein_g")} />
        <input aria-label="Carbs (g)" className={input} inputMode="decimal" placeholder="carbs g" value={form.carbs_g} onChange={set("carbs_g")} />
        <input aria-label="Fat (g)" className={input} inputMode="decimal" placeholder="fat g" value={form.fat_g} onChange={set("fat_g")} />
        <button type="submit" className={button} disabled={busy}>{busy ? "Saving…" : "Log meal"}</button>
      </div>
      {message && (
        <p role="status" className={`mt-2 text-sm ${message.ok ? "text-emerald-600" : "text-red-600"}`} data-testid="meal-message">
          {message.text}
        </p>
      )}
    </form>
  );
}

export function WeightForm({ onSubmit }) {
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);
  const opId = useRef(newOpId());
  const submitting = useRef(false); // a ref, not state: two submits in one tick must not both run

  async function submit(e) {
    e.preventDefault();
    if (submitting.current) return;
    submitting.current = true;
    setBusy(true);
    const r = await onSubmit({ weight_kg: value }, opId.current);
    submitting.current = false;
    setBusy(false);
    if (r.ok) {
      setMessage({ ok: true, text: r.duplicate ? "Already logged." : "Weight logged." });
      setValue("");
      opId.current = newOpId();
    } else {
      setMessage({ ok: false, text: r.error?.message ?? "Could not log the weight." });
    }
  }

  return (
    <form className={card} onSubmit={submit} data-testid="weight-form">
      <h2 className="text-lg font-semibold">Log weight</h2>
      <div className="mt-3 flex gap-2">
        <input aria-label="Weight (kg)" className={input} inputMode="decimal" placeholder="kg" value={value} onChange={(e) => setValue(e.target.value)} />
        <button type="submit" className={button} disabled={busy}>{busy ? "Saving…" : "Log weight"}</button>
      </div>
      {message && (
        <p role="status" className={`mt-2 text-sm ${message.ok ? "text-emerald-600" : "text-red-600"}`} data-testid="weight-message">
          {message.text}
        </p>
      )}
    </form>
  );
}

/** One line of text for the chart: every day, its kcal and weight. Used as the chart's accessible name. */
export function weekSummaryText(rows) {
  return rows
    .map((r) => `${r.label}: ${r.meals > 0 ? `${fmt(r.kcal)} kcal` : "no meals"}${r.weight_kg != null ? `, ${fmt(r.weight_kg, 1)} kg` : ""}`)
    .join("; ");
}

export function WeekChart({ rows }) {
  const data = useMemo(() => rows.map((r) => ({ ...r, weight: r.weight_kg ?? null })), [rows]);
  const weights = data.map((d) => d.weight).filter((w) => w != null);
  const lo = weights.length ? Math.floor(Math.min(...weights) - 1) : 0;
  const hi = weights.length ? Math.ceil(Math.max(...weights) + 1) : 100;
  return (
    <section className={card} data-testid="week-chart" aria-label="Last 7 days">
      <h2 className="text-lg font-semibold">Last 7 days</h2>
      <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-neutral-600 dark:text-neutral-300" data-testid="week-legend">
        <li className="flex items-center gap-1.5">
          <span aria-hidden="true" className="inline-block h-2.5 w-2.5 rounded-sm bg-emerald-500" />
          Calories (bars, left axis, kcal)
        </li>
        <li className="flex items-center gap-1.5">
          <span aria-hidden="true" className="inline-block h-0.5 w-4 bg-indigo-500" />
          Weight (line, right axis, kg)
        </li>
      </ul>
      <div className="mt-2 h-60 w-full text-neutral-600 dark:text-neutral-300" role="img" aria-label={weekSummaryText(data)} data-testid="week-chart-plot">
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={data} margin={{ top: 8, right: 4, bottom: 0, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="currentColor" strokeOpacity={0.2} />
            <XAxis dataKey="label" tickLine={false} interval={0} tick={{ fill: "currentColor", fontSize: 11 }} />
            <YAxis yAxisId="kcal" width={40} tickLine={false} axisLine={false} tick={{ fill: "currentColor", fontSize: 11 }} />
            <YAxis yAxisId="kg" orientation="right" width={36} domain={[lo, hi]} tickLine={false} axisLine={false} tick={{ fill: "currentColor", fontSize: 11 }} />
            <Tooltip />
            <Bar yAxisId="kcal" dataKey="kcal" name="kcal" fill="#10b981" radius={[4, 4, 0, 0]} isAnimationActive={false} />
            <Line yAxisId="kg" dataKey="weight" name="kg" stroke="#6366f1" strokeWidth={2} connectNulls dot isAnimationActive={false} />
          </ComposedChart>
        </ResponsiveContainer>
      </div>
      <p className="mt-2 text-xs text-neutral-500" data-testid="week-summary">
        {(() => {
          const logged = data.filter((d) => d.meals > 0);
          const avg = logged.length ? Math.round(logged.reduce((s, d) => s + d.kcal, 0) / logged.length) : 0;
          return `${logged.length} of ${data.length} days logged, ${fmt(avg)} kcal average`;
        })()}
      </p>
    </section>
  );
}

export default function App({ now = () => new Date() } = {}) {
  const [state, setState] = useState({ status: "loading" });
  const day = localDay(now());

  const refresh = useCallback(async () => {
    const [today, week, goals] = await Promise.all([loadToday(day), loadWeek(day), loadGoals()]);
    if (!today.ok || !week.ok) {
      setState({ status: "error", message: (today.ok ? week : today).error.message });
      return;
    }
    setState({ status: "ready", today, week: week.rows, goals });
  }, [day]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const schema = await ensureSchema();
      if (cancelled) return;
      if (!schema.ok) return setState({ status: "error", message: schema.error.message });
      await refresh();
    })();
    return () => {
      cancelled = true;
    };
  }, [refresh]);

  const addMeal = useCallback(
    async (form, opId) => {
      const r = await logMeal(form, { opId, now: now(), day });
      if (r.ok) await refresh();
      return r;
    },
    [day, now, refresh],
  );
  const addWeight = useCallback(
    async (form, opId) => {
      const r = await logWeight(form, { opId, now: now(), day });
      if (r.ok) await refresh();
      return r;
    },
    [day, now, refresh],
  );
  const setGoal = useCallback(
    async (kcal) => {
      const r = await saveGoals({ kcal });
      if (r.ok) await refresh();
      return r;
    },
    [refresh],
  );

  return (
    <main className="mx-auto max-w-2xl space-y-4 p-4 text-neutral-900 dark:text-neutral-100">
      <h1 className="text-2xl font-bold">Health Log</h1>
      {state.status === "loading" && <p data-testid="app-loading" className="text-neutral-500">Loading…</p>}
      {state.status === "error" && (
        <p role="alert" data-testid="app-error" className="rounded-lg bg-red-50 p-3 text-sm text-red-700 dark:bg-red-950 dark:text-red-300">
          {state.message}
        </p>
      )}
      {state.status === "ready" && (
        <>
          <TodayCard day={day} card={state.today.card} meals={state.today.meals} goals={state.goals} onGoal={setGoal} />
          <div className="grid gap-4 sm:grid-cols-2">
            <MealForm onSubmit={addMeal} />
            <WeightForm onSubmit={addWeight} />
          </div>
          <WeekChart rows={state.week} />
        </>
      )}
    </main>
  );
}

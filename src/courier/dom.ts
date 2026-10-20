/**
 * Small DOM helpers and the context every screen gets. Every string a screen
 * shows goes in through `textContent`; there is no `innerHTML` in this page
 * outside the markdown renderer's own sanitised path.
 */
import type { Announcer } from "../share/announcer.js";
import type { ThreadRef } from "./model.js";
import type { CourierStore } from "./store.js";

export function el<K extends keyof HTMLElementTagNameMap>(doc: Document, tag: K, className?: string, text?: string): HTMLElementTagNameMap[K] {
  const node = doc.createElement(tag);
  if (className !== undefined) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

let ids = 0;
/** A page-unique id for aria wiring. */
export function uid(prefix: string): string {
  ids += 1;
  return `${prefix}-${ids}`;
}

export interface ViewContext {
  readonly doc: Document;
  readonly store: CourierStore;
  readonly announcer: Announcer;
  now(): number;
  /** Renders `markdown` through Share's sanitising renderer into `host`. Never throws: a failure leaves a plain notice. */
  renderBody(host: HTMLElement, markdown: string, label: string): void;
  /** Reloads the overview (threads, requests) and repaints the current screen. */
  refresh(): Promise<void>;
  openThread(ref: ThreadRef): void;
  showNeedsYou(): void;
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** "5 minutes ago", "in 3 hours": coarse on purpose. */
export function relativeTime(then: number, now: number): string {
  const delta = then - now;
  const abs = Math.abs(delta);
  const formatter = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  if (abs < MINUTE) return "just now";
  if (abs < HOUR) return formatter.format(Math.round(delta / MINUTE), "minute");
  if (abs < DAY) return formatter.format(Math.round(delta / HOUR), "hour");
  return formatter.format(Math.round(delta / DAY), "day");
}

export function absoluteTime(time: number): string {
  return new Date(time).toLocaleString("en", { dateStyle: "medium", timeStyle: "short" });
}

/** A `<time>` whose text is relative and whose title is exact. */
export function timeElement(doc: Document, then: number | undefined, now: number): HTMLElement {
  const node = doc.createElement("time");
  if (then === undefined) { node.textContent = "unknown time"; return node; }
  node.dateTime = new Date(then).toISOString();
  node.textContent = relativeTime(then, now);
  node.title = absoluteTime(then);
  return node;
}

export function status(doc: Document, kind: "info" | "success" | "warning" | "danger", text: string): HTMLElement {
  const node = el(doc, "p", `tc-status tc-status--${kind} cr-status`, text);
  if (kind === "danger" || kind === "warning") node.setAttribute("role", "alert");
  return node;
}


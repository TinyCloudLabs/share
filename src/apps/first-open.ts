/**
 * The first-open disclosure, as plain sentences. The runner page shows it before
 * any sign-in opens. Pure: no DOM.
 */
import type { CatalogEntry } from "./catalog.ts";

export function firstOpenLines(entry: CatalogEntry): string[] {
  return [
    `${entry.name} runs in your TinyCloud with its own sign-in. It can only read and change what its manifest asks for; that list is shown below.`,
    `Published by ${entry.publisher.name}.`,
    "If this app isn't in your TinyCloud, we'll save its files as part of opening it.",
  ];
}

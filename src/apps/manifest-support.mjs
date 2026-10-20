/**
 * Why a manifest cannot be described by the Details sheet (and so cannot be saved), or null. The ONE function the
 * saver, the sheet and scripts/apps-catalog.mjs (`verifyCatalog`) all use.
 *
 * These are the shapes the SDK resolves in a way the sheet's lists and sentences do not mirror, and that matter:
 *  - a `did`: it hands everything the app is granted to another key;
 *  - a `prefix` that is not text: the SDK uses it as it is (`5/`, `null/`), where the sheet would read it as "not given";
 *  - a `space` (the manifest's or a permission's) that is not text or has nothing visible in it: the SDK uses it as
 *    written, where the sheet would call it the app's own data or show an invisible name;
 *  - an invisible character, or a space other than U+0020, in anything the sheet displays as a place (a space, a
 *    path, a service, a secret's name or scope, the prefix): the name shown would not be the name used;
 *  - an explicit `tinycloud.capabilities` grant: the SDK adds that read per space itself, so a hand-written one is a
 *    second row for the same thing.
 * A catalog app has none of them, so they are refused rather than described.
 *
 * @param {unknown} manifest
 * @returns {string|null}
 */
import { hasInvisibleOrSpecialSpace, isVisibleText } from "../share/invisible-text.mjs";

const isObject = (value) => typeof value === "object" && value !== null && !Array.isArray(value);
/** A string shown as a place must not hide characters; non-strings are other checks' business. */
const hides = (value) => typeof value === "string" && hasInvisibleOrSpecialSpace(value);

export function unsupportedManifest(manifest) {
  if (!isObject(manifest)) return null;
  if (manifest.did !== undefined) return "it hands its access to another identity (did)";
  if (manifest.prefix !== undefined && typeof manifest.prefix !== "string") return "its prefix is not text";
  if (hides(manifest.prefix)) return "its prefix has an invisible character";
  if (manifest.space !== undefined && !isVisibleText(manifest.space)) return "its space is not visible text";
  for (const entry of Array.isArray(manifest.permissions) ? manifest.permissions : []) {
    if (!isObject(entry)) continue;
    if (entry.space !== undefined && !isVisibleText(entry.space)) return "one of its permissions names a space that is not visible text";
    if (hides(entry.service) || hides(entry.path)) return "one of its permissions has an invisible character in its service or path";
    // The SDK adds the read of each space's permission list itself; asking for it by hand adds nothing the page could describe.
    if (entry.service === "tinycloud.capabilities" || entry.service === "capabilities") return "it asks for the permission-list read itself (the SDK adds that automatically)";
  }
  if (isObject(manifest.secrets)) {
    for (const [key, spec] of Object.entries(manifest.secrets)) {
      if (hasInvisibleOrSpecialSpace(key)) return "a secret's name has an invisible character";
      if (isObject(spec) && (hides(spec.name) || hides(spec.scope))) return "a secret's name or scope has an invisible character";
    }
  }
  return null;
}

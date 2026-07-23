/**
 * `--expires` duration parsing: a positive integer plus one unit —
 * s(econds), m(inutes), h(ours), d(ays). Nothing looser (no "1h30m", no
 * bare numbers) — fail closed on anything else.
 */

const DURATION_RE = /^(\d+)([smhd])$/;

const UNIT_MS: Record<string, number> = {
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
};

/** Parse a duration like `30d`, `12h`, `45m`, `10s` into milliseconds. */
export function parseDuration(text: string): number {
  const match = DURATION_RE.exec(text);
  if (match === null) {
    throw new TypeError(
      `invalid duration ${JSON.stringify(text)}: expected <integer><s|m|h|d>, e.g. 30d`,
    );
  }
  const [, countText, unit] = match as unknown as [string, string, string];
  const count = Number(countText);
  const unitMs = UNIT_MS[unit];
  if (!Number.isSafeInteger(count) || count <= 0 || unitMs === undefined) {
    throw new TypeError(`invalid duration ${JSON.stringify(text)}`);
  }
  const ms = count * unitMs;
  if (!Number.isSafeInteger(ms)) {
    throw new TypeError(`duration ${JSON.stringify(text)} overflows`);
  }
  return ms;
}

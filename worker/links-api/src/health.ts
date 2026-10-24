import { LINK_TYPES, TYPE_CONFIG, RESERVE } from "./config.ts";
import type { ServiceDeps } from "./service.ts";
import type { StatsByType } from "./storage.ts";
import { accumulateUsage, flushTally, type UsageReport } from "./usage.ts";

export const HEALTH_WINDOW_SECONDS = 60;

const REJECT_CODES = [
  "invalid_request",
  "invalid_signature",
  "unauthorized",
  "blocked",
  "replayed",
  "too_large",
  "rate_limited",
  "capacity",
] as const;
const CAPACITY_REASONS = ["address_live_cap", "reserve", "type_quota"] as const;

function pick<K extends string>(counts: Readonly<Record<string, number>>, prefix: string, keys: readonly K[]): Record<K, number> {
  return Object.fromEntries(keys.map((k) => [k, counts[`${prefix}.${k}`] ?? 0])) as Record<K, number>;
}

/**
 * The `links.health` line (contract 10): counts only. No ids, issuers, nonces, links, bodies or addresses.
 * `live` and `highWater` are null in a run that did not compute the live totals; `usage` carries the day's
 * totals and, with a plan, the percentage of each limit.
 */
export function buildHealthLine(
  counts: Readonly<Record<string, number>>,
  stats: StatsByType | null,
  usage: UsageReport,
): string {
  const highWater =
    stats === null
      ? null
      : LINK_TYPES.filter((type) => {
          const quota = TYPE_CONFIG[type];
          return (
            stats[type].rows >= quota.quotaRows * RESERVE.highWaterFraction ||
            stats[type].bytes >= quota.quotaBytes * RESERVE.highWaterFraction
          );
        });
  return JSON.stringify({
    event: "links.health",
    windowSeconds: HEALTH_WINDOW_SECONDS,
    creates: pick(counts, "creates", LINK_TYPES),
    reads: pick(counts, "reads", ["hit", "miss", "authenticated"] as const),
    deletes: pick(counts, "deletes", ["ok", "miss"] as const),
    rejects: pick(counts, "rejects", REJECT_CODES),
    errors: { internal: counts["errors.internal"] ?? 0 },
    capacityRefusals: pick(counts, "capacity", CAPACITY_REASONS),
    blockedIssuers: counts["blocked.issuer"] ?? 0,
    blockedAddresses: counts["blocked.address"] ?? 0,
    highWater,
    live: stats === null ? null : Object.fromEntries(LINK_TYPES.map((type) => [type, stats[type]])),
    usage: { day: usage.day, ...usage.metrics },
  });
}

/**
 * The scheduled run (every 60 s): sweep, fold the window's counters into the day's usage (the plan alert is
 * emitted from here), then one health line. The live totals scan every live row, so they are computed every
 * `statsEveryMinutes` minutes.
 */
export async function runScheduled(deps: ServiceDeps): Promise<void> {
  const nowSeconds = Math.floor(deps.now() / 1000);
  const { storage, usage } = deps;
  await storage.sweep(nowSeconds);
  const counts = await storage.readCounts();
  const report = await accumulateUsage(storage, {
    counts,
    nowSeconds,
    databaseBytes: usage.tally?.databaseBytes ?? null,
    plan: usage.plan,
    log: deps.log,
  });
  const computeLive = Math.floor(nowSeconds / 60) % usage.statsEveryMinutes === 0;
  const stats = computeLive ? await storage.stats(nowSeconds) : null;
  deps.log(buildHealthLine(counts, stats, report));
  if (usage.tally !== null) {
    await flushTally(storage, usage.tally);
  }
}

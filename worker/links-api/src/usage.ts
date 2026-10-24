import { FREE_PLAN_METRICS, type FreePlan, type FreePlanMetric } from "./config.ts";
import type { LinkStorage } from "./storage.ts";

/** UTC calendar day, `YYYY-MM-DD`; the Free plan daily limits reset at 00:00 UTC. */
export function utcDay(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toISOString().slice(0, 10);
}

/** What the D1 binding reports on each result (`meta`). */
export interface D1Meta {
  readonly rows_read?: number;
  readonly rows_written?: number;
  readonly size_after?: number;
}

/**
 * D1 work done by this isolate that has not been counted yet, and the last database size D1 reported.
 * `take()` hands the pending numbers to the counters and starts again from zero.
 */
export class UsageTally {
  private rowsRead = 0;
  private rowsWritten = 0;
  private sizeBytes: number | null = null;

  record(meta: D1Meta | undefined): void {
    if (meta === undefined) {
      return;
    }
    this.rowsRead += meta.rows_read ?? 0;
    this.rowsWritten += meta.rows_written ?? 0;
    if (typeof meta.size_after === "number") {
      this.sizeBytes = meta.size_after;
    }
  }

  take(): { readonly rowsRead: number; readonly rowsWritten: number } {
    const taken = { rowsRead: this.rowsRead, rowsWritten: this.rowsWritten };
    this.rowsRead = 0;
    this.rowsWritten = 0;
    return taken;
  }

  get databaseBytes(): number | null {
    return this.sizeBytes;
  }
}

/** Moves the tally into the counters that the scheduled run folds into the day's totals. */
export async function flushTally(storage: LinkStorage, tally: UsageTally): Promise<void> {
  const { rowsRead, rowsWritten } = tally.take();
  if (rowsRead > 0) {
    await storage.count("usage.d1_rows_read", rowsRead);
  }
  if (rowsWritten > 0) {
    await storage.count("usage.d1_rows_written", rowsWritten);
  }
}

export interface MetricUsage {
  readonly used: number;
  /** null without a plan (self-host). */
  readonly limit: number | null;
  readonly pct: number | null;
}

export interface UsageReport {
  readonly day: string;
  readonly metrics: Readonly<Record<FreePlanMetric, MetricUsage>>;
}

export interface UsageInput {
  readonly counts: Readonly<Record<string, number>>;
  readonly nowSeconds: number;
  /** Last database size D1 reported (a gauge); null when unknown. */
  readonly databaseBytes: number | null;
  readonly plan: FreePlan | null;
  readonly log: (line: string) => void;
}

const pct = (used: number, limit: number) => Math.round((used * 1000) / limit) / 10;

/**
 * Folds the window's counters into the day's totals, emits `{"alert":"free_plan_70",...}` once per
 * metric per UTC day when a metric is at or above the plan's alert percentage, and returns the usage
 * for the health line. Counts only.
 */
export async function accumulateUsage(storage: LinkStorage, input: UsageInput): Promise<UsageReport> {
  const day = utcDay(input.nowSeconds);
  const totals = await storage.addUsage(day, {
    requests: input.counts["requests"] ?? 0,
    d1_rows_read: input.counts["usage.d1_rows_read"] ?? 0,
    d1_rows_written: input.counts["usage.d1_rows_written"] ?? 0,
  });
  const metrics = {} as Record<FreePlanMetric, MetricUsage>;
  for (const metric of FREE_PLAN_METRICS) {
    const limit = input.plan?.limits[metric];
    const used = limit?.kind === "gauge" ? (input.databaseBytes ?? 0) : (totals[metric] ?? 0);
    metrics[metric] = { used, limit: limit?.limit ?? null, pct: limit ? pct(used, limit.limit) : null };
    if (input.plan && limit && (used * 100) / limit.limit >= input.plan.alertPercent && (await storage.claimAlert(day, metric))) {
      input.log(JSON.stringify({ alert: `free_plan_${input.plan.alertPercent}`, metric, pct: metrics[metric].pct, day }));
    }
  }
  return { day, metrics };
}

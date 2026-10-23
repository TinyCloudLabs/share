import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { WORKERS_FREE_PLAN, type ServiceConfig } from "../src/config.ts";
import { runScheduled } from "../src/health.ts";
import type { ServiceDeps } from "../src/service.ts";
import { UsageTally } from "../src/usage.ts";
import { ADAPTER_FACTORIES, createSqliteAdapter, type Adapter } from "./support/adapters.ts";

const CONFIG: ServiceConfig = {
  audience: "https://api.tinycloud.xyz",
  corsOrigins: [],
  takeOrigins: [],
  addressSalt: "test-salt-0123456789",
  kill: { create: false, read: false, take: false, delete: false },
  clientAddressHeader: "CF-Connecting-IP",
};

const DAY_ONE = Date.UTC(2026, 9, 24, 12, 0, 0);
const DAY_TWO = DAY_ONE + 86_400_000;

function alertLines(lines: string[]): { alert: string; metric: string; pct: number; day: string }[] {
  return lines.filter((l) => l.startsWith('{"alert"')).map((l) => JSON.parse(l));
}

function healthLine(lines: string[]) {
  const found = lines.filter((l) => l.includes('"event":"links.health"')).at(-1);
  return JSON.parse(found ?? "{}");
}

describe.each(ADAPTER_FACTORIES)("free plan 70% alert: $name adapter", ({ create }) => {
  let adapter: Adapter;
  let lines: string[];
  let nowMs: number;
  let tally: UsageTally;
  let deps: ServiceDeps;

  beforeAll(async () => {
    adapter = await create();
  });
  afterAll(async () => {
    await adapter.close();
  });
  beforeEach(async () => {
    await adapter.reset();
    lines = [];
    nowMs = DAY_ONE;
    tally = new UsageTally();
    deps = {
      storage: adapter.storage(),
      config: CONFIG,
      usage: { plan: WORKERS_FREE_PLAN, tally, statsEveryMinutes: 5 },
      now: () => nowMs,
      log: (line) => lines.push(line),
    };
  });

  it("69% emits nothing, 70% emits one line, 71% the same day emits none, the next day emits again", async () => {
    await deps.storage.count("usage.d1_rows_written", 69_000);
    await runScheduled(deps);
    expect(alertLines(lines)).toEqual([]);
    expect(healthLine(lines).usage.d1_rows_written).toEqual({ used: 69_000, limit: 100_000, pct: 69 });

    await deps.storage.count("usage.d1_rows_written", 1_000);
    nowMs += 60_000;
    await runScheduled(deps);
    expect(alertLines(lines)).toEqual([
      { alert: "free_plan_70", metric: "d1_rows_written", pct: 70, day: "2026-10-24" },
    ]);

    await deps.storage.count("usage.d1_rows_written", 1_000);
    nowMs += 60_000;
    await runScheduled(deps);
    expect(alertLines(lines)).toHaveLength(1);
    expect(healthLine(lines).usage.d1_rows_written.pct).toBe(71);

    nowMs = DAY_TWO;
    await deps.storage.count("usage.d1_rows_written", 70_000);
    await runScheduled(deps);
    expect(alertLines(lines)).toHaveLength(2);
    expect(alertLines(lines)[1]).toEqual({ alert: "free_plan_70", metric: "d1_rows_written", pct: 70, day: "2026-10-25" });
  });

  it("each metric alerts once on its own: requests, rows read, and the database size gauge", async () => {
    await deps.storage.count("requests", 70_000);
    await deps.storage.count("usage.d1_rows_read", 3_500_000);
    tally.record({ size_after: 350_000_000 });
    await runScheduled(deps);
    expect(alertLines(lines).map((a) => [a.metric, a.pct]).sort()).toEqual([
      ["d1_database_bytes", 70],
      ["d1_rows_read", 70],
      ["requests", 70],
    ]);
    nowMs += 60_000;
    await runScheduled(deps);
    expect(alertLines(lines)).toHaveLength(3);
  });

  it("counts only: the alert and health lines carry no content", async () => {
    await deps.storage.count("usage.d1_rows_written", 80_000);
    await runScheduled(deps);
    for (const line of lines) {
      expect(line).not.toMatch(/did:key|bafkrei|tlk_|https?:/);
    }
  });
});

describe("self-host: the same counters, no Cloudflare limits", () => {
  it("reports usage without a limit and never alerts", async () => {
    const adapter = await createSqliteAdapter();
    const lines: string[] = [];
    const deps: ServiceDeps = {
      storage: adapter.storage(),
      config: CONFIG,
      usage: { plan: null, tally: null, statsEveryMinutes: 1 },
      now: () => DAY_ONE,
      log: (line) => lines.push(line),
    };
    await deps.storage.count("requests", 500_000);
    await runScheduled(deps);
    expect(alertLines(lines)).toEqual([]);
    expect(healthLine(lines).usage.requests).toEqual({ used: 500_000, limit: null, pct: null });
    expect(healthLine(lines).live).not.toBeNull();
    await adapter.close();
  });
});

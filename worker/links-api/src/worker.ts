import { DEFAULT_STATS_EVERY_MINUTES, WORKERS_FREE_PLAN, configFromEnv, type EnvLike } from "./config.ts";
import { D1Driver, type D1Database } from "./d1-driver.ts";
import { runScheduled } from "./health.ts";
import { jsonResponse } from "./http.ts";
import { handleRequest, type ServiceDeps } from "./service.ts";
import { SqlStorage } from "./sql-storage.ts";
import { UsageTally, flushTally } from "./usage.ts";

interface WorkerEnv extends EnvLike {
  readonly DB: D1Database;
}

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
}

/** D1 work done by this isolate, shared by its requests; each request hands what it has to the counters. */
const tally = new UsageTally();

/**
 * The structured lines of the scheduled run (`links.health`, `free_plan_70`) go to the console as objects, so
 * Workers Logs indexes their fields. This is the only console output of the Worker: the request handler writes
 * none (its failures are counted, not logged), so no request path, URL or link id reaches a log line.
 */
function emit(line: string): void {
  try {
    console.log(JSON.parse(line));
  } catch {
    console.log(line);
  }
}

function depsFor(env: WorkerEnv, log: (line: string) => void): ServiceDeps {
  return {
    storage: new SqlStorage(new D1Driver(env.DB, tally)),
    config: configFromEnv(env),
    usage: { plan: WORKERS_FREE_PLAN, tally, statsEveryMinutes: DEFAULT_STATS_EVERY_MINUTES },
    now: () => Date.now(),
    log,
  };
}

export default {
  async fetch(request: Request, env: WorkerEnv, ctx: ExecutionContext): Promise<Response> {
    let deps: ServiceDeps;
    try {
      deps = depsFor(env, () => undefined);
    } catch {
      return jsonResponse(500, { error: "internal" }, { kind: "none" });
    }
    const response = await handleRequest(request, deps);
    ctx.waitUntil(flushTally(deps.storage, tally).catch(() => undefined));
    return response;
  },
  async scheduled(_controller: unknown, env: WorkerEnv, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(runScheduled(depsFor(env, emit)));
  },
};

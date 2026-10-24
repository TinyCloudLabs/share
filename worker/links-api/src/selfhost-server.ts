import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { configFromEnv, type EnvLike, type ServiceConfig } from "./config.ts";
import { runScheduled } from "./health.ts";
import { handleRequest, type ServiceDeps } from "./service.ts";
import { SqlStorage } from "./sql-storage.ts";
import { SqliteDriver } from "./sqlite-driver.ts";

/** Header the server sets from the socket address; a value sent by the client is discarded. */
export const SOCKET_ADDRESS_HEADER = "X-Links-Remote-Address";
export const SCHEDULE_INTERVAL_MS = 60_000;

export interface SelfHostOptions {
  readonly env: EnvLike;
  readonly dbPath: string;
  readonly log?: (line: string) => void;
  readonly now?: () => number;
}

export interface SelfHost {
  readonly server: Server;
  readonly deps: ServiceDeps;
  /** Runs the sweep and emits one health line; also driven by the 60 s timer. */
  tick(): Promise<void>;
  close(): Promise<void>;
}

function toRequest(req: IncomingMessage, trustedHeader: string | null): Request {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined || name.toLowerCase() === SOCKET_ADDRESS_HEADER.toLowerCase()) {
      continue;
    }
    headers.set(name, Array.isArray(value) ? value.join(", ") : value);
  }
  if (trustedHeader === null) {
    headers.set(SOCKET_ADDRESS_HEADER, req.socket.remoteAddress ?? "");
  }
  const method = req.method ?? "GET";
  const hasBody = method !== "GET" && method !== "HEAD";
  const host = req.headers.host ?? "localhost";
  const init: RequestInit & { duplex?: "half" } = { method, headers };
  if (hasBody) {
    init.body = Readable.toWeb(req) as ReadableStream<Uint8Array>;
    init.duplex = "half";
  }
  return new Request(`http://${host}${req.url ?? "/"}`, init);
}

async function writeResponse(res: ServerResponse, response: Response): Promise<void> {
  const headers: Record<string, string> = {};
  response.headers.forEach((value, name) => {
    headers[name] = value;
  });
  res.writeHead(response.status, headers);
  res.end(Buffer.from(await response.arrayBuffer()));
}

/** The self-host build: the same service code over one SQLite file, with a 60 s timer for the sweep and health line. */
export function createSelfHost(options: SelfHostOptions): SelfHost {
  const trusted = typeof options.env["CLIENT_ADDRESS_HEADER"] === "string" ? options.env["CLIENT_ADDRESS_HEADER"] : null;
  const config: ServiceConfig = configFromEnv({
    ...options.env,
    CLIENT_ADDRESS_HEADER: trusted ?? SOCKET_ADDRESS_HEADER,
  });
  const driver = new SqliteDriver(options.dbPath);
  const deps: ServiceDeps = {
    storage: new SqlStorage(driver),
    config,
    usage: { plan: null, tally: null, statsEveryMinutes: 1 },
    now: options.now ?? (() => Date.now()),
    log: options.log ?? ((line) => console.log(line)),
  };
  const server = createServer((req, res) => {
    handleRequest(toRequest(req, trusted), deps)
      .then((response) => writeResponse(res, response))
      .catch(() => {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end('{"error":"internal"}');
      });
  });
  const tick = () => runScheduled(deps);
  const timer = setInterval(() => {
    tick().catch((err: unknown) => deps.log(`links.schedule_failed ${err instanceof Error ? err.name : "unknown"}`));
  }, SCHEDULE_INTERVAL_MS);
  timer.unref();
  return {
    server,
    deps,
    tick,
    close: () =>
      new Promise<void>((resolve) => {
        clearInterval(timer);
        server.close(() => {
          driver.close();
          resolve();
        });
        server.closeAllConnections();
      }),
  };
}

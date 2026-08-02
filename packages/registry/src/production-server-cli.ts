/**
 * Local entrypoint for the shipped production Worker.  The route and
 * authorization decisions stay in worker.ts; this only adapts node:http and
 * an in-memory R2-shaped bucket for a hermetic process boundary.
 */
import { createServer } from "node:http";
import { Readable } from "node:stream";
import worker, { UploadAuthorization, type DurableObjectNamespace, type DurableObjectState, type RegistryEnv } from "./worker.js";

class MemoryR2Object {
  constructor(private readonly bytes: Uint8Array, readonly customMetadata: Record<string, string> | undefined) {}
  async arrayBuffer(): Promise<ArrayBuffer> { return this.bytes.slice().buffer as ArrayBuffer; }
}

class MemoryR2 {
  private readonly objects = new Map<string, MemoryR2Object>();

  async get(key: string): Promise<MemoryR2Object | null> { return this.objects.get(key) ?? null; }

  async put(key: string, value: ArrayBuffer | Uint8Array, options?: { customMetadata?: Record<string, string> }): Promise<void> {
    this.objects.set(key, new MemoryR2Object(new Uint8Array(value instanceof Uint8Array ? value : value.slice(0)), options?.customMetadata));
  }

  async delete(keys: string | string[]): Promise<void> {
    for (const key of Array.isArray(keys) ? keys : [keys]) this.objects.delete(key);
  }

  async list(options?: { prefix?: string }): Promise<{ objects: Array<{ key: string; customMetadata?: Record<string, string> }>; truncated: false }> {
    return { objects: [...this.objects.entries()].filter(([key]) => options?.prefix === undefined || key.startsWith(options.prefix)).map(([key, object]) => object.customMetadata === undefined ? { key } : { key, customMetadata: object.customMetadata }), truncated: false };
  }
}

class MemoryDurableObjectStorage {
  private readonly values = new Map<string, unknown>();

  async get<T>(key: string): Promise<T | undefined> { return this.values.get(key) as T | undefined; }
  async put<T>(key: string, value: T): Promise<void> { this.values.set(key, value); }
}

class MemoryDurableObjectState implements DurableObjectState {
  readonly storage = new MemoryDurableObjectStorage();
  private queue = Promise.resolve();

  async blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T> {
    const result = this.queue.then(callback);
    this.queue = result.then(() => undefined, () => undefined);
    return result;
  }
}

class MemoryDurableObjects implements DurableObjectNamespace {
  private readonly objects = new Map<string, UploadAuthorization>();

  getByName(name: string) {
    let object = this.objects.get(name);
    if (!object) {
      object = new UploadAuthorization(new MemoryDurableObjectState());
      this.objects.set(name, object);
    }
    return { fetch: (input: string, init?: RequestInit) => object!.fetch(new Request(input, init)) };
  }
}

function requestUrl(request: import("node:http").IncomingMessage): string {
  return `http://127.0.0.1${request.url ?? "/"}`;
}

const bucket = new MemoryR2();
const env: RegistryEnv = {
  REGISTRY: bucket as unknown as RegistryEnv["REGISTRY"],
  UPLOAD_AUTHORIZATION: new MemoryDurableObjects(),
  ...(process.env.REGISTRY_AUTH_PUBLIC_KEY === undefined ? {} : { REGISTRY_AUTH_PUBLIC_KEY: process.env.REGISTRY_AUTH_PUBLIC_KEY }),
  ...(process.env.REGISTRY_LINK_UPLOAD_PUBLIC_KEY === undefined ? {} : { REGISTRY_LINK_UPLOAD_PUBLIC_KEY: process.env.REGISTRY_LINK_UPLOAD_PUBLIC_KEY }),
  ...(process.env.MAX_BLOB_BYTES === undefined ? {} : { MAX_BLOB_BYTES: process.env.MAX_BLOB_BYTES }),
};

const server = createServer(async (request, response) => {
  try {
    const method = request.method ?? "GET";
    const init: RequestInit & { duplex?: "half" } = { method, headers: new Headers(request.headers as Record<string, string>) };
    if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
      init.body = Readable.toWeb(request) as unknown as ReadableStream<Uint8Array>;
      init.duplex = "half";
    }
    const webRequest = new Request(requestUrl(request), init);
    const result = await worker.fetch(webRequest, env);
    response.writeHead(result.status, Object.fromEntries(result.headers.entries()));
    if (result.body === null) response.end();
    else {
      const bytes = new Uint8Array(await result.arrayBuffer());
      response.end(bytes);
    }
  } catch {
    response.writeHead(500, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "production-registry-adapter-failed" }));
  }
});

const port = Number(process.argv[process.argv.indexOf("--port") + 1] ?? "8787");
server.listen(port, "127.0.0.1", () => {
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("production registry did not bind");
  process.stdout.write(`production share registry listening on http://127.0.0.1:${address.port}\n`);
});

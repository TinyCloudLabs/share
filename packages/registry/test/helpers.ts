import type { DevRegistry } from "../src/dev-server.js";

export const DEV_BASE_URL = "http://registry.local";

/**
 * Adapt the in-process dev-registry handler into a `fetch` the client can
 * use — no port binding. undici requires `duplex: "half"` on any Request
 * constructed with a body (DOM's RequestInit type doesn't know the field).
 */
export function handlerFetch(registry: DevRegistry): typeof fetch {
  return async (input, init) => {
    const withDuplex =
      init?.body === undefined || init.body === null
        ? init
        : ({ ...init, duplex: "half" } as RequestInit);
    return registry.handler(new Request(input, withDuplex));
  };
}

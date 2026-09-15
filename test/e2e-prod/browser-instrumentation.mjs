export function installBrowserInstrumentation() {
  window.__tc500BinaryBodies = [];
  window.__tc500Clipboard = [];
  const originalFetch = window.fetch.bind(window);
  window.fetch = async (input, init) => {
    const request = input instanceof Request ? input : undefined;
    const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url, location.href);
    const contentType = new Headers(init?.headers ?? request?.headers).get("content-type") ?? "";
    let body = init?.body;
    if (url.pathname === "/invoke" && contentType.startsWith("application/vnd.tinycloud.sealed") && body === undefined && request !== undefined && !new Set(["GET", "HEAD"]).has(request.method)) {
      body = await request.clone().arrayBuffer();
    }
    if (url.pathname === "/invoke" && contentType.startsWith("application/vnd.tinycloud.sealed") && (body instanceof Blob || body instanceof ArrayBuffer || ArrayBuffer.isView(body))) {
      const bytes = body instanceof Blob ? new Uint8Array(await body.arrayBuffer()) : body instanceof ArrayBuffer ? new Uint8Array(body) : new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
      window.__tc500BinaryBodies.push(Array.from(bytes));
    }
    return originalFetch(input, init);
  };
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async (value) => { window.__tc500Clipboard.push(value); } } });
}

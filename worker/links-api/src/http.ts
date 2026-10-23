import { MAX_RECORD_HEADER_BYTES } from "./config.ts";

/** Headers on every response: stored bytes are never served renderable and nothing is cached. */
const COMMON_HEADERS: Readonly<Record<string, string>> = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Content-Security-Policy": "default-src 'none'; sandbox",
  "Cross-Origin-Resource-Policy": "same-site",
};

export type CorsMode =
  | { readonly kind: "none" }
  /** GET: any origin, no credentials. */
  | { readonly kind: "open" }
  /** POST from a listed first-party origin. */
  | { readonly kind: "origin"; readonly origin: string };

export function corsHeaders(cors: CorsMode): Record<string, string> {
  if (cors.kind === "open") {
    return { "Access-Control-Allow-Origin": "*", "Access-Control-Expose-Headers": "X-Link-Record" };
  }
  if (cors.kind === "origin") {
    return {
      "Access-Control-Allow-Origin": cors.origin,
      Vary: "Origin",
      "Access-Control-Expose-Headers": "Retry-After",
    };
  }
  return {};
}

export function jsonResponse(
  status: number,
  body: unknown,
  cors: CorsMode,
  extraHeaders: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...COMMON_HEADERS, "Content-Type": "application/json", ...corsHeaders(cors), ...extraHeaders },
  });
}

export function emptyResponse(status: number, cors: CorsMode, extraHeaders: Record<string, string> = {}): Response {
  return new Response(null, { status, headers: { ...COMMON_HEADERS, ...corsHeaders(cors), ...extraHeaders } });
}

/** The stored body as raw bytes plus the signed record in `X-Link-Record`. */
export function rawRecordResponse(bytes: Uint8Array, recordHeader: string, cors: CorsMode): Response {
  if (recordHeader.length > MAX_RECORD_HEADER_BYTES) {
    throw new RangeError("record header too large");
  }
  return new Response(bytes, {
    status: 200,
    headers: {
      ...COMMON_HEADERS,
      "Content-Type": "application/octet-stream",
      "Content-Disposition": 'attachment; filename="link.bin"',
      "X-Link-Record": recordHeader,
      ...corsHeaders(cors),
    },
  });
}

/** Reads the request body with a running cap; null as soon as it exceeds `maxBytes`. */
export async function readCappedBody(request: Request, maxBytes: number): Promise<Uint8Array | null> {
  const declared = request.headers.get("Content-Length");
  if (declared !== null && Number(declared) > maxBytes) {
    return null;
  }
  if (request.body === null) {
    return new Uint8Array(0);
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return joined;
}

/** `application/json` with optional parameters; nothing else. */
export function isJsonContentType(value: string | null): boolean {
  if (value === null) {
    return false;
  }
  return value.split(";")[0]?.trim().toLowerCase() === "application/json";
}

export const COMMON_HEADERS: Record<string, string> = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Content-Security-Policy": "default-src 'none'; sandbox",
  "Cross-Origin-Resource-Policy": "same-origin",
};

export function jsonResponse(
  status: number,
  body: unknown,
  extraHeaders: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...COMMON_HEADERS, "Content-Type": "application/json", ...extraHeaders },
  });
}

export function notFound(): Response {
  return jsonResponse(404, { error: "not_found" });
}

export function rateLimited(retryAfterSeconds: number): Response {
  return jsonResponse(429, { error: "rate_limited" }, {
    "Retry-After": String(retryAfterSeconds),
  });
}

export function rawSealedResponse(bytes: Uint8Array, cid: string, expiresIso: string): Response {
  return new Response(bytes, {
    status: 200,
    headers: {
      ...COMMON_HEADERS,
      "Content-Type": "application/octet-stream",
      "Content-Disposition": 'attachment; filename="share.bin"',
      "X-Share-Cid": cid,
      "X-Share-Expires": expiresIso,
    },
  });
}

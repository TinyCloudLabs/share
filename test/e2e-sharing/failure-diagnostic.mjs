// Pure helper extracted from integration.mjs's Failure diagnostic block
// (lines ~620-660, ~1110-1155). Categorizes free-text diagnostic values and
// summarizes failed /delegate and /invoke browser telemetry entries without
// ever surfacing raw text, URLs, headers, request data, or trace IDs.

const SAFE_ERROR_CODE_PATTERN = /^[A-Z][A-Z0-9_]{1,63}$/;
const SAFE_CONTENT_TYPE_PATTERN = /^[\w.+-]+\/[\w.+-]+$/;

export function safeBrowserDiagnostic(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === "string") {
    const normalized = value.toLowerCase();
    const category = normalized.includes("signature") ? "signature"
      : normalized.includes("cid") ? "cid"
      : normalized.includes("canonical") || normalized.includes("timestamp") || normalized.includes("expired") ? "canonical-registration"
      : normalized.includes("chain") || normalized.includes("bound") ? "registration-binding"
      : normalized.includes("policy_registration_invalid") || normalized.includes("policy") ? "policy"
      : normalized.includes("capability") ? "capability"
      : normalized.includes("config") ? "config"
      : normalized.includes("auth") || normalized.includes("session") ? "auth"
      : normalized.includes("enforcer") || normalized.includes("did:") ? "identity"
      : normalized.includes("invoke") || normalized.includes("delegate") ? "authorization"
      : normalized.includes("permission") ? "permission"
      : normalized.includes("sign") ? "sign-in"
      : normalized.includes("space") ? "space"
      : normalized.includes("library") ? "library"
      : normalized.includes("network") ? "network"
      : normalized.includes("invalid") ? "invalid"
      : normalized.includes("failed") || normalized.includes("failure") ? "failure"
      : "other";
    return { length: value.length, category };
  }
  if (typeof value !== "object") return { type: typeof value };
  const object = value;
  const message = typeof object.message === "string" ? object.message : typeof object.error === "string" ? object.error : undefined;
  return { type: Array.isArray(value) ? "array" : "object", message: message === undefined ? undefined : safeBrowserDiagnostic(message) };
}

function safePathname(url) {
  if (typeof url !== "string" || url.length === 0) return null;
  try {
    return new URL(url).pathname;
  } catch {
    return null;
  }
}

function isFailedEntry(entry) {
  if (entry === null || typeof entry !== "object") return false;
  if (typeof entry.status === "number" && entry.status >= 400) return true;
  if (entry.ok === false) return true;
  if (entry.errorCode !== undefined && entry.errorCode !== null) return true;
  if (entry.responseErrorCode !== undefined && entry.responseErrorCode !== null) return true;
  return false;
}

function firstStringField(entry, keys) {
  for (const key of keys) {
    if (typeof entry[key] === "string") return entry[key];
  }
  return undefined;
}

function safeContentType(entry) {
  const raw = firstStringField(entry, ["contentType", "responseContentType"]);
  if (raw === undefined) return null;
  const mediaType = raw.split(";")[0].trim();
  if (mediaType.length === 0 || mediaType.length > 100) return null;
  return SAFE_CONTENT_TYPE_PATTERN.test(mediaType) ? mediaType : null;
}

function safeResponseBodyLength(entry) {
  const raw = firstStringField(entry, ["responseBody", "responseBodyPreview", "body", "text"]);
  return raw === undefined ? null : raw.length;
}

function safeResponseKeys(entry) {
  const raw = firstStringField(entry, ["responseBody", "responseBodyPreview", "body", "text"]);
  if (raw === undefined) return [];
  try {
    const parsed = JSON.parse(raw);
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) ? Object.keys(parsed).sort() : [];
  } catch {
    return [];
  }
}

function structuredErrorCode(entry) {
  const raw = entry.errorCode ?? entry.responseErrorCode ?? entry.code;
  if (raw === null || raw === undefined) return null;
  if (typeof raw === "number" && Number.isFinite(raw)) return raw;
  if (typeof raw === "string") {
    return SAFE_ERROR_CODE_PATTERN.test(raw) ? raw : safeBrowserDiagnostic(raw);
  }
  return safeBrowserDiagnostic(raw);
}

function serverTraceIdPresent(entry) {
  if (typeof entry.traceId === "string" && entry.traceId.length > 0) return true;
  if (typeof entry.serverTraceId === "string" && entry.serverTraceId.length > 0) return true;
  const headerSources = [entry.responseHeaders, entry.headers];
  for (const headers of headerSources) {
    if (headers === null || typeof headers !== "object") continue;
    for (const key of Object.keys(headers)) {
      const normalizedKey = key.toLowerCase();
      if ((normalizedKey === "x-trace-id" || normalizedKey === "x-request-id" || normalizedKey.endsWith("-trace-id")) && typeof headers[key] === "string" && headers[key].length > 0) {
        return true;
      }
    }
  }
  return false;
}

export function safeFailedTelemetry(entries) {
  if (!Array.isArray(entries)) return [];

  // Build digest stats over all /delegate entries (failed and successful).
  const digestStats = new Map(); // digest -> { count, hasSuccess }
  for (const entry of entries) {
    if (entry === null || typeof entry !== "object") continue;
    if (safePathname(entry.url) !== "/delegate") continue;
    if (entry.requestDigestAvailable !== true || typeof entry.requestBodyDigest !== "string") continue;
    const digest = entry.requestBodyDigest;
    if (!digestStats.has(digest)) digestStats.set(digest, { count: 0, hasSuccess: false });
    const stats = digestStats.get(digest);
    stats.count++;
    if (typeof entry.status === "number" && entry.status >= 200 && entry.status < 300) stats.hasSuccess = true;
  }
  const distinctDelegateRequestBodyCount = digestStats.size;

  const failed = [];
  for (const entry of entries) {
    if (entry === null || typeof entry !== "object") continue;
    const pathname = safePathname(entry.url);
    if (pathname !== "/delegate" && pathname !== "/invoke") continue;
    if (!isFailedEntry(entry)) continue;
    const result = {
      pathname,
      status: typeof entry.status === "number" && Number.isFinite(entry.status) ? entry.status : null,
      contentType: safeContentType(entry),
      responseBodyLength: safeResponseBodyLength(entry),
      responseKeys: safeResponseKeys(entry),
      errorCode: structuredErrorCode(entry),
      responseBody: safeBrowserDiagnostic(entry.responseBody),
      responseBodyPreview: safeBrowserDiagnostic(entry.responseBodyPreview),
      errorBody: safeBrowserDiagnostic(entry.errorBody),
      serverTraceIdPresent: serverTraceIdPresent(entry),
    };
    if (pathname === "/delegate") {
      result.requestBodyLength = typeof entry.requestBodyLength === "number" ? entry.requestBodyLength : null;
      const digestValid = entry.requestDigestAvailable === true && typeof entry.requestBodyDigest === "string" && typeof entry.requestBodyLength === "number" && Number.isFinite(entry.requestBodyLength) && entry.requestBodyLength > 0;
      result.requestDigestAvailable = digestValid;
      if (digestValid) {
        const stats = digestStats.get(entry.requestBodyDigest);
        result.matchesSuccessfulRequestBody = stats ? stats.hasSuccess : false;
        result.sameRequestBodyCount = stats ? stats.count : 1;
      } else {
        result.matchesSuccessfulRequestBody = false;
        result.sameRequestBodyCount = 0;
      }
      result.distinctDelegateRequestBodyCount = distinctDelegateRequestBodyCount;
    }
    failed.push(result);
  }
  return failed;
}

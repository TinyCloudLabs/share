import { READ_SIGNERS_ENV, parseReadSigners, type ReadSigner } from "./read-signers.ts";

/**
 * Every number the service enforces lives in this file. The per-type table holds the lives and
 * quotas (contract sections 3 and 4.9); `MAX_LINK_BODY_BYTES` is the one body size limit for all types.
 */

export const LINK_TYPES = ["openkey-login", "openkey-approval-request", "courier", "share"] as const;
export type LinkType = (typeof LINK_TYPES)[number];

export interface TypeConfig {
  /** Longest `expiresAt - issuedAt`, in seconds. */
  readonly maxLifeSeconds: number;
  /** Read once, by an explicit `POST .../take`; `GET` never serves it. */
  readonly readOnce: boolean;
  /** Live-row and live-byte quota for the type. */
  readonly quotaRows: number;
  readonly quotaBytes: number;
}

export const TYPE_CONFIG: Readonly<Record<LinkType, TypeConfig>> = {
  "openkey-login": {
    maxLifeSeconds: 600,
    readOnce: true,
    quotaRows: 4_000,
    quotaBytes: 134_217_728,
  },
  "openkey-approval-request": {
    maxLifeSeconds: 86_400,
    readOnce: false,
    quotaRows: 4_000,
    quotaBytes: 134_217_728,
  },
  courier: {
    maxLifeSeconds: 7 * 86_400,
    readOnce: false,
    quotaRows: 4_000,
    quotaBytes: 268_435_456,
  },
  share: {
    maxLifeSeconds: 30 * 86_400,
    readOnce: false,
    quotaRows: 12_000,
    quotaBytes: 1_744_830_464,
  },
};

export const READ_ONCE_TYPES: readonly LinkType[] = LINK_TYPES.filter((t) => TYPE_CONFIG[t].readOnce);

export const WINDOW_SECONDS = 120;
export const MIN_LIFE_SECONDS = 120;
/**
 * The one size limit for every link type: the largest decoded (sealed) body, in bytes (64 KiB).
 * Every other size limit, including the HTTP request cap below, is derived from this constant.
 */
export const MAX_LINK_BODY_BYTES = 65_536;
export const MIN_BODY_BYTES = 30;
export const NONCE_TTL_SECONDS = 300;
export const ID_BYTES = 17;
export const ID_ATTEMPTS = 5;

/** The sealed body in base64url (4 characters per 3 bytes) plus 3 KiB for the header and signature. */
export const REQUEST_BODY_CAP_BYTES = Math.ceil((MAX_LINK_BODY_BYTES * 4) / 3) + 3_072;

export interface WindowLimit {
  readonly limit: number;
  readonly windowSeconds: number;
}

export const LIMITS = {
  issuerCreate: [
    { limit: 10, windowSeconds: 60 },
    { limit: 200, windowSeconds: 86_400 },
  ],
  issuerDelete: [{ limit: 60, windowSeconds: 60 }],
  addressCreate: [
    { limit: 30, windowSeconds: 60 },
    { limit: 600, windowSeconds: 86_400 },
  ],
  addressRefused: { limit: 60, windowSeconds: 60 },
  addressRead: { limit: 120, windowSeconds: 60 },
  addressDelete: { limit: 120, windowSeconds: 60 },
  apiKeyCreate: { limit: 120, windowSeconds: 60 },
  apiKeyDelete: { limit: 120, windowSeconds: 60 },
  /** Per allow-listed label (contract 4.11); `LINKS_READ_AUTH_LIMIT` overrides the number. */
  authenticatedRead: { limit: 6_000, windowSeconds: 60 },
} as const;

export const ADDRESS_LIVE_CAP = { rows: 100, bytes: 16 * 1024 * 1024 } as const;
export const RESERVE = { highWaterFraction: 0.8, addressRowsAtOrAboveHighWater: 10 } as const;

/** Largest `X-Link-Record` header the service will emit. */
export const MAX_RECORD_HEADER_BYTES = 2_048;

export interface ServiceConfig {
  /** Origin this instance serves; a create whose `audience` differs is refused. */
  readonly audience: string;
  /** Browser origins allowed to POST create and delete. */
  readonly corsOrigins: readonly string[];
  /** Browser origins allowed to POST take (default none). */
  readonly takeOrigins: readonly string[];
  /** Salt for the address hashes; required. */
  readonly addressSalt: string;
  /** Operations switched off; each answers `503 capacity`. */
  readonly kill: Readonly<Record<"create" | "read" | "take" | "delete", boolean>>;
  /** Header that carries the client address; Cloudflare sets CF-Connecting-IP. */
  readonly clientAddressHeader: string;
  /** Keys whose signed reads use the label's own bucket (contract 4.11); none when absent. */
  readonly readSigners?: readonly ReadSigner[];
  /** Reads a minute per label for those keys; the default is `LIMITS.authenticatedRead.limit`. */
  readonly readAuthLimit?: number;
}

export const DEFAULT_CORS_ORIGINS: readonly string[] = ["https://share.tinycloud.xyz"];
export const DEFAULT_AUDIENCE = "https://api.tinycloud.xyz";

export interface EnvLike {
  readonly [key: string]: unknown;
}

function list(value: unknown, fallback: readonly string[]): readonly string[] {
  if (typeof value !== "string") {
    return fallback;
  }
  return value
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function flag(value: unknown): boolean {
  return value === "1" || value === "true";
}

/** Reads the service configuration from environment-style bindings. Throws when the salt is missing. */
export function configFromEnv(env: EnvLike): ServiceConfig {
  const salt = env["ADDRESS_SALT"];
  if (typeof salt !== "string" || salt.length < 16) {
    throw new Error("config: ADDRESS_SALT must be set (at least 16 characters)");
  }
  const audience = typeof env["LINKS_AUDIENCE"] === "string" ? env["LINKS_AUDIENCE"] : DEFAULT_AUDIENCE;
  const header = typeof env["CLIENT_ADDRESS_HEADER"] === "string" ? env["CLIENT_ADDRESS_HEADER"] : "CF-Connecting-IP";
  const readSigners = parseReadSigners(env[READ_SIGNERS_ENV]);
  const authLimit = Number(env["LINKS_READ_AUTH_LIMIT"] ?? LIMITS.authenticatedRead.limit);
  if (!Number.isSafeInteger(authLimit) || authLimit < 1) {
    throw new Error("config: LINKS_READ_AUTH_LIMIT must be a positive integer");
  }
  return {
    audience,
    corsOrigins: list(env["LINKS_CORS_ORIGINS"], DEFAULT_CORS_ORIGINS),
    takeOrigins: list(env["LINKS_TAKE_ORIGINS"], []),
    addressSalt: salt,
    kill: {
      create: flag(env["KILL_CREATE"]),
      read: flag(env["KILL_READ"]),
      take: flag(env["KILL_TAKE"]),
      delete: flag(env["KILL_DELETE"]),
    },
    clientAddressHeader: header,
    readSigners,
    readAuthLimit: authLimit,
  };
}

/**
 * Cloudflare Workers Free plan limits the alert tracks. ONE table; values are as published on the
 * pages named in `source`, read on `retrievedOn`. Sizes are taken in decimal units (the smaller
 * reading of "MB" and "GB"), so the alert fires early rather than late.
 */
export interface PlanLimit {
  /** `daily`: a count that resets at 00:00 UTC. `gauge`: a current size. */
  readonly kind: "daily" | "gauge";
  readonly limit: number;
  readonly unit: "requests" | "rows" | "bytes";
  readonly source: string;
}

export const FREE_PLAN_METRICS = ["requests", "d1_rows_read", "d1_rows_written", "d1_database_bytes"] as const;
export type FreePlanMetric = (typeof FREE_PLAN_METRICS)[number];

export interface FreePlan {
  readonly retrievedOn: string;
  /** The alert line is emitted once per metric per UTC day at or above this percentage. */
  readonly alertPercent: number;
  readonly limits: Readonly<Record<FreePlanMetric, PlanLimit>>;
}

export const WORKERS_FREE_PLAN: FreePlan = {
  retrievedOn: "2026-10-23",
  alertPercent: 70,
  limits: {
    requests: {
      kind: "daily",
      limit: 100_000,
      unit: "requests",
      source: "https://developers.cloudflare.com/workers/platform/limits/#daily-requests",
    },
    d1_rows_read: {
      kind: "daily",
      limit: 5_000_000,
      unit: "rows",
      source: "https://developers.cloudflare.com/d1/platform/pricing/#billing-metrics",
    },
    d1_rows_written: {
      kind: "daily",
      limit: 100_000,
      unit: "rows",
      source: "https://developers.cloudflare.com/d1/platform/pricing/#billing-metrics",
    },
    // Maximum database size on Free is 500 MB; the 5 GB account total is not reached first with one database.
    d1_database_bytes: {
      kind: "gauge",
      limit: 500_000_000,
      unit: "bytes",
      source: "https://developers.cloudflare.com/d1/platform/limits/",
    },
  },
};

/** The scheduled run computes the live row and byte totals this often (each run scans every live row). */
export const DEFAULT_STATS_EVERY_MINUTES = 5;

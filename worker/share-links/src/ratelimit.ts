import type { D1Database } from "./d1";

export interface RateDecision {
  allowed: boolean;
  retryAfterSeconds: number;
}

/**
 * Fixed-window counter in the `rl` table. The key carries the window bucket, so
 * each window is a fresh row; expired rows are removed by the hourly cron.
 */
export async function hitRateLimit(
  db: D1Database,
  scope: string,
  ipHash: string,
  limit: number,
  windowSeconds: number,
  nowSeconds: number,
): Promise<RateDecision> {
  const bucket = Math.floor(nowSeconds / windowSeconds);
  const windowEnd = (bucket + 1) * windowSeconds;
  const key = `${scope}:${ipHash}:${bucket}`;
  const row = await db
    .prepare(
      "INSERT INTO rl (k, n, exp) VALUES (?, 1, ?) ON CONFLICT(k) DO UPDATE SET n = n + 1 RETURNING n",
    )
    .bind(key, windowEnd + 60)
    .first<{ n: number }>();
  const count = row?.n ?? 0;
  return {
    allowed: count <= limit,
    retryAfterSeconds: Math.max(1, windowEnd - nowSeconds),
  };
}

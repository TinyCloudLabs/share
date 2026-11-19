// OpenKey allows 3 email-code sends per 60 s per client IP (TC-2310). A smoke that signs several
// identities in quick succession, or resends, can trip it; so every send waits until at least
// `minGapMs` after the previous one (3 sends then span ≥ 42 s, never 4 in a minute). One gate is
// shared by every identity and page of a run. Sends from other processes on the same IP are not seen.

/**
 * `record(atMs)` notes a send that happened (from the request itself) and returns `{ atMs, gapMs }`;
 * `wait()` resolves once a new send would be at least `minGapMs` after the last one, with the ms waited.
 */
export function createOtpGate({ minGapMs = 21_000, now = Date.now, sleep = (ms) => new Promise((done) => setTimeout(done, ms)) } = {}) {
  let last;
  return {
    record(atMs = now()) {
      const gapMs = last === undefined ? null : atMs - last;
      last = atMs;
      return { atMs, gapMs };
    },
    async wait() {
      if (last === undefined) return 0;
      const left = last + minGapMs - now();
      if (left <= 0) return 0;
      await sleep(left);
      return left;
    },
  };
}

/** Whether a request is OpenKey's email-code send. */
export const isOtpSend = (method, url) => method === "POST" && /^https:\/\/(api\.)?openkey\.so\/api\/auth\/email-otp\/send-verification-otp$/.test(url.split(/[?#]/)[0]);

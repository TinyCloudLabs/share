import { appendFileSync } from "node:fs";

export function walletSummaryRecorder(path = process.env.GITHUB_STEP_SUMMARY) {
  const recorded = new Set();
  return (address) => {
    if (typeof address !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(address) || !path) return;
    const key = address.toLowerCase();
    if (recorded.has(key)) return;
    appendFileSync(path, `Smoke wallet: ${address}\n`);
    recorded.add(key);
  };
}

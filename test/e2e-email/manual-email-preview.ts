import { chmod, mkdir, open, readFile, stat } from "node:fs/promises";
import { dirname } from "node:path";

type Json = Record<string, unknown>;

function escapeHtml(value: string): string {
  return value.replace(/[&<>\"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" })[character] as string);
}

export async function writeEmailPreview(input: { path: string; shareUrl: string; recipientEmail: string; documentName: string }): Promise<void> {
  await mkdir(dirname(input.path), { recursive: true, mode: 0o700 });
  const html = `<!doctype html><meta charset="utf-8"><title>TinyCloud share invitation</title><main><p>TinyCloud sharing invitation</p><p>${escapeHtml(input.recipientEmail)}</p><p><a href="${escapeHtml(input.shareUrl)}">Open ${escapeHtml(input.documentName)}</a></p></main>\n`;
  const handle = await open(input.path, "w", 0o600);
  try { await handle.writeFile(html, "utf8"); await handle.sync(); } finally { await handle.close(); }
  await chmod(input.path, 0o600);
  if (((await stat(input.path)).mode & 0o777) !== 0o600) throw new Error("email preview permissions are not 0600");
}

async function main(): Promise<void> {
  const artifactPath = process.argv[process.argv.indexOf("--artifact") + 1];
  if (typeof artifactPath !== "string" || artifactPath.length === 0) throw new Error("usage: manual-email-preview --artifact PATH [--inspect]");
  const artifact = JSON.parse(await readFile(artifactPath, "utf8")) as Json;
  const shareUrl = artifact.shareUrl;
  const browserInvitation = artifact.browserInvitation;
  if (typeof shareUrl !== "string" || typeof browserInvitation !== "object" || browserInvitation === null) throw new Error("artifact does not contain a browser invitation");
  const outputPath = process.argv.includes("--output") ? process.argv[process.argv.indexOf("--output") + 1] : `${artifactPath}.email.html`;
  if (typeof outputPath !== "string" || outputPath.length === 0) throw new Error("preview output path is missing");
  if (process.argv.includes("--inspect")) { console.log(JSON.stringify({ artifactPath, outputPath, shareUrl, browserInvitationStatus: (browserInvitation as Json).status, redeem: false })); return; }
  await writeEmailPreview({ path: outputPath, shareUrl, recipientEmail: "sam@tinycloud.xyz", documentName: "TinyCloud policy payload test" });
  console.log(JSON.stringify({ artifactPath, outputPath, browserInvitationStatus: (browserInvitation as Json).status, deliveryStatus: "not-sent", redeem: false }));
}

if (process.argv[1]?.endsWith("manual-email-preview.ts")) void main().catch((error) => { console.error(error instanceof Error ? error.message : "manual email preview failed"); process.exitCode = 1; });

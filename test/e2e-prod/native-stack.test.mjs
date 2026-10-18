import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { credentialOtpFromMail, isCredentialOtpMail, resendFixtureJsonResponse, runBoundedStep } from "./native-stack.mjs";

test("Resend fixture responses declare their exact bounded UTF-8 length", () => {
  const response = resendFixtureJsonResponse({ id: "mail_é" }, { "cache-control": "no-store" });

  assert.equal(response.headers["content-type"], "application/json");
  assert.equal(response.headers["content-length"], String(Buffer.byteLength(response.body)));
  assert.equal(response.headers["cache-control"], "no-store");
  assert.deepEqual(JSON.parse(response.body), { id: "mail_é" });
});

test("OTP selection is bound to the verification subject and exact recipient", () => {
  const recipient = "unique@example.test";
  assert.equal(isCredentialOtpMail({ payload: { subject: "Your OpenCredentials verification code", to: [recipient], text: "123456" } }, recipient), true);
  assert.equal(isCredentialOtpMail({ payload: { subject: "Your TinyCloud share", to: [recipient], text: "Unrelated 654321" } }, recipient), false);
  assert.equal(isCredentialOtpMail({ payload: { subject: "Your OpenCredentials verification code", to: ["other@example.test"], text: "123456" } }, recipient), false);
});

test("OTP extraction reads only the 8-digit code line and ignores HTML tokens", () => {
  const message = {
    payload: {
      html: '<style>body { color: #65432187 }</style>',
      text: "Your 8-digit OpenCredentials code is 12345678.\n\nEnter it only on the page where you just asked to verify this email address. Never share it with anyone, including someone who says they sent you a file. It expires in five minutes and works once.\n\nIf you did not request this code, ignore this email; nothing is shared without it.",
    },
  };
  assert.equal(credentialOtpFromMail(message), "12345678");
  assert.equal(credentialOtpFromMail({ payload: { text: "Your 8-digit OpenCredentials code is 1234567." } }), undefined);
  assert.equal(credentialOtpFromMail({ payload: { text: "Use 123456" } }), undefined);
  assert.equal(credentialOtpFromMail({ payload: { text: "Your one-time OpenCredentials code is 123456. It expires in five minutes." } }), undefined);
});

async function gone(pid, timeout = 3_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    try { process.kill(pid, 0); } catch (error) { if (error.code === "ESRCH") return true; }
    await new Promise((resolveWait) => setTimeout(resolveWait, 50));
  }
  return false;
}

async function grandchildPid(pidFile) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const text = await readFile(pidFile, "utf8").catch(() => "");
    if (/^\d+\s*$/.test(text)) return Number(text);
    await new Promise((resolveWait) => setTimeout(resolveWait, 20));
  }
  throw new Error("stub step did not record its grandchild");
}

test("a timed-out setup step takes its whole process group down, grandchildren included", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tc500-bounded-step-"));
  const pidFile = join(directory, "grandchild.pid");
  // The stub (like corepack -> pnpm -> script) starts a long-lived grandchild and waits.
  const step = runBoundedStep("sh", ["-c", `sleep 300 & echo $! > '${pidFile}'; wait`], directory, {}, 500);
  const pid = await grandchildPid(pidFile);
  await assert.rejects(step, /timed out after 500 ms/);
  assert.equal(await gone(pid), true, "the grandchild outlived the timed-out step");
});

test("a finished setup step leaves no background descendant behind", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tc500-bounded-step-"));
  const pidFile = join(directory, "grandchild.pid");
  await runBoundedStep("sh", ["-c", `sleep 300 & echo $! > '${pidFile}'`], directory, {}, 10_000);
  assert.equal(await gone(await grandchildPid(pidFile)), true, "a background grandchild outlived its step");
});

test("a failing setup step rejects with its exit status", async () => {
  await assert.rejects(runBoundedStep("sh", ["-c", "exit 3"], tmpdir(), {}, 10_000), /exited with 3/);
});

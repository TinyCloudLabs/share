/**
 * Test tooling for test/e2e-prod/courier-live-smoke.mjs: a throwaway account has
 * no courier data, and the /courier view cannot write requests or messages (it
 * must not). This page signs in with a courier-prefix write grant and plays the
 * part of the CLI for one thread: a peer's request mirrored in, one of the
 * agent's own messages and an AUTH_REQUIRED task, and one approval request.
 * It is built only by the smoke's own vite config and is never deployed.
 */
import { loadSharePublicConfig } from "../../../src/email-share/config.ts";
import { EXT, keys } from "../../../src/courier/model.ts";
import { COURIER_MANIFEST_SCOPE, COURIER_PREFIX, COURIER_SPACE } from "../../../src/courier/scope.ts";
import { signInWithManifest } from "../../../src/share/openkey-session.ts";

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
function ulid(at: number, salt: number): string {
  let time = at;
  let head = "";
  for (let index = 0; index < 10; index += 1) { head = CROCKFORD[time % 32] + head; time = Math.floor(time / 32); }
  const random = crypto.getRandomValues(new Uint8Array(16));
  return `${head}${Array.from(random, (byte) => CROCKFORD[(byte + salt) % 32]).join("")}`;
}

const status = document.querySelector<HTMLElement>("#status")!;
const set = (state: string, text: string): void => { status.dataset.state = state; status.textContent = text; };

document.querySelector<HTMLButtonElement>("#seed")!.addEventListener("click", () => {
  void (async () => {
    try {
      set("working", "Signing in…");
      const signedIn = await signInWithManifest({
        manifest: {
          manifest_version: 1, app_id: "xyz.tinycloud.courier.seed", name: "Courier seed", description: "Throwaway test data.",
          space: COURIER_SPACE, prefix: "", defaults: false, includePublicSpace: false,
          permissions: [{ service: "tinycloud.kv", space: COURIER_SPACE, path: COURIER_PREFIX, actions: ["get", "put", "list"], skipPrefix: true }],
        },
        ...COURIER_MANIFEST_SCOPE,
        config: await loadSharePublicConfig(),
        appName: "Courier seed (test)",
        hostSpaces: [COURIER_SPACE],
      });
      const kv = signedIn.tinycloud.space(COURIER_SPACE).kv;
      const now = Date.now();
      const thread = ulid(now - 3_600_000, 1);
      const peerMessage = ulid(now - 3_500_000, 2);
      const ownMessage = ulid(now - 3_000_000, 3);
      const task = ulid(now - 2_900_000, 4);
      const request = ulid(now - 60_000, 5);
      const put = async (key: string, value: unknown): Promise<void> => {
        const result = await kv.put(key, JSON.stringify(value), { prefix: "", contentType: "application/json" });
        if (!result.ok) throw new Error(`seed-put-failed:${result.error.code}`);
      };
      const from = { owner: "did:pkh:eip155:1:0x0000000000000000000000000000000000000001", agent: "did:key:z6MkthrowawayPeer", label: "Throwaway peer agent" };
      await put(keys.thread("me", "hunter", thread, "meta", thread), { threadId: thread, subject: "Seed: review the status table", startedBy: { owner: from.owner, courier: from.agent }, createdAt: new Date(now - 3_600_000).toISOString() });
      await put(keys.thread("peer", "hunter", thread, "msg", peerMessage), { messageId: peerMessage, contextId: thread, role: "ROLE_USER", parts: [{ text: "# Seed request\n\nPlease merge the docs-only PR.\n\n| item | state |\n| --- | --- |\n| a1 | done |\n| a2 | needs Sam |\n", mediaType: "text/markdown" }], referenceTaskIds: [], metadata: { [EXT]: { from, intent: "request", inReplyTo: null, asks: [{ id: "a2", title: "Merge the docs-only PR" }] } } });
      await put(keys.thread("me", "hunter", thread, "msg", ownMessage), { messageId: ownMessage, contextId: thread, role: "ROLE_AGENT", parts: [{ text: "Looking at it. I need my owner's approval for the merge.", mediaType: "text/markdown" }], referenceTaskIds: [task], metadata: { [EXT]: { from: { ...from, label: "Throwaway own agent" }, intent: "answer", inReplyTo: peerMessage } } });
      await put(keys.thread("me", "hunter", thread, "task", task), { id: task, contextId: thread, status: { state: "TASK_STATE_AUTH_REQUIRED", timestamp: new Date(now - 2_900_000).toISOString(), message: { role: "ROLE_AGENT", parts: [{ text: "Waiting on approval from my owner.", mediaType: "text/markdown" }] } }, metadata: { [EXT]: { ask: "a2" } } });
      await put(keys.request(request), { id: request, peer: "hunter", threadId: thread, taskId: task, action: "gh pr merge 20 --squash (throwaway; nothing is merged)", reason: "Seed data for the Courier view smoke test.", risk: "None: this is a throwaway account.", requestedBy: { owner: from.owner, agent: from.agent }, createdAt: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 24 * 3_600_000).toISOString(), status: "pending" });
      await signedIn.dispose();
      set("seeded", "Seeded.");
    } catch (error) {
      set("failed", `Failed: ${error instanceof Error ? error.message : "unknown"}`);
    }
  })();
});

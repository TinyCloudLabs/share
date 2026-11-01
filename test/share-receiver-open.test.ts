// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://share.tinycloud.xyz/viewer"}
// The viewer's own receive path: `createShareReceiverClient` -> `share.receive` -> `get`, on web-sdk's shipped receiver, against a
// closed synthetic world (a signed publisher, a fake OpenCredentials witness, a registry record and a fake owner node; see
// fixtures/share-receiver-world.ts). The receiving side is real: the invitation, the owner/node binding, the mailbox code through
// the SDK's own element, the credential, the policy session, and the decrypt. A share opens only when the digest its owner
// registered is the one the SDK computes for that kind of share.
import { afterEach, describe, expect, it, vi } from "vitest";
import { createShareReceiverClient } from "../src/share/receiver.js";
import type { SharePublicConfig } from "../src/email-share/config.js";
import { makeWitness } from "./fixtures/opencredentials-witness/witness-stub.mjs";
import { buildShareReceiverWorld, NODE_ORIGIN, REGISTRY_ORIGIN, SHARE_ORIGIN, WITNESS_ORIGIN, type ShareKind } from "./fixtures/share-receiver-world.js";

const CONFIG: SharePublicConfig = {
  version: "tinycloud.share/config-v2", shareOrigin: SHARE_ORIGIN, senderBootstrapNodeOrigin: NODE_ORIGIN,
  registryOrigin: REGISTRY_ORIGIN, credentialsOrigin: WITNESS_ORIGIN, accountlessReceiverEnabled: true,
};
// One open per test: the SDK reads the code, signs, and decrypts; allow it more than the default.
vi.setConfig({ testTimeout: 60_000 });
const OTP = "12345678";
// One issuer for the whole file: the SDK keeps an issuer's published keys between opens.
const witness = makeWitness({ code: OTP });
const PLAINTEXT = "# Quarterly notes\n\nÜber-secret, byte for byte.\n";

afterEach(() => {
  vi.unstubAllGlobals();
  document.body.replaceChildren();
  sessionStorage.clear();
});

/** Types the emailed code into the credential element the SDK mounted, as the recipient would, unless the SDK needed no code (a credential it already holds). */
async function typeMailboxCode(mount: HTMLElement, finished: () => boolean): Promise<void> {
  const field = await vi.waitFor(() => {
    const input = mount.querySelector("tinycloud-credential-acquisition")?.shadowRoot?.querySelector("input");
    if (input instanceof HTMLInputElement) return input;
    if (finished()) return null;
    throw new Error("the code field is not mounted yet");
  }, { timeout: 20_000 });
  if (field === null) return;
  field.value = OTP;
  field.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
  const submit = mount.querySelector("tinycloud-credential-acquisition")?.shadowRoot?.querySelector<HTMLButtonElement>("button[type=submit]");
  if (submit !== null && submit !== undefined && !submit.disabled) submit.click();
}

async function open(kind: ShareKind) {
  const world = await buildShareReceiverWorld({ kind, plaintext: PLAINTEXT, witness });
  vi.stubGlobal("fetch", world.fetchFn);
  const tinycloud = await createShareReceiverClient(CONFIG);
  const mount = document.createElement("div");
  document.body.append(mount);
  const received = await tinycloud.share.receive(world.link, { identity: "receiver", interaction: { kind: "inline", mountTarget: mount } });
  const content = received.get();
  let finished = false;
  const settled = content.then((value) => ({ value }), (error: unknown) => ({ error })).finally(() => { finished = true; });
  await typeMailboxCode(mount, () => finished);
  return { world, outcome: await settled };
}

describe("the viewer's receive path opens a share only under the digest rule for its kind", () => {
  it("opens an older share (no key path, canonical-hash digest) to its plaintext", async () => {
    const { world, outcome } = await open("legacy");
    if ("error" in outcome) throw outcome.error;
    expect(new TextDecoder().decode(outcome.value.bytes)).toBe(PLAINTEXT);
    expect(outcome.value.filename).toBe("report.md");
    expect(world.decryptRequests()).toBe(1);
  });

  it("opens a path-bound share (share/<id>, raw-byte digest) to its plaintext", async () => {
    const { world, outcome } = await open("path-bound");
    if ("error" in outcome) throw outcome.error;
    expect(new TextDecoder().decode(outcome.value.bytes)).toBe(PLAINTEXT);
    expect(world.registered.keyPath).toMatch(/^share\//);
    expect(world.decryptRequests()).toBe(1);
  });

  it.each<[string, ShareKind]>([
    ["a path-bound share whose registered digest is not its key's", "path-bound-tampered-digest"],
    ["a path-bound share that registered the canonical hash", "path-bound-canonical-digest"],
    ["an older share that registered the raw digest", "legacy-raw-digest"],
  ])("refuses %s, before anything is decrypted", async (_name, kind) => {
    const { world, outcome } = await open(kind);
    if (!("error" in outcome)) throw new Error("the share opened");
    // Refused for its key binding, not for any earlier step.
    if (!(outcome.error instanceof Error)) throw new Error("the refusal is not an error");
    expect(outcome.error.message).toBe("encrypted content envelope binding is invalid");
    expect(world.decryptRequests()).toBe(0);
  });
});

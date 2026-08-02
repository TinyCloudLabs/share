import { afterEach, describe, expect, it, vi } from "vitest";
import { mountRecipientDidAuthorization } from "../src/viewer/recipient-did.js";
import type { ResolveResult } from "../src/viewer/resolve.js";

afterEach(() => { document.body.replaceChildren(); vi.restoreAllMocks(); });

const okResult = { state: "ok", envelope: {} as never, senderVerified: true } as ResolveResult;
const waitingResult = { state: "recipient-did-authorization-required", envelope: {} as never, shareCid: "share-cid" } as ResolveResult;

describe("recipient-DID browser authorization", () => {
  it("offers the current OpenKey/session-holder continuation and opens on success", async () => {
    const root = document.createElement("div");
    document.body.append(root);
    const resume = vi.fn(async () => okResult);
    mountRecipientDidAuthorization(root, { expectedDid: "did:key:holder", resume });

    expect(root.textContent).toContain("Confirm this OpenKey device");
    const button = root.querySelector<HTMLButtonElement>("button")!;
    button.click();
    await vi.waitFor(() => expect(resume).toHaveBeenCalledOnce());
    await vi.waitFor(() => expect(root.textContent).toContain("OpenKey confirmed. Opening the share…"));
  });

  it("keeps the retry action for a wrong-DID result", async () => {
    const root = document.createElement("div");
    document.body.append(root);
    mountRecipientDidAuthorization(root, { expectedDid: "did:key:holder", resume: async () => waitingResult });

    const button = root.querySelector<HTMLButtonElement>("button")!;
    button.click();
    await vi.waitFor(() => expect(root.textContent).toContain("not the one named by the sender"));
    expect(button.disabled).toBe(false);
  });

  it("does not expose provider/session details when authorization is unavailable", async () => {
    const root = document.createElement("div");
    document.body.append(root);
    const debug = vi.spyOn(console, "debug").mockImplementation(() => undefined);
    mountRecipientDidAuthorization(root, { expectedDid: "did:key:holder", resume: async () => { throw new Error("session bearer unavailable"); } });

    root.querySelector<HTMLButtonElement>("button")!.click();
    await vi.waitFor(() => expect(root.textContent).toContain("We couldn't confirm this OpenKey device."));
    expect(root.textContent).not.toContain("session bearer unavailable");
    expect(debug).toHaveBeenCalledOnce();
  });
});

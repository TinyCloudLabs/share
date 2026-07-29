import { describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createShareHostFromEnv } from "../src/host/share-adapter.js";
import { startProductionServer } from "../src/host/production-server.js";
import { COMMITTED_TRUST_BUNDLE_PATH, loadTrustBundle, validateTrustBundle } from "../src/host/trust-bundle.js";

/**
 * TC-372. The Share trust bundle contains no secret. Every one of its
 * seventeen fields is a public origin, a `did:web` identifier, a key id, a
 * PUBLIC Ed25519 key, a version or an enablement boolean, and fifteen of them
 * are already republished verbatim at
 * `/.well-known/tinycloud-share/config.json`. Sealing it inside the CVM
 * therefore protected nothing while making it unchangeable, because a Phala
 * sealed environment can only be rewritten wholesale — taking the co-sealed
 * Cloudflare Tunnel token with it.
 *
 * These tests hold the committed replacement to the two properties that make
 * unsealing safe: it is byte-for-byte the trust production already publishes,
 * so switching the source changes nothing observable; and it fails closed on
 * every way it could be missing, empty, malformed or ambiguous.
 */

/**
 * Read from https://share.tinycloud.xyz/.well-known/tinycloud-share/config.json
 * on 2026-07-29. `nodeInvitationPublicKey` is the known-wrong development
 * fixture from TC-359; it is pinned here deliberately, so that flipping the
 * source is provably a no-op and correcting the key is a separate, visible,
 * one-line diff (TC-369).
 */
const PUBLISHED_IN_PRODUCTION = {
  shareOrigin: "https://share.tinycloud.xyz",
  registryOrigin: "https://registry.tinycloud.xyz",
  nodeOrigin: "https://tee.node.tinycloud.xyz",
  credentialsOrigin: "https://witness.credentials.org",
  nodeAudience: "did:web:tee.node.tinycloud.xyz",
  nodeEnabled: true,
  issuerDid: "did:web:issuer.credentials.org",
  issuerVct: "opencredentials.email/v1",
  issuerEnabled: true,
  nodeInvitationKid: "did:web:tee.node.tinycloud.xyz#invitation-key-1",
  nodeInvitationPublicKey: "tv7Sn8LztrteJyVgwP9aQL6b1kuiDq9CePhTx19HyrI",
  nodeKeyVersion: 1,
  issuerKeyVersion: 1,
  issuerPublicKey: "eEJI4xEobto4HtQ7Pg9R1vBOwcpfGRTlXDG5QfqLnGQ",
} as const;

function committedDocument(): Record<string, unknown> {
  return JSON.parse(readFileSync(COMMITTED_TRUST_BUNDLE_PATH, "utf8")) as Record<string, unknown>;
}

function scratch(contents?: string): { readonly path: string; readonly cleanup: () => void } {
  const directory = mkdtempSync(join(tmpdir(), "share-trust-bundle-"));
  const path = join(directory, "trust-bundle.production.json");
  if (contents !== undefined) writeFileSync(path, contents);
  return { path, cleanup: () => rmSync(directory, { recursive: true, force: true }) };
}

describe("the committed production trust bundle", () => {
  it("is a strict production bundle with no test escape hatch", () => {
    const bundle = validateTrustBundle(committedDocument());
    expect(bundle.environment).toBe("production");
    expect(bundle.version).toBe("tinycloud.share-email-trust-bundle/v1");
  });

  it("carries no secret material: the sender identity stays empty", () => {
    const bundle = loadTrustBundle({ SHARE_TRUST_BUNDLE_SOURCE: "committed" });
    expect(bundle.sender).toEqual({ senderDid: "", senderPublicKey: "", senderPrivateKey: "" });
    expect(JSON.stringify(committedDocument())).not.toMatch(/private|secret|token/i);
  });

  it("republishes exactly the trust production already serves publicly", () => {
    const host = createShareHostFromEnv({ SHARE_TRUST_BUNDLE_SOURCE: "committed" });
    expect(host.publicConfig).toMatchObject(PUBLISHED_IN_PRODUCTION);
    expect(host.publicConfig.environment).toBeUndefined();
  });

  it("pins returnOrigin to shareOrigin, as tinycloud-node's own validator requires", () => {
    const document = committedDocument();
    expect(document.returnOrigin).toBe(document.shareOrigin);
    expect(document.nodeInvitationKid).toBe(`${String(document.nodeAudience)}#invitation-key-${String(document.nodeKeyVersion)}`);
    expect(String(document.issuerKid).startsWith(`${String(document.issuerDid)}#`)).toBe(true);
  });

  it("produces the identical bundle whether it is committed or passed inline", () => {
    const inline = loadTrustBundle({ SHARE_TRUST_BUNDLE: JSON.stringify(committedDocument()) });
    const committed = loadTrustBundle({ SHARE_TRUST_BUNDLE_SOURCE: "committed" });
    expect(committed).toEqual(inline);
  });

  it("boots the production host with no trust material in the environment at all", async () => {
    const server = startProductionServer({ SHARE_TRUST_BUNDLE_SOURCE: "committed", PORT: "0", HOST: "127.0.0.1" });
    try {
      await once(server, "listening");
      expect(server.listening).toBe(true);
    } finally {
      await new Promise<void>((done) => server.close(() => done()));
    }
  });
});

describe("the committed trust bundle source fails closed", () => {
  it("throws when the committed document is missing", () => {
    const { path, cleanup } = scratch();
    try {
      expect(() => loadTrustBundle({ SHARE_TRUST_BUNDLE_SOURCE: "committed" }, path)).toThrow(/missing or unreadable/);
    } finally {
      cleanup();
    }
  });

  it("throws when the committed document is empty rather than treating it as absent", () => {
    const { path, cleanup } = scratch("   \n");
    try {
      expect(() => loadTrustBundle({ SHARE_TRUST_BUNDLE_SOURCE: "committed" }, path)).toThrow(/is empty/);
    } finally {
      cleanup();
    }
  });

  it("throws when the committed document is not JSON", () => {
    const { path, cleanup } = scratch("{ not json");
    try {
      expect(() => loadTrustBundle({ SHARE_TRUST_BUNDLE_SOURCE: "committed" }, path)).toThrow(/not valid JSON/);
    } finally {
      cleanup();
    }
  });

  it("throws when the committed document is JSON but not a v1 bundle", () => {
    const { path, cleanup } = scratch(JSON.stringify({ version: "tinycloud.share-email-trust-bundle/v1" }));
    try {
      expect(() => loadTrustBundle({ SHARE_TRUST_BUNDLE_SOURCE: "committed" }, path)).toThrow(/invalid shape/);
    } finally {
      cleanup();
    }
  });

  it("throws when the committed invitation key is not a canonical 32-byte key", () => {
    const { path, cleanup } = scratch(JSON.stringify({ ...committedDocument(), nodeInvitationPublicKey: "not-a-key" }));
    try {
      expect(() => loadTrustBundle({ SHARE_TRUST_BUNDLE_SOURCE: "committed" }, path)).toThrow(/nodeInvitationPublicKey/);
    } finally {
      cleanup();
    }
  });

  it("refuses an environment source alongside the committed one instead of silently preferring either", () => {
    const inline = JSON.stringify(committedDocument());
    expect(() => loadTrustBundle({ SHARE_TRUST_BUNDLE_SOURCE: "committed", SHARE_TRUST_BUNDLE: inline })).toThrow(/exactly one Share trust bundle source/);
    expect(() => loadTrustBundle({ SHARE_TRUST_BUNDLE_SOURCE: "committed", SHARE_TRUST_BUNDLE_FILE: COMMITTED_TRUST_BUNDLE_PATH })).toThrow(/exactly one Share trust bundle source/);
  });

  it("rejects an unrecognised source rather than falling back to the environment", () => {
    expect(() => loadTrustBundle({ SHARE_TRUST_BUNDLE_SOURCE: "url", SHARE_TRUST_BUNDLE: JSON.stringify(committedDocument()) })).toThrow(/must be exactly "committed" or "environment"/);
    expect(() => loadTrustBundle({ SHARE_TRUST_BUNDLE_SOURCE: "" })).toThrow(/must be exactly "committed" or "environment"/);
  });
});

describe("the sealed environment source is unchanged", () => {
  it("still loads an inline bundle when no source is selected", () => {
    expect(loadTrustBundle({ SHARE_TRUST_BUNDLE: JSON.stringify(committedDocument()) }).public.shareOrigin).toBe(PUBLISHED_IN_PRODUCTION.shareOrigin);
  });

  it("still loads an inline bundle under an explicit environment source", () => {
    expect(loadTrustBundle({ SHARE_TRUST_BUNDLE_SOURCE: "environment", SHARE_TRUST_BUNDLE: JSON.stringify(committedDocument()) }).public.shareOrigin).toBe(PUBLISHED_IN_PRODUCTION.shareOrigin);
  });

  it("still requires a bundle when neither a source nor an environment value is set", () => {
    expect(() => loadTrustBundle({})).toThrow(/SHARE_TRUST_BUNDLE is required/);
    expect(() => loadTrustBundle({ SHARE_TRUST_BUNDLE_SOURCE: "environment" })).toThrow(/SHARE_TRUST_BUNDLE is required/);
  });

  it("still rejects two environment sources at once", () => {
    expect(() => loadTrustBundle({ SHARE_TRUST_BUNDLE: "{}", SHARE_TRUST_BUNDLE_FILE: COMMITTED_TRUST_BUNDLE_PATH })).toThrow(/exactly one Share trust bundle source/);
  });
});

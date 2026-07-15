import { Buffer } from "node:buffer";

import { ed25519 } from "@noble/curves/ed25519";
import {
  computeDelegationArtifactCid,
  didKeyFromEd25519PublicKey,
  fromBase64Url,
  generateKey,
  nativeVerifiedRecipientBundleV2Schema,
  recipientDidEnvelopeV2Schema,
  recipientDidEnvelopeV2SigningBytes,
  seal,
  toBase64Url,
  unsignedRecipientDidEnvelopeV2Schema,
  type NativeVerifiedRecipientBundleV2,
  type RecipientDidDelegationBundleV2,
  type RecipientDidEnvelopeV2,
  type UnsignedRecipientDidEnvelopeV2,
} from "@tinycloud/share-envelope";
import { putBlob } from "@tinycloud/share-registry";
import {
  createDevRegistry,
  type DevRegistry,
} from "@tinycloud/share-registry/dev-server";
import { beforeEach, describe, expect, it } from "vitest";

import {
  continueRecipientDidShare,
  RecipientNodeReadError,
  openRecipientDidShare,
  verifyRecipientDidShare,
  type RecipientDidReadRequest,
  type RecipientDidViewerAdapter,
} from "../src/viewer/recipient-did.js";
import {
  continueRecipientDidResolution,
  resolveShare,
} from "../src/viewer/resolve.js";
import { renderViewerState } from "../src/viewer/ui.js";
import vector from "../packages/envelope/test/vectors/recipient-did-v2.json";

const NOW = new Date("2029-01-01T00:00:00.000Z");
const REGISTRY_BASE = "http://registry.local";
const VIEWER_ORIGIN = "https://share.tinycloud.xyz";
const ALLOWED_ORIGINS = ["https://node.tinycloud.xyz"] as const;
const fixtureEnvelope = recipientDidEnvelopeV2Schema.parse(vector.envelope);
const fixtureAuthority = nativeVerifiedRecipientBundleV2Schema.parse(vector.nativeVerified);

interface RejectMutation {
  target: "envelope" | "native";
  op: string;
  path?: string;
  value?: unknown;
  origin?: string;
  nodeAudience?: string;
  resign?: boolean;
  nativeReject?: boolean;
}
interface RejectCase { name: string; mutation: RejectMutation; expected: string }

function setPointer(root: unknown, pointer: string, value: unknown): void {
  const parts = pointer.slice(1).split("/").map((part) => part.replaceAll("~1", "/").replaceAll("~0", "~"));
  let cursor = root;
  for (const part of parts.slice(0, -1)) {
    cursor = Array.isArray(cursor)
      ? cursor[Number(part)]
      : (cursor as Record<string, unknown>)[part];
  }
  const last = parts.at(-1)!;
  if (Array.isArray(cursor)) cursor[Number(last)] = value;
  else (cursor as Record<string, unknown>)[last] = value;
}

function getPointer(root: unknown, pointer: string): unknown {
  let cursor = root;
  for (const part of pointer.slice(1).split("/").map((item) => item.replaceAll("~1", "/").replaceAll("~0", "~"))) {
    cursor = Array.isArray(cursor)
      ? cursor[Number(part)]
      : (cursor as Record<string, unknown>)[part];
  }
  return cursor;
}

function signForTest(unsignedInput: UnsignedRecipientDidEnvelopeV2): RecipientDidEnvelopeV2 {
  const seed = fromBase64Url(vector.currentSdkFixture.sessionJwkD);
  const unsigned = unsignedRecipientDidEnvelopeV2Schema.parse(unsignedInput);
  const signerDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(seed));
  const payload = { ...unsigned, signature: { signerDid, algorithm: "Ed25519" as const } };
  return {
    ...payload,
    signature: {
      ...payload.signature,
      value: toBase64Url(ed25519.sign(recipientDidEnvelopeV2SigningBytes(payload), seed)),
    },
  };
}

function resign(input: unknown): RecipientDidEnvelopeV2 {
  const parsed = recipientDidEnvelopeV2Schema.parse(input);
  const { signature: _signature, ...unsigned } = parsed;
  return signForTest(unsignedRecipientDidEnvelopeV2Schema.parse(unsigned));
}

function corruptGrantProof() {
  const grant = fixtureEnvelope.delegation.grant;
  const value = grant.value.replace(/.$/, (last) => last === "A" ? "B" : "A");
  const artifact = { ...grant, value };
  return { ...artifact, cid: computeDelegationArtifactCid(artifact) };
}

function applyReject(testCase: RejectCase): {
  envelope: unknown;
  native: () => Promise<NativeVerifiedRecipientBundleV2>;
} {
  let envelope: unknown = structuredClone(fixtureEnvelope);
  const authority: unknown = structuredClone(fixtureAuthority);
  const mutation = testCase.mutation;
  if (mutation.target === "native") {
    if (mutation.op !== "reject") setPointer(authority, mutation.path!, mutation.value);
  } else {
    const root = fixtureEnvelope.delegation.issuerProofs[0]!;
    const extra = corruptGrantProof();
    if (mutation.op === "set") setPointer(envelope, mutation.path!, mutation.value);
    else if (mutation.op === "misorder-corrupt-grant-proof") setPointer(envelope, "/delegation/issuerProofs", [extra, root]);
    else if (mutation.op === "append-corrupt-grant-proof") setPointer(envelope, "/delegation/issuerProofs", [root, extra]);
    else if (mutation.op === "duplicate-root") setPointer(envelope, "/delegation/issuerProofs", [root, root]);
    else if (mutation.op === "corrupt-grant-value") setPointer(envelope, "/delegation/grant/value", extra.value);
    else if (mutation.op === "set-route") setPointer(envelope, "/delegation/routing", { origin: mutation.origin, nodeAudience: mutation.nodeAudience });
    else if (mutation.op === "set-target-route") {
      setPointer(envelope, "/target/origin", mutation.origin);
      setPointer(envelope, "/target/nodeAudience", mutation.nodeAudience);
    } else if (["uppercase", "remove-padding", "append"].includes(mutation.op)) {
      const current = getPointer(envelope, mutation.path!);
      if (typeof current !== "string") throw new TypeError("mutation target is not a string");
      const replacement = mutation.op === "uppercase" ? current.toUpperCase()
        : mutation.op === "remove-padding" ? current.replace(/=+$/, "")
        : `${current}${String(mutation.value)}`;
      setPointer(envelope, mutation.path!, replacement);
    }
    if (mutation.resign === true) envelope = resign(envelope);
  }
  return {
    envelope,
    native: async () => {
      if (mutation.op === "reject" || mutation.nativeReject === true) throw new Error("native reject");
      return nativeVerifiedRecipientBundleV2Schema.parse(authority);
    },
  };
}

function registryFetch(target: DevRegistry, events: string[]): typeof fetch {
  return async (input, init) => {
    events.push("registry");
    const withDuplex = init?.body === undefined || init.body === null
      ? init
      : ({ ...init, duplex: "half" } as RequestInit);
    return target.handler(new Request(input, withDuplex));
  };
}

async function publish(registry: DevRegistry, envelope: unknown): Promise<string> {
  const key = generateKey();
  const sealed = await seal(Uint8Array.from(Buffer.from(JSON.stringify(envelope), "utf8")), key);
  await putBlob(REGISTRY_BASE, sealed.blob, new Date("2096-01-01T00:00:00.000Z"), {
    fetchFn: registryFetch(registry, []),
  });
  return `${VIEWER_ORIGIN}/s/${sealed.cid}#k=${toBase64Url(key)}`;
}

function makeAdapter(
  events: string[],
  overrides: Partial<RecipientDidViewerAdapter> = {},
): RecipientDidViewerAdapter {
  return {
    verifyDelegationBundle: async () => {
      events.push("native");
      return structuredClone(fixtureAuthority);
    },
    getActiveAccountDid: async () => {
      events.push("active-account");
      return fixtureEnvelope.authorizationTarget.did;
    },
    connectAccount: async () => {
      events.push("connect-account");
      return fixtureEnvelope.authorizationTarget.did;
    },
    readExact: async () => {
      events.push("node");
      return new TextEncoder().encode("# Recipient file");
    },
    ...overrides,
  };
}

let registry: DevRegistry;
beforeEach(() => { registry = createDevRegistry(); });

describe("recipient-DID network ordering", () => {
  for (const testCase of vector.reject as RejectCase[]) {
    it(`${testCase.name}: frozen reject never reaches OpenKey or target node`, async () => {
      const { envelope, native } = applyReject(testCase);
      const url = await publish(registry, envelope);
      const events: string[] = [];
      const adapter = makeAdapter(events, {
        verifyDelegationBundle: async () => {
          events.push("native");
          return native();
        },
      });
      const result = await resolveShare(url, {
        registryBaseUrl: REGISTRY_BASE,
        fetchFn: registryFetch(registry, events),
        recipientDidAdapter: adapter,
        allowedNodeOrigins: ALLOWED_ORIGINS,
        now: () => NOW.getTime(),
      });
      expect(result.state).not.toBe("ok");
      expect(events[0]).toBe("registry");
      expect(events).not.toContain("active-account");
      expect(events).not.toContain("connect-account");
      expect(events).not.toContain("node");
      if (["schema", "artifact-cid-mismatch", "signature"].includes(testCase.expected)) {
        expect(events).not.toContain("native");
      }
    });
  }

  it("never reaches the SDK on invalid links, decryption failures, or schema failures", async () => {
    const cases: Array<() => Promise<{ url: string }>> = [
      async () => ({ url: `${VIEWER_ORIGIN}/not-a-share` }),
      async () => {
        const url = await publish(registry, fixtureEnvelope);
        return { url: url.replace(/#k=.*/, `#k=${toBase64Url(generateKey())}`) };
      },
      async () => ({ url: await publish(registry, { version: 2, shareId: "malformed" }) }),
    ];
    for (const makeCase of cases) {
      const { url } = await makeCase();
      const events: string[] = [];
      const result = await resolveShare(url, {
        registryBaseUrl: REGISTRY_BASE,
        fetchFn: registryFetch(registry, events),
        recipientDidAdapter: makeAdapter(events),
        allowedNodeOrigins: ALLOWED_ORIGINS,
        now: () => NOW.getTime(),
      });
      expect(result.state).not.toBe("ok");
      expect(events).not.toContain("native");
      expect(events).not.toContain("active-account");
      expect(events).not.toContain("connect-account");
      expect(events).not.toContain("node");
    }
  });

  it("checks the static allowlist after native verification and before OpenKey or node", async () => {
    const url = await publish(registry, fixtureEnvelope);
    const events: string[] = [];
    const result = await resolveShare(url, {
      registryBaseUrl: REGISTRY_BASE,
      fetchFn: registryFetch(registry, events),
      recipientDidAdapter: makeAdapter(events),
      allowedNodeOrigins: [],
      now: () => NOW.getTime(),
    });

    expect(result.state).toBe("recipient-verification-failed");
    expect(events).toEqual(["registry", "native"]);
  });

  it("performs registry, native verification, account equality, then one exact node read", async () => {
    const url = await publish(registry, fixtureEnvelope);
    const events: string[] = [];
    let request: RecipientDidReadRequest | undefined;
    const adapter = makeAdapter(events, {
      readExact: async (input) => {
        events.push("node");
        request = input;
        return new TextEncoder().encode("# Recipient file");
      },
    });
    const result = await resolveShare(url, {
      registryBaseUrl: REGISTRY_BASE,
      fetchFn: registryFetch(registry, events),
      recipientDidAdapter: adapter,
      allowedNodeOrigins: ALLOWED_ORIGINS,
      now: () => NOW.getTime(),
    });
    expect(result).toMatchObject({ state: "ok", access: "recipient-did", senderVerified: true });
    expect(events).toEqual(["registry", "native", "active-account", "node"]);
    expect(request).toMatchObject({
      origin: fixtureEnvelope.target.origin,
      nodeAudience: fixtureEnvelope.target.nodeAudience,
      spaceId: fixtureEnvelope.target.spaceId,
      path: fixtureEnvelope.target.resource.path,
      recipientDid: fixtureEnvelope.authorizationTarget.did,
      redirect: "error",
    });
    expect(request?.delegation).toEqual(fixtureEnvelope.delegation);
  });

  it.each([
    ["success", "ok", ["native", "active-account", "node", "after-return"]],
    ["native", "recipient-verification-failed", ["native", "after-return"]],
    ["active-account", "recipient-identity-cancelled", ["native", "active-account", "after-return"]],
    ["node", "recipient-node-unavailable", ["native", "active-account", "node", "after-return"]],
  ] as const)(
    "zeroes the fragment key before post-decrypt callbacks on %s paths",
    async (failureStage, expectedState, expectedStages) => {
      const url = await publish(registry, fixtureEnvelope);
      let parsedKey: Uint8Array | undefined;
      const observations: Array<{ stage: string; zero: boolean }> = [];
      const observe = (stage: string): void => {
        if (parsedKey === undefined) throw new Error("fragment key was not observed");
        observations.push({
          stage,
          zero: parsedKey.every((byte) => byte === 0),
        });
      };
      const result = await resolveShare(url, {
        registryBaseUrl: REGISTRY_BASE,
        fetchFn: registryFetch(registry, []),
        allowedNodeOrigins: ALLOWED_ORIGINS,
        now: () => NOW.getTime(),
        onKeyParsed: (key) => {
          parsedKey = key;
        },
        recipientDidAdapter: {
          verifyDelegationBundle: async () => {
            observe("native");
            if (failureStage === "native") throw new Error("native failed");
            return structuredClone(fixtureAuthority);
          },
          getActiveAccountDid: async () => {
            observe("active-account");
            if (failureStage === "active-account") {
              throw new Error("account lookup failed");
            }
            return fixtureEnvelope.authorizationTarget.did;
          },
          connectAccount: async () => fixtureEnvelope.authorizationTarget.did,
          readExact: async () => {
            observe("node");
            if (failureStage === "node") throw new Error("node failed");
            return new TextEncoder().encode("# Recipient file");
          },
        },
      });
      observe("after-return");

      expect(result.state).toBe(expectedState);
      expect(observations.map(({ stage }) => stage)).toEqual(expectedStages);
      expect(observations.every(({ zero }) => zero)).toBe(true);
    },
  );

  it.each([
    ["registry fetch", "fetch-failed"],
    ["envelope decrypt", "decrypt-failed"],
  ] as const)("zeroes the fragment key after a %s failure", async (failure, state) => {
    const published = await publish(registry, fixtureEnvelope);
    const url = failure === "envelope decrypt"
      ? published.replace(/#k=.*/, `#k=${toBase64Url(generateKey())}`)
      : published;
    let parsedKey: Uint8Array | undefined;
    const result = await resolveShare(url, {
      registryBaseUrl: REGISTRY_BASE,
      fetchFn: failure === "registry fetch"
        ? async () => new Response(null, { status: 503 })
        : registryFetch(registry, []),
      onKeyParsed: (key) => {
        parsedKey = key;
      },
    });

    expect(result.state).toBe(state);
    expect(parsedKey).toBeDefined();
    expect(parsedKey?.every((byte) => byte === 0)).toBe(true);
  });

  it("zeroes the fragment key when the key observer throws", async () => {
    const url = await publish(registry, fixtureEnvelope);
    let parsedKey: Uint8Array | undefined;

    await expect(resolveShare(url, {
      registryBaseUrl: REGISTRY_BASE,
      fetchFn: registryFetch(registry, []),
      onKeyParsed: (key) => {
        parsedKey = key;
        throw new Error("observer failed");
      },
    })).rejects.toThrow("observer failed");

    expect(parsedKey).toBeDefined();
    expect(parsedKey?.every((byte) => byte === 0)).toBe(true);
  });

  it("requires a user action when there is no active account", async () => {
    const events: string[] = [];
    const result = await openRecipientDidShare(fixtureEnvelope, {
      adapter: makeAdapter(events, { getActiveAccountDid: async () => { events.push("active-account"); return null; } }),
      allowedOrigins: ALLOWED_ORIGINS,
      now: NOW,
    });
    expect(result.state).toBe("recipient-identity-required");
    expect(events).toEqual(["native", "active-account"]);
  });

  it("never reaches the node for a wrong or noncanonical account", async () => {
    for (const did of [
      "did:pkh:eip155:1:0x0000000000000000000000000000000000000000",
      fixtureEnvelope.authorizationTarget.did.toUpperCase(),
    ]) {
      const events: string[] = [];
      const result = await openRecipientDidShare(fixtureEnvelope, {
        adapter: makeAdapter(events, { getActiveAccountDid: async () => { events.push("active-account"); return did; } }),
        allowedOrigins: ALLOWED_ORIGINS,
        now: NOW,
      });
      expect(result.state).toBe("recipient-wrong-account");
      expect(events).not.toContain("node");
    }
  });

  it("uses connectAccount only in explicit connect mode", async () => {
    const events: string[] = [];
    const result = await openRecipientDidShare(fixtureEnvelope, {
      adapter: makeAdapter(events),
      allowedOrigins: ALLOWED_ORIGINS,
      accountMode: "connect",
      now: NOW,
    });
    expect(result.state).toBe("recipient-ok");
    expect(events).toEqual(["native", "connect-account", "node"]);
  });

  it("continues account selection without retaining/replaying the link or native verification", async () => {
    const url = await publish(registry, fixtureEnvelope);
    const events: string[] = [];
    const keyBuffers: Uint8Array[] = [];
    const adapter = makeAdapter(events, {
      getActiveAccountDid: async () => {
        events.push("active-account");
        return null;
      },
    });
    const initial = await resolveShare(url, {
      registryBaseUrl: REGISTRY_BASE,
      fetchFn: registryFetch(registry, events),
      recipientDidAdapter: adapter,
      allowedNodeOrigins: ALLOWED_ORIGINS,
      now: () => NOW.getTime(),
      onKeyParsed: (key) => keyBuffers.push(key),
    });
    expect(initial.state).toBe("recipient-identity-required");
    if (initial.state !== "recipient-identity-required") throw new Error("expected continuation");
    expect(initial.continuation.validUntilMs).toBe(
      NOW.getTime() + 5 * 60 * 1_000,
    );
    expect(events).toEqual(["registry", "native", "active-account"]);
    expect(keyBuffers).toHaveLength(1);
    expect(keyBuffers[0]?.every((byte) => byte === 0)).toBe(true);

    events.length = 0;
    const resumed = await continueRecipientDidResolution(initial.continuation, {
      adapter,
      accountMode: "connect",
      now: NOW,
    });
    expect(resumed.state).toBe("ok");
    expect(events).toEqual(["connect-account", "node"]);
  });

  it("atomically rejects a concurrent replay and performs exactly one node read", async () => {
    const events: string[] = [];
    let releaseAccount!: (did: string) => void;
    const accountGate = new Promise<string>((resolve) => {
      releaseAccount = resolve;
    });
    const adapter = makeAdapter(events, {
      getActiveAccountDid: async () => {
        events.push("active-account");
        return accountGate;
      },
      readExact: async () => {
        events.push("node");
        return new TextEncoder().encode("# Recipient file");
      },
    });
    const verified = await verifyRecipientDidShare(fixtureEnvelope, {
      adapter,
      allowedOrigins: ALLOWED_ORIGINS,
      now: NOW,
    });
    if (verified.state !== "recipient-verified") {
      throw new Error("expected verified continuation");
    }

    const winner = continueRecipientDidShare(verified.continuation, {
      adapter,
      accountMode: "active",
      now: NOW,
    });
    const loser = continueRecipientDidShare(verified.continuation, {
      adapter,
      accountMode: "active",
      now: NOW,
    });
    releaseAccount(fixtureEnvelope.authorizationTarget.did);

    const [winnerResult, loserResult] = await Promise.all([winner, loser]);
    expect(winnerResult.state).toBe("recipient-ok");
    expect(loserResult.state).toBe("recipient-continuation-expired");
    expect(events).toEqual(["native", "active-account", "node"]);
    expect(events.filter((event) => event === "node")).toHaveLength(1);
  });

  it.each([
    ["cancelled", "recipient-identity-cancelled"],
    ["wrong account", "recipient-wrong-account"],
  ] as const)("restores a live continuation after %s identity selection", async (firstOutcome, firstState) => {
    const events: string[] = [];
    let attempts = 0;
    const adapter = makeAdapter(events, {
      connectAccount: async () => {
        events.push("connect-account");
        attempts += 1;
        if (attempts === 1) {
          if (firstOutcome === "cancelled") throw new Error("user cancelled");
          return "did:pkh:eip155:1:0x0000000000000000000000000000000000000000";
        }
        return fixtureEnvelope.authorizationTarget.did;
      },
    });
    const verified = await verifyRecipientDidShare(fixtureEnvelope, {
      adapter,
      allowedOrigins: ALLOWED_ORIGINS,
      now: NOW,
    });
    if (verified.state !== "recipient-verified") {
      throw new Error("expected verified continuation");
    }

    const first = await continueRecipientDidShare(verified.continuation, {
      adapter,
      accountMode: "connect",
      now: NOW,
    });
    expect(first.state).toBe(firstState);

    const retry = await continueRecipientDidShare(verified.continuation, {
      adapter,
      accountMode: "connect",
      now: NOW,
    });
    expect(retry.state).toBe("recipient-ok");
    expect(events).toEqual(["native", "connect-account", "connect-account", "node"]);
  });

  it("consumes the continuation after a node attempt, including node failure", async () => {
    const events: string[] = [];
    const adapter = makeAdapter(events, {
      readExact: async () => {
        events.push("node");
        throw new RecipientNodeReadError("unavailable");
      },
    });
    const verified = await verifyRecipientDidShare(fixtureEnvelope, {
      adapter,
      allowedOrigins: ALLOWED_ORIGINS,
      now: NOW,
    });
    if (verified.state !== "recipient-verified") {
      throw new Error("expected verified continuation");
    }

    const attempted = await continueRecipientDidShare(verified.continuation, {
      adapter,
      accountMode: "active",
      now: NOW,
    });
    expect(attempted.state).toBe("recipient-node-unavailable");

    const replay = await continueRecipientDidShare(verified.continuation, {
      adapter,
      accountMode: "active",
      now: NOW,
    });
    expect(replay.state).toBe("recipient-continuation-expired");
    expect(events).toEqual(["native", "active-account", "node"]);
  });

  it("expires the verified continuation before any later account or node call", async () => {
    const events: string[] = [];
    const adapter = makeAdapter(events, {
      getActiveAccountDid: async () => {
        events.push("active-account");
        return null;
      },
    });
    const initial = await openRecipientDidShare(fixtureEnvelope, {
      adapter,
      allowedOrigins: ALLOWED_ORIGINS,
      now: NOW,
    });
    expect(initial.state).toBe("recipient-identity-required");
    if (initial.state !== "recipient-identity-required") {
      throw new Error("expected continuation");
    }

    events.length = 0;
    const expired = await continueRecipientDidShare(initial.continuation, {
      adapter,
      accountMode: "connect",
      now: new Date(NOW.getTime() + 5 * 60 * 1_000),
    });
    expect(expired.state).toBe("recipient-continuation-expired");
    expect(events).toEqual([]);
  });

  it.each([
    ["unauthorized", "recipient-node-unauthorized"],
    ["not-found", "recipient-node-not-found"],
    ["unavailable", "recipient-node-unavailable"],
  ] as const)("maps %s node failures without leaking adapter detail", async (code, state) => {
    const result = await openRecipientDidShare(fixtureEnvelope, {
      adapter: makeAdapter([], { readExact: async () => { throw new RecipientNodeReadError(code); } }),
      allowedOrigins: ALLOWED_ORIGINS,
      now: NOW,
    });
    expect(result.state).toBe(state);
  });
});

describe("recipient-DID viewer states", () => {
  it("renders a keyboard-operable account button in document order and announces errors", async () => {
    const root = document.createElement("div");
    document.body.append(root);
    let selected = 0;
    const verified = await openRecipientDidShare(fixtureEnvelope, {
      adapter: makeAdapter([], { getActiveAccountDid: async () => null }),
      allowedOrigins: ALLOWED_ORIGINS,
      now: NOW,
    });
    expect(verified.state).toBe("recipient-identity-required");
    if (verified.state !== "recipient-identity-required") {
      throw new Error("expected recipient continuation");
    }
    renderViewerState(root, {
      state: "recipient-identity-required",
      envelope: fixtureEnvelope,
      continuation: verified.continuation,
    }, { onSelectRecipientAccount: () => { selected += 1; } });
    const button = root.querySelector("button");
    expect(button?.textContent).toBe("Choose account");
    expect(document.activeElement).not.toBe(button);
    button?.click();
    expect(selected).toBe(1);

    renderViewerState(root, { state: "recipient-verification-failed" });
    expect(root.querySelector('[role="alert"]')).not.toBeNull();
    expect(root.querySelector(".viewer-content")).toBeNull();
  });
});

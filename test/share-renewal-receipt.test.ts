// @vitest-environment node
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { PersistedSessionData } from "@tinycloud/web-sdk";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { admitSignInRenewal, renewalRestoreFor, verifiedRenewalLease } from "../src/share/renewal-receipt.js";
import { clearRenewalReceipt, loadRenewalReceipt, renewalReceiptRunning, saveRenewalReceipt } from "../src/share/renewal-store.js";
import { fixture, iso, originalEnd, OTHER_RENEWER } from "./renewal-fixture.js";

const PREFIX = "tinycloud-share-library-";

// The SIWE fixtures are CBOR built from node byte arrays, which jsdom's realm would not accept: this file runs under node with a small storage.
beforeEach(() => {
  const values = new Map<string, string>();
  const localStorage = {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => void values.set(key, value),
    removeItem: (key: string) => void values.delete(key),
  };
  Object.defineProperty(globalThis, "window", { value: { localStorage }, configurable: true });
});

describe("a renewal receipt is checked against the saved session record", () => {
  it("yields the lease for the saved grant, signed by its owner for that grant's renewal alone", async () => {
    const { record, receipt, lease } = await fixture();
    expect(await verifiedRenewalLease(receipt, record)).toBe(lease.authorization);
  });

  it("refuses a lease for another session", async () => {
    const { record, receipt } = await fixture();
    const other = await fixture();
    expect(await verifiedRenewalLease(other.receipt, record)).toBeNull();
    expect(await verifiedRenewalLease({ ...receipt, receipt: { ...receipt.receipt, originalCid: other.record.tinycloudSession!.delegationCid } }, record)).toBeNull();
  });

  it("refuses a lease another wallet signed", async () => {
    const { record, receipt } = await fixture({ leaseSigner: privateKeyToAccount(generatePrivateKey()) });
    expect(await verifiedRenewalLease(receipt, record)).toBeNull();
  });

  it("refuses a lease whose grant owner is not the saved session's account", async () => {
    const { record, receipt } = await fixture();
    const someoneElse = privateKeyToAccount(generatePrivateKey()).address;
    expect(await verifiedRenewalLease(receipt, { ...record, address: someoneElse })).toBeNull();
  });

  it("refuses a lease that grants more than renewing that grant", async () => {
    const { record, receipt } = await fixture({ extraAbility: true });
    expect(await verifiedRenewalLease(receipt, record)).toBeNull();
  });

  it("refuses a lease that names a renewer other than the receipt's", async () => {
    const { record, receipt } = await fixture({ leaseAudience: OTHER_RENEWER });
    expect(await verifiedRenewalLease(receipt, record)).toBeNull();
  });

  it("refuses a receipt approved after the grant ended", async () => {
    const late = iso(originalEnd + 1000);
    const { record, receipt } = await fixture({ approvedAt: late });
    expect(await verifiedRenewalLease({ ...receipt, approvedAt: late }, record)).toBeNull();
  });

  it("refuses what is not a receipt at all", async () => {
    const { record } = await fixture();
    expect(await verifiedRenewalLease({ version: 1 }, record)).toBeNull();
    expect(await verifiedRenewalLease(null, record)).toBeNull();
  });
});

describe("a restore through the lease", () => {
  function storage(status: "loaded" | "renewal-candidate" | "missing", record: PersistedSessionData, active?: string) {
    return {
      activeAddressForRenewal: () => active,
      loadRenewalCandidate: async () => status === "missing" ? { status, data: null } : { status, data: record },
    } as Parameters<typeof renewalRestoreFor>[1];
  }

  it("happens only once the saved session is past its end and its receipt checks out", async () => {
    const { owner, record, receipt, lease } = await fixture();
    saveRenewalReceipt(PREFIX, owner.address, receipt);
    expect(await renewalRestoreFor(PREFIX, storage("renewal-candidate", record, owner.address))).toEqual({ address: owner.address, leaseAuthorization: lease.authorization });
    expect(await renewalRestoreFor(PREFIX, storage("loaded", record, owner.address))).toBeNull();
    expect(await renewalRestoreFor(PREFIX, storage("missing", record, owner.address))).toBeNull();
  });

  it("does not happen without a receipt, or with a receipt kept for another account", async () => {
    const { owner, record, receipt } = await fixture();
    expect(await renewalRestoreFor(PREFIX, storage("renewal-candidate", record, owner.address))).toBeNull();
    saveRenewalReceipt(PREFIX, privateKeyToAccount(generatePrivateKey()).address, receipt);
    expect(await renewalRestoreFor(PREFIX, storage("renewal-candidate", record, owner.address))).toBeNull();
  });

  it("does not happen once the receipt is cleared with the session", async () => {
    const { owner, record, receipt } = await fixture();
    saveRenewalReceipt(PREFIX, owner.address, receipt);
    clearRenewalReceipt(PREFIX);
    expect(await renewalRestoreFor(PREFIX, storage("renewal-candidate", record, owner.address))).toBeNull();
  });

  it("is tried by the page only while the receipt's lease end has not passed", async () => {
    const { owner, receipt } = await fixture();
    saveRenewalReceipt(PREFIX, owner.address, receipt);
    expect(renewalReceiptRunning(PREFIX, owner.address)).toBe(true);
    saveRenewalReceipt(PREFIX, owner.address, { ...receipt, receipt: { ...receipt.receipt, leaseExpiresAt: iso(Date.now() - 1000) } });
    expect(renewalReceiptRunning(PREFIX, owner.address)).toBe(false);
  });
});

// The real SDK admission against a loopback stand-in for the session's node: it publishes the renewer identity and records every lease presented.
describe("admitting the lease OpenKey signed at the session's node", () => {
  let node: Server;
  let origin: string;
  let published: unknown;
  let delegateStatus: number | "hang";
  let presented: string[];

  beforeEach(async () => {
    presented = [];
    delegateStatus = 200;
    node = createServer((request, response) => {
      if (request.method === "GET" && request.url === "/.well-known/tinycloud/node-keys") {
        response.setHeader("content-type", "application/json").end(JSON.stringify(published));
      } else if (request.method === "POST" && request.url === "/delegate") {
        presented.push(String(request.headers.authorization ?? ""));
        request.resume();
        if (delegateStatus === "hang") return;
        response.statusCode = delegateStatus;
        response.setHeader("content-type", "application/json").end(JSON.stringify({ activated: [], skipped: [] }));
      } else {
        response.statusCode = 500;
        response.end("unexpected");
      }
    });
    // The repo's TypeScript lib predates Promise.withResolvers.
    await new Promise<void>((resolve) => node.listen(0, "127.0.0.1", resolve));
    origin = `http://127.0.0.1:${(node.address() as AddressInfo).port}`;
  });

  afterEach(async () => {
    node.closeAllConnections();
    await new Promise<void>((resolve) => node.close(() => resolve()));
  });

  const publish = (receipt: { readonly receipt: { readonly nodeIdentity: unknown } }): void => { published = receipt.receipt.nodeIdentity; };
  const admit = (address: string, record: PersistedSessionData, renewal: unknown, load = async (): Promise<PersistedSessionData | null> => record, arrivedAt: number | undefined = performance.now()) =>
    admitSignInRenewal({ tcw: { activeNodeIdentity: async () => ({ origin, nodeDid: "did:key:node" }) }, prefix: PREFIX, address, renewal, arrivedAt, storage: { load } });

  it("admits it and keeps it as the session's receipt", async () => {
    const { owner, record, receipt, lease } = await fixture();
    publish(receipt);
    expect(await admit(owner.address, record, receipt)).toBe(true);
    expect(presented).toEqual([lease.authorization]);
    expect(loadRenewalReceipt(PREFIX, owner.address)).toEqual(receipt);
  });

  it("keeps no receipt when the session was signed out while the node admitted it", async () => {
    const { owner, record, receipt } = await fixture();
    publish(receipt);
    expect(await admit(owner.address, record, receipt, async () => (presented.length === 0 ? record : null))).toBe(false);
    expect(loadRenewalReceipt(PREFIX, owner.address)).toBeNull();
  });

  it("keeps no receipt when the node refuses the lease, so the session runs to its signed end", async () => {
    const { owner, record, receipt } = await fixture();
    publish(receipt);
    delegateStatus = 403;
    expect(await admit(owner.address, record, receipt)).toBe(false);
    expect(presented).toHaveLength(1);
    expect(loadRenewalReceipt(PREFIX, owner.address)).toBeNull();
  });

  it("gives up after five seconds when the node does not answer", async () => {
    const { owner, record, receipt } = await fixture();
    publish(receipt);
    delegateStatus = "hang";
    const started = Date.now();
    expect(await admit(owner.address, record, receipt)).toBe(false);
    expect(Date.now() - started).toBeLessThan(7_000);
    expect(loadRenewalReceipt(PREFIX, owner.address)).toBeNull();
  }, 10_000);

  it("sends nothing when the lease does not check out against the session just signed in", async () => {
    const { owner, record, receipt } = await fixture({ leaseSigner: privateKeyToAccount(generatePrivateKey()) });
    publish(receipt);
    expect(await admit(owner.address, record, receipt)).toBe(false);
    const other = await fixture();
    expect(await admit(owner.address, record, other.receipt)).toBe(false);
    expect(presented).toEqual([]);
    expect(loadRenewalReceipt(PREFIX, owner.address)).toBeNull();
  });

  it("contacts no node and keeps nothing when OpenKey returned no lease", async () => {
    const { owner, record } = await fixture();
    expect(await admit(owner.address, record, undefined)).toBe(false);
    expect(presented).toEqual([]);
    expect(loadRenewalReceipt(PREFIX, owner.address)).toBeNull();
  });

  it("sends nothing once a minute has passed since the lease arrived", async () => {
    const { owner, record, receipt } = await fixture();
    publish(receipt);
    expect(await admit(owner.address, record, receipt, undefined, performance.now() - 60_001)).toBe(false);
    // No arrival time (the lease never came through the sign-in client): not sent.
    expect(await admitSignInRenewal({ tcw: { activeNodeIdentity: async () => ({ origin, nodeDid: "did:key:node" }) }, prefix: PREFIX, address: owner.address, renewal: receipt, arrivedAt: undefined, storage: { load: async () => record } })).toBe(false);
    expect(presented).toEqual([]);
  });
});

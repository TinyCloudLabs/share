/**
 * The library sign-in's renewal lease. When the owner leaves renewal on in OpenKey's sign-in window, OpenKey signs
 * a lease for the session's grant and returns it beside the signed session. It records the lease so the owner's
 * stops can end it, but it does not send it to the node: right after sign-in Share checks it against the session
 * record the SDK just saved, has the session's node admit it, and only then keeps it as the session's receipt
 * (`renewal-store.ts`). The node stays the authority on whether the lease still renews: the SDK's renewal restore
 * asks it before it restores anything. Without a lease, or when a check or the admission fails, the session lasts
 * until its signed end, as a sign-in without renewal does.
 */
import { parseSignedSiweCacao, pkhDid, principalDidEquals } from "@tinycloud/sdk-core";
import { admitOwnerRenewalLease } from "@tinycloud/sdk-core/delegations/renewal";
import { parseApprovalRenewal } from "@tinycloud/share-envelope/links";
import { BrowserSessionStorage, type PersistedSessionData, type TinyCloudWeb } from "@tinycloud/web-sdk";
import { loadRenewalReceipt, saveRenewalReceipt } from "./renewal-store.js";

const RENEW = "tinycloud.delegation/renew";

/** How long the sign-in waits for the node to admit the lease before going on without renewal. */
const ADMIT_TIMEOUT_MS = 5_000;

/**
 * The latest a lease is sent to the node, after it arrived on this device. A stop at OpenKey leaves a sign-in lease
 * it cannot find at the node on for ten minutes, in case the app is still admitting it; this keeps every admission
 * well inside that. Measured on this device's monotonic clock, never against OpenKey's `approvedAt`.
 */
const ADMIT_DEADLINE_MS = 60_000;

/**
 * The lease authorization in `value` when it is a well-formed receipt for `record`'s own grant, signed by the
 * grant's owner, for that grant only; otherwise null. Never throws.
 */
export async function verifiedRenewalLease(value: unknown, record: PersistedSessionData): Promise<string | null> {
  try {
    const renewal = parseApprovalRenewal(value);
    const { receipt } = renewal;
    const grant = record.tinycloudSession;
    if (!grant || receipt.originalCid !== grant.delegationCid) return null;
    const original = await parseSignedSiweCacao(grant.delegationHeader.Authorization.replace(/^Bearer\s+/i, ""), grant.delegationCid);
    const lease = await parseSignedSiweCacao(receipt.leaseAuthorization, receipt.leaseCid);
    const target = lease.attenuation[`urn:cid:${grant.delegationCid}`];
    const caveats = target?.[RENEW];
    const originalEnd = Date.parse(original.expiresAt ?? "");
    if (
      !principalDidEquals(original.issuer, pkhDid(record.address, record.chainId)) ||
      !principalDidEquals(lease.issuer, original.issuer) ||
      lease.audience !== receipt.nodeIdentity.renewerDid ||
      lease.proofs.length !== 0 ||
      Object.keys(lease.attenuation).length !== 1 ||
      !target || Object.keys(target).length !== 1 ||
      !Array.isArray(caveats) || caveats.length !== 1 ||
      typeof caveats[0] !== "object" || caveats[0] === null || Object.keys(caveats[0]).length !== 0 ||
      Date.parse(lease.expiresAt ?? "") !== Date.parse(receipt.leaseExpiresAt) ||
      !Number.isFinite(originalEnd) || Date.parse(renewal.approvedAt) >= originalEnd
    ) {
      return null;
    }
    return receipt.leaseAuthorization;
  } catch {
    return null;
  }
}

export type SessionRecordStorage = Pick<BrowserSessionStorage, "load">;
export type RenewalRestoreStorage = Pick<BrowserSessionStorage, "activeAddressForRenewal" | "loadRenewalCandidate">;

/**
 * Has the signed-in session's node admit the lease OpenKey returned, then keeps it as the session's receipt. The lease
 * must first check out against the session record the sign-in just saved under `prefix`, and is sent only within a
 * minute of `arrivedAt` (a `performance.now()` reading taken when OpenKey returned it). Resolves whether renewal is
 * now on.
 */
export async function admitSignInRenewal(input: {
  tcw: Pick<TinyCloudWeb, "activeNodeIdentity">;
  prefix: string;
  address: string;
  renewal: unknown;
  arrivedAt: number | undefined;
  storage?: SessionRecordStorage;
  receipts?: Storage;
}): Promise<boolean> {
  const { tcw, prefix, address, renewal, arrivedAt } = input;
  if (renewal === undefined || renewal === null || arrivedAt === undefined) return false;
  try {
    const storage = input.storage ?? new BrowserSessionStorage({ keyPrefix: prefix });
    const record = await storage.load(address);
    const grant = record?.tinycloudSession;
    const leaseAuthorization = record ? await verifiedRenewalLease(renewal, record) : null;
    if (!record || !grant || !leaseAuthorization) return false;
    const { receipt } = parseApprovalRenewal(renewal);
    const { origin } = await tcw.activeNodeIdentity();
    const remaining = arrivedAt + ADMIT_DEADLINE_MS - performance.now();
    if (!(remaining > 0)) return false;
    await admitOwnerRenewalLease({
      host: origin,
      originalAuthorization: grant.delegationHeader.Authorization.replace(/^Bearer\s+/i, ""),
      originalCid: grant.delegationCid,
      ownerDid: pkhDid(record.address, record.chainId),
      agentDid: grant.verificationMethod,
      spaceId: grant.spaceId,
      nodeIdentity: receipt.nodeIdentity,
      leaseAuthorization,
      leaseCid: receipt.leaseCid,
      leaseExpiresAt: receipt.leaseExpiresAt,
      signal: AbortSignal.timeout(Math.min(ADMIT_TIMEOUT_MS, remaining)),
    });
    // A sign-out during the admission cleared the record: keep no receipt beside a session that is gone.
    if ((await storage.load(address))?.tinycloudSession?.delegationCid !== grant.delegationCid) return false;
    return saveRenewalReceipt(prefix, address, renewal, input.receipts);
  } catch {
    return false;
  }
}

export interface RenewalRestore {
  readonly address: string;
  readonly leaseAuthorization: string;
}

/**
 * Restore through the lease only when the saved session is past its signed end and its own receipt checks out.
 * Null otherwise: a session still inside its signed end needs no lease, and one without a receipt is left for the
 * plain restore.
 */
export async function renewalRestoreFor(
  prefix: string,
  storage: RenewalRestoreStorage = new BrowserSessionStorage({ keyPrefix: prefix }),
  receipts?: Storage,
): Promise<RenewalRestore | null> {
  const address = storage.activeAddressForRenewal();
  if (!address) return null;
  const receipt = loadRenewalReceipt(prefix, address, receipts);
  if (receipt === null) return null;
  const candidate = await storage.loadRenewalCandidate(address);
  if (candidate.status !== "renewal-candidate") return null;
  const leaseAuthorization = await verifiedRenewalLease(receipt, candidate.data);
  return leaseAuthorization ? { address, leaseAuthorization } : null;
}

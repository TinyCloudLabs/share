import type { SenderHistoryDisplayRecord } from "./sender-history.js";
import { parseOwnedSpace } from "./owner-revoke.js";
import { SHARE_APPLICATION_SPACE, type ShareTinyCloud } from "./openkey-session.js";

/**
 * TC-1584. What the owner's node says about each saved share.
 *
 * The saved record only knows what this browser did to the share (it never
 * hears about a revocation made on the account site or the CLI). The node
 * lists the account's own delegations with their lifecycle state, and that
 * answer needs no wallet approval: it is an ordinary signed-in read.
 *
 * Only a share this account made on the node this session is on is asked
 * about. Everything the node cannot confirm is `unknown`, never `active`.
 */
export type NodeShareState = "active" | "revoked" | "expired" | "unknown";

export interface NodeShareStatus {
  readonly state: NodeShareState;
  /** For `expired`: when the node says the share ended (ISO time). Absent when the node did not say; the saved expiry is never a stand-in. */
  readonly expiredAt?: string;
}

/** `signal` aborts the read: no further page is asked for once it has fired. */
export type NodeStatusReader = (records: readonly SenderHistoryDisplayRecord[], signal?: AbortSignal) => Promise<ReadonlyMap<string, NodeShareStatus>>;

const MAX_LISTING_PAGES = 20;
const LISTING_PAGE_SIZE = 100;

interface NodeRow { readonly state: "active" | "revoked" | "expired"; readonly expiresAt: string | undefined }

function rowState(status: string): NodeRow["state"] {
  if (status === "revoked" || status === "ancestor_revoked") return "revoked";
  return status === "expired" ? "expired" : "active";
}

function isoOf(value: Date | string | null): string | undefined {
  if (value === null) return undefined;
  const time = new Date(value).getTime();
  return Number.isFinite(time) ? new Date(time).toISOString() : undefined;
}

/** The share's own roots: the policy root for an addressed share, the delegation itself for a link. */
function rootsOf(record: SenderHistoryDisplayRecord): readonly string[] {
  return [record.ownerDelegationCid, record.enforcementDelegationCid].filter((cid): cid is string => cid !== undefined && cid.length > 0);
}

export function createNodeStatusReader(tinycloud: Pick<ShareTinyCloud, "delegations" | "activeNodeIdentity">, address: string): NodeStatusReader {
  return async (records, signal) => {
    // A function, so the check is read again after every await.
    const stopped = (): boolean => signal?.aborted === true;
    const result = new Map<string, NodeShareStatus>(records.map((record) => [record.shareId, { state: "unknown" }]));
    let node: { readonly origin: string; readonly nodeDid: string };
    try {
      node = await tinycloud.activeNodeIdentity();
    } catch {
      return result;
    }
    const mine = records.filter((record) => {
      const space = parseOwnedSpace(record.target.spaceId);
      return space !== undefined && space.address === address.toLowerCase() && space.name === SHARE_APPLICATION_SPACE
        && record.target.origin === node.origin && record.target.nodeAudience === node.nodeDid && rootsOf(record).length > 0;
    });
    const spaces = [...new Set(mine.map((record) => record.target.spaceId))];
    for (const spaceId of spaces) {
      if (stopped()) break;
      const known = new Map<string, NodeRow>();
      let complete = false;
      try {
        let cursor: string | undefined;
        for (let page = 0; page < MAX_LISTING_PAGES && !stopped(); page += 1) {
          const listing = await tinycloud.delegations.query({ direction: "granted", space: spaceId, limit: LISTING_PAGE_SIZE, ...(cursor === undefined ? {} : { cursor }) });
          if (!listing.ok) break;
          for (const row of listing.data.items) known.set(row.cid, { state: rowState(row.status), expiresAt: isoOf(row.expiresAt) });
          cursor = listing.data.nextCursor;
          if (cursor === undefined) { complete = true; break; }
        }
      } catch {
        complete = false;
      }
      for (const record of mine.filter((candidate) => candidate.target.spaceId === spaceId)) {
        const rows = rootsOf(record).map((cid) => known.get(cid));
        const states = rows.map((row) => row?.state);
        // Any root the node shows as revoked ends the share, whatever else is unread.
        if (states.includes("revoked")) result.set(record.shareId, { state: "revoked" });
        else if (states.includes("expired")) {
          // The earliest end the node names among the expired roots.
          const ends = rows.filter((row) => row?.state === "expired").flatMap((row) => row?.expiresAt === undefined ? [] : [row.expiresAt]).sort();
          result.set(record.shareId, ends[0] === undefined ? { state: "expired" } : { state: "expired", expiredAt: ends[0] });
        }
        // "Active" needs a complete listing and the share's root in it; an enforcement root the account does not list proves nothing either way.
        else if (complete && states.some((state) => state !== undefined)) result.set(record.shareId, { state: "active" });
      }
    }
    return result;
  };
}

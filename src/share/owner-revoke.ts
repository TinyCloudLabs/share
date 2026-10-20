import type { AccountDelegationRecord } from "@tinycloud/sdk-core";
import type { SenderShareRecord } from "@tinycloud/share-sdk";
import { ownerEncryptionNetwork, SHARE_APPLICATION_PREFIX, SHARE_APPLICATION_SPACE, type ShareTinyCloud } from "./openkey-session.js";

/**
 * TC-721. Revoking a share with the owner's wallet when the session that
 * created it is gone.
 *
 * A saved share record is encrypted client state: the library writes it, an
 * imported link can create one, and nothing in it is authority. Before the
 * wallet is asked to sign a revocation of `cid`, the node itself is asked
 * whether that CID is a share root this app created in the signed-in
 * account's own applications space. If any part cannot be shown, nothing is
 * signed.
 */

const MAX_LISTING_PAGES = 20;
const LISTING_PAGE_SIZE = 100;
const SHARE_OBJECTS = `${SHARE_APPLICATION_PREFIX}shares/`;

/** What the node says about the delegation the wallet is about to revoke. */
export type VerifiedRootState = "active" | "revoked";

/** Which kind of share root is being verified; they differ only in what the node lists for them. */
export type ShareRootKind = "policy-root" | "bearer";

/** Reasons the sender page maps to its own copy. */
export type OwnerRevokeRefusal = "revoke-unbound-policy-root" | "revoke-earlier-sign-in" | "revoke-listing-incomplete";

function refuse(reason: OwnerRevokeRefusal): Error {
  return new Error(reason);
}

/** `tinycloud:pkh:eip155:<chain>:<address>:<name>` split into the address and the space name, or undefined for any other shape. */
export function parseOwnedSpace(spaceId: string): { readonly address: string; readonly name: string } | undefined {
  const match = /^tinycloud:pkh:eip155:\d+:(0x[0-9a-fA-F]{40}):([A-Za-z0-9._-]+)$/.exec(spaceId);
  return match === null ? undefined : { address: match[1]!.toLowerCase(), name: match[2]! };
}

/**
 * Every resource of the listed delegation must be this share's own object
 * (`<space>/kv/<record path>`) or the signed-in account's own encryption
 * network, and at least one must be the object. A session delegation, a
 * delegation that also reaches other data, and another share's root all fail.
 */
function grantsOnlyThisShare(row: AccountDelegationRecord, record: SenderShareRecord, address: string): boolean {
  const space = record.target.spaceId.toLowerCase();
  const network = ownerEncryptionNetwork(address).toLowerCase();
  let objects = 0;
  for (const entry of row.resources) {
    if (entry.resource.toLowerCase() === network) continue;
    const marker = entry.resource.indexOf("/kv/");
    if (marker < 0 || entry.resource.slice(0, marker).toLowerCase() !== space) return false;
    const path = entry.resource.slice(marker + "/kv/".length);
    const inside = record.resource.kind === "exact" ? path === record.resource.path : path.startsWith(record.resource.path);
    if (!inside) return false;
    objects += 1;
  }
  return objects > 0;
}

/**
 * Finds `cid` in the signed-in account's own delegations on the active node
 * and checks it against the record. Returns the node's lifecycle state;
 * throws `revoke-unbound-policy-root` when the record belongs to another
 * account or node, `revoke-earlier-sign-in` when it cannot be shown to be this
 * account's share, and `revoke-listing-incomplete` when the listing was longer
 * than the pages read.
 */
export async function verifyShareRootOnNode(input: {
  readonly tinycloud: ShareTinyCloud;
  readonly address: string;
  readonly node: { readonly origin: string; readonly nodeDid: string };
  readonly record: SenderShareRecord;
  readonly cid: string | undefined;
  readonly kind: ShareRootKind;
}): Promise<VerifiedRootState> {
  const { record, cid, kind } = input;
  const space = parseOwnedSpace(record.target.spaceId);
  if (space === undefined || space.address !== input.address.toLowerCase()) throw refuse("revoke-unbound-policy-root");
  if (record.target.origin !== input.node.origin || record.target.nodeAudience !== input.node.nodeDid) throw refuse("revoke-unbound-policy-root");
  if (space.name !== SHARE_APPLICATION_SPACE || cid === undefined || cid.length === 0) throw refuse("revoke-earlier-sign-in");
  if (!record.resource.path.startsWith(SHARE_OBJECTS)) throw refuse("revoke-earlier-sign-in");
  if (kind === "policy-root" && (record.ownerDid === undefined || !record.ownerDid.startsWith("did:key:"))) throw refuse("revoke-earlier-sign-in");

  let cursor: string | undefined;
  for (let page = 0; page < MAX_LISTING_PAGES; page += 1) {
    // The node derives the account from the signed request; the record cannot choose it.
    const listing = await input.tinycloud.delegations.query({ direction: "granted", space: record.target.spaceId, limit: LISTING_PAGE_SIZE, ...(cursor === undefined ? {} : { cursor }) });
    if (!listing.ok) throw refuse("revoke-earlier-sign-in");
    const row = listing.data.items.find((item) => item.cid === cid);
    if (row !== undefined) {
      if (row.direction !== "granted") throw refuse("revoke-earlier-sign-in");
      if (!grantsOnlyThisShare(row, record, input.address)) throw refuse("revoke-earlier-sign-in");
      // Share roots are signed by a session key, and the policy roots have no proof chain.
      if (kind === "policy-root" && (row.delegatorDid !== record.ownerDid || !row.delegatorDid.startsWith("did:key:") || row.parents.length > 0)) throw refuse("revoke-earlier-sign-in");
      return row.status === "revoked" || row.status === "ancestor_revoked" ? "revoked" : "active";
    }
    cursor = listing.data.nextCursor;
    if (cursor === undefined) throw refuse("revoke-earlier-sign-in");
  }
  // The page cap ran out with more of the list unread: not finding the root says nothing about the share.
  throw refuse("revoke-listing-incomplete");
}

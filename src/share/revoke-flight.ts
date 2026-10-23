/**
 * TC-721. Revokes in flight, for the whole page session.
 *
 * The library view is mounted again every time the sender leaves it and comes
 * back, and an OpenKey approval can stay open for a minute or more. A guard
 * that lived in the view would let a re-mounted row start a second revoke (a
 * second wallet request) for the same share. These maps live at module level,
 * keyed by account and share, and are cleared when the revoke settles.
 */

export interface FlightOutcome {
  readonly revoked: boolean;
  /** The reason a revoke did not happen; only read to choose the message. */
  readonly failure?: unknown;
}

const flights = new Map<string, RevokeFlight>();
/** Only one OpenKey approval is open at a time, so a cancel always belongs to the revoke that asked. */
let walletRequestOpen = false;
/**
 * Counts sign-outs. A revoke started before one belongs to a session that no
 * longer exists: it may not ask the wallet for anything, and its late settle
 * must not release a guard that now belongs to the next account.
 */
let session = 0;
/** Gives up the wallet requests that are open, so their waiters end now instead of at the 60 s window. */
const openRequests = new Set<() => void>();

export function flightKey(address: string, shareId: string): string {
  return `${address.toLowerCase()}/${shareId}`;
}

export function activeFlight(key: string): RevokeFlight | undefined {
  return flights.get(key);
}

export class RevokeFlight {
  /** True while this revoke's OpenKey approval is open. */
  approval = false;
  /** Rows showing this flight repaint when `approval` changes. */
  readonly subscribers = new Set<() => void>();
  readonly done: Promise<FlightOutcome>;
  /** The sign-in this revoke belongs to. */
  readonly session = session;
  /** Set by a revoke that succeeded but could not remove the stored link. Shown once to the sender. */
  note?: string;

  constructor(key: string, run: (flight: RevokeFlight) => Promise<void>) {
    flights.set(key, this);
    this.done = run(this).then(
      (): FlightOutcome => ({ revoked: true }),
      (failure: unknown): FlightOutcome => ({ revoked: false, failure }),
    ).finally(() => { if (flights.get(key) === this) flights.delete(key); });
  }

  setApproval(open: boolean): void {
    this.approval = open;
    for (const repaint of [...this.subscribers]) repaint();
  }
}

/** The owner wallet's revocation request is valid for this long from the moment the approval is asked for. */
export const APPROVAL_WINDOW_MS = 60_000;

/** What `withWalletApproval` needs to know about its caller: where to report the open approval, and (for a revoke) the sign-in it belongs to. */
export interface WalletApprovalSubject {
  setApproval(open: boolean): void;
  readonly session?: number;
}

/** True for the error `withWalletApproval` throws when it stops waiting after the approval window. */
export function isApprovalAbandoned(error: unknown): boolean {
  return error instanceof Error && error.message === "revoke-approval-abandoned";
}

/**
 * Runs `task` (the wallet request) only if no other approval is open. A second
 * share's revoke is refused with `revoke-another-approval` instead of queueing,
 * so the person is never asked to approve something they did not just click.
 *
 * The lock is held for at most the approval window: the signed request is
 * dead after 60 seconds, and an external wallet or a closed window may never
 * answer. After that Share stops waiting (`revoke-approval-abandoned`), frees
 * the lock and lets the sender try again. The abandoned request is told it is
 * no longer current (`current()` is false), so a late answer cannot touch the
 * state of a newer attempt; the row never turns Revoked from it. If it did
 * revoke the share, the next attempt's node check sees that and finishes with
 * no new approval.
 */
export async function withWalletApproval<T>(flight: WalletApprovalSubject, task: (current: () => boolean) => Promise<T>): Promise<T> {
  // A revoke that outlived its sign-in never reaches the wallet. (A caller that is not a revoke has no sign-in of its own to outlive.)
  if (flight.session !== undefined && flight.session !== session) throw new Error("revoke-session-ended");
  if (walletRequestOpen) throw new Error("revoke-another-approval");
  walletRequestOpen = true;
  flight.setApproval(true);
  let abandoned = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let abandon: () => void = () => undefined;
  const expiry = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => { abandoned = true; reject(new Error("revoke-approval-abandoned")); }, APPROVAL_WINDOW_MS);
    abandon = () => { abandoned = true; reject(new Error("revoke-session-ended")); };
  });
  openRequests.add(abandon);
  const mine = session;
  try {
    const running = task(() => !abandoned);
    // A request abandoned here may still reject later; nobody is waiting for it.
    running.catch(() => undefined);
    return await Promise.race([running, expiry]);
  } finally {
    clearTimeout(timer);
    openRequests.delete(abandon);
    // After a sign-out the lock may already belong to the next account's request.
    if (mine === session) walletRequestOpen = false;
    flight.setApproval(false);
  }
}

/**
 * Sign-out, and a fresh page load in tests: forgets every flight, frees the
 * wallet lock and abandons the wallet request that is open. A request that
 * answers late is told it is no longer current and changes nothing.
 */
export function resetRevokeFlights(): void {
  session += 1;
  flights.clear();
  walletRequestOpen = false;
  for (const abandon of [...openRequests]) abandon();
  openRequests.clear();
}

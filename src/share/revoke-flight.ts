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

  constructor(key: string, run: (flight: RevokeFlight) => Promise<void>) {
    flights.set(key, this);
    this.done = run(this).then(
      (): FlightOutcome => ({ revoked: true }),
      (failure: unknown): FlightOutcome => ({ revoked: false, failure }),
    ).finally(() => { flights.delete(key); });
  }

  setApproval(open: boolean): void {
    this.approval = open;
    for (const repaint of [...this.subscribers]) repaint();
  }
}

/**
 * Runs `task` (the wallet request) only if no other approval is open. A second
 * share's revoke is refused with `revoke-another-approval` instead of queueing,
 * so the person is never asked to approve something they did not just click.
 */
export async function withWalletApproval<T>(flight: RevokeFlight, task: () => Promise<T>): Promise<T> {
  if (walletRequestOpen) throw new Error("revoke-another-approval");
  walletRequestOpen = true;
  flight.setApproval(true);
  try {
    return await task();
  } finally {
    walletRequestOpen = false;
    flight.setApproval(false);
  }
}

/** Test seam: forgets every flight, as a fresh page load would. */
export function resetRevokeFlights(): void {
  flights.clear();
  walletRequestOpen = false;
}

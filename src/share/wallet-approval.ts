/**
 * TC-1583. An OpenKey approval the page is waiting on.
 *
 * Creating a share and revoking one both stop on a wallet approval that opens
 * in OpenKey's own window. Nothing in the page said so, and a hidden or
 * blocked window looked like a hang. Every place that asks the wallet for a
 * signature reports it here (`trackWalletApproval`), and the screens that wait
 * on it (`subscribeWalletApproval`) show one hint while it is open.
 *
 * This only observes: it holds no key, signs nothing and changes no request.
 * The count is module-wide because an approval belongs to the page, not to a
 * screen that may be mounted again while it is open.
 */

type Listener = (open: boolean) => void;

let open = 0;
const listeners = new Set<Listener>();

function notify(): void {
  const isOpen = open > 0;
  for (const listener of [...listeners]) listener(isOpen);
}

export function walletApprovalOpen(): boolean {
  return open > 0;
}

/** Calls `listener` whenever an approval opens or the last one closes. Returns the unsubscribe. */
export function subscribeWalletApproval(listener: Listener): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

/** Runs `request` (a wallet signature) and reports it as open until it settles, either way. */
export async function trackWalletApproval<T>(request: () => Promise<T>): Promise<T> {
  open += 1;
  if (open === 1) notify();
  try {
    return await request();
  } finally {
    open -= 1;
    if (open === 0) notify();
  }
}

/** Test seam: forgets every open approval and listener, as a fresh page load would. */
export function resetWalletApproval(): void {
  open = 0;
  listeners.clear();
}

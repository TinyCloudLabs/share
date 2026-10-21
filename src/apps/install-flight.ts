/**
 * One install at a time per app, for the whole page session.
 *
 * The sheet can be closed and reopened while an OpenKey approval is open, and a
 * card and its detail sheet both have an Install button. A guard that lived in
 * the view would let a second click start a second sign-in. The flights live at
 * module level, keyed by app id: a second `startInstall` for an app that is
 * still running returns the same flight and starts nothing. A settled flight
 * stays (so reopening the sheet shows how it ended) until the person tries
 * again, which replaces it.
 */
import { type CatalogEntry, availabilityOf } from "./catalog.ts";
import { InstallError, type InstallOutcome, type InstallPorts, runInstall } from "./install.ts";

export type InstallState =
  | { phase: "checking" }
  | { phase: "signing-in" }
  | { phase: "approval" }
  | { phase: "installing"; done: number; total: number }
  | { phase: "registering" }
  | { phase: "installed"; outcome: InstallOutcome }
  | { phase: "failed"; error: InstallError };

export class InstallFlight {
  state: InstallState = { phase: "checking" };
  /** True once the person cancelled: the flight shows "cancelled" at once, and nothing it does afterwards is shown or written. */
  cancelled = false;
  /** The phase the install was in when it was cancelled, so the message can say whether files may already be saved. */
  cancelledIn: InstallState["phase"] | undefined;
  /** Views showing this flight repaint when its state changes. */
  readonly subscribers = new Set<() => void>();
  readonly done: Promise<InstallState>;

  constructor(readonly appId: string, run: (flight: InstallFlight) => Promise<InstallOutcome>) {
    this.done = run(this).then(
      (outcome): InstallState => ({ phase: "installed", outcome }),
      (error: unknown): InstallState => ({ phase: "failed", error: error instanceof InstallError ? error : new InstallError("failed", { cause: error }) }),
    ).then((state) => { this.set(state); return this.cancelled ? this.state : state; });
  }

  get active(): boolean {
    return this.state.phase !== "installed" && this.state.phase !== "failed";
  }

  set(state: InstallState): void {
    // After a cancel the underlying run may still report (an OpenKey window left open, a write in flight): it no longer changes what is shown.
    if (this.cancelled) return;
    this.state = state;
    for (const repaint of [...this.subscribers]) repaint();
  }

  /**
   * Cancels a running install. The panel says so at once. The run behind it is stopped at its next step: it opens no
   * OpenKey window if it had not yet, and if a window is already open and later approved, the session is closed
   * and nothing is written (see `guarded`).
   */
  cancel(): void {
    if (!this.active) return;
    this.cancelledIn = this.state.phase;
    this.cancelled = true;
    this.state = { phase: "failed", error: new InstallError("cancelled") };
    for (const repaint of [...this.subscribers]) repaint();
  }
}

/**
 * `ports` for one flight: once the flight is cancelled, nothing new starts (no OpenKey window), a session that
 * arrives late is closed, and no write is made. It wraps the ports; the sign-in, the scope and the writes themselves
 * are the real ones, unchanged.
 */
function guarded(ports: InstallPorts, flight: InstallFlight): InstallPorts {
  return {
    ...ports,
    openSession: async (manifest, hooks) => {
      if (flight.cancelled) throw new InstallError("cancelled");
      const session = await ports.openSession(manifest, hooks);
      if (flight.cancelled) {
        await Promise.resolve(session.dispose()).catch(() => undefined);
        throw new InstallError("cancelled");
      }
      return {
        put: async (key, bytes, contentType) => {
          if (flight.cancelled) throw new InstallError("cancelled");
          return session.put(key, bytes, contentType);
        },
        confirmListed: (installer) => session.confirmListed(installer),
        dispose: () => session.dispose(),
      };
    },
  };
}

const flights = new Map<string, InstallFlight>();

export function flightFor(appId: string): InstallFlight | undefined {
  return flights.get(appId);
}

/** Starts an install, or returns the one already running for this app (then `makePorts` is not called). */
export function startInstall(entry: CatalogEntry, makePorts: () => InstallPorts): InstallFlight {
  const current = flights.get(entry.app_id);
  if (current?.active === true) return current;
  const flight = new InstallFlight(entry.app_id, async (self) => {
    // The kill switch: a disabled entry never gets ports, a fetch or a sign-in (runInstall refuses it again).
    if (!availabilityOf(entry).available) throw new InstallError("disabled");
    return runInstall(entry, guarded(makePorts(), self), (progress) => self.set(progress));
  });
  flights.set(entry.app_id, flight);
  return flight;
}

/** Test seam: forgets every flight, as a fresh page load would. */
export function resetInstallFlights(): void {
  flights.clear();
}

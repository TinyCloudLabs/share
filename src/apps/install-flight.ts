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
import type { CatalogEntry } from "./catalog.ts";
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
  /** Views showing this flight repaint when its state changes. */
  readonly subscribers = new Set<() => void>();
  readonly done: Promise<InstallState>;

  constructor(readonly appId: string, run: (flight: InstallFlight) => Promise<InstallOutcome>) {
    this.done = run(this).then(
      (outcome): InstallState => ({ phase: "installed", outcome }),
      (error: unknown): InstallState => ({ phase: "failed", error: error instanceof InstallError ? error : new InstallError("failed", { cause: error }) }),
    ).then((state) => { this.set(state); return state; });
  }

  get active(): boolean {
    return this.state.phase !== "installed" && this.state.phase !== "failed";
  }

  set(state: InstallState): void {
    this.state = state;
    for (const repaint of [...this.subscribers]) repaint();
  }
}

const flights = new Map<string, InstallFlight>();

export function flightFor(appId: string): InstallFlight | undefined {
  return flights.get(appId);
}

/** Starts an install, or returns the one already running for this app (then `makePorts` is not called). */
export function startInstall(entry: CatalogEntry, makePorts: () => InstallPorts): InstallFlight {
  const current = flights.get(entry.app_id);
  if (current?.active === true) return current;
  const flight = new InstallFlight(entry.app_id, (self) => runInstall(entry, makePorts(), (progress) => self.set(progress)));
  flights.set(entry.app_id, flight);
  return flight;
}

/** Test seam: forgets every flight, as a fresh page load would. */
export function resetInstallFlights(): void {
  flights.clear();
}

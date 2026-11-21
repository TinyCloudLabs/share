/** A saved session from an earlier sign-in was ended on this device, so the sign-in wall shows from the start. Its own module, so the wall can tell it apart without loading the library. */
export class StaleSessionError extends Error {
  constructor() { super("stale-session"); }
}

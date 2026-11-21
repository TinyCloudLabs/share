/** The person did not approve the one-time setup. Reads as a sign-in that did not complete. Its own module, so the sign-in wall can tell it apart without loading the setup. */
export class NetworkSetupDeclinedError extends Error {
  readonly kind = "signIn" as const;
  constructor() { super("network-setup-declined"); }
}

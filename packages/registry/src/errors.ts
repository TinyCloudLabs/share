/**
 * Typed, fail-closed error hierarchy for the registry client.
 * No error here is ever swallowed into a fallback — callers must handle them.
 */

/** Base class so callers can `catch (e instanceof RegistryError)` for all registry failures. */
export class RegistryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/**
 * The bytes do not hash to the expected CID. Thrown when a gateway returns
 * wrong bytes for a CID (lying/compromised gateway) or when an upload
 * endpoint claims a CID that differs from the locally computed one.
 */
export class CidMismatchError extends RegistryError {
  readonly expectedCid: string;
  readonly actualCid: string | undefined;

  constructor(expectedCid: string, actualCid?: string) {
    super(
      `CID mismatch: expected ${expectedCid}` +
        (actualCid === undefined ? "" : `, got ${actualCid}`),
    );
    this.expectedCid = expectedCid;
    this.actualCid = actualCid;
  }
}

/** Blob exceeds the configured size cap (envelopes are 1-2 KB; the cap is headroom, not a target). */
export class BlobTooLargeError extends RegistryError {
  readonly byteLength: number;
  readonly maxBlobBytes: number;

  constructor(byteLength: number, maxBlobBytes: number) {
    super(`blob is ${byteLength} bytes, exceeds cap of ${maxBlobBytes} bytes`);
    this.byteLength = byteLength;
    this.maxBlobBytes = maxBlobBytes;
  }
}

/**
 * The registry answered with a non-2xx status, a malformed body, or an
 * unexpected content-type. `status` is the HTTP status (0 is never used).
 */
export class RegistryHttpError extends RegistryError {
  readonly status: number;
  readonly url: string;

  constructor(message: string, status: number, url: string) {
    super(`${message} (status ${status}, url ${url})`);
    this.status = status;
    this.url = url;
  }
}

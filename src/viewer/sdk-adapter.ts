import type { RecipientDidViewerAdapter } from "./recipient-did.js";
import { OPENKEY_ORIGIN } from "./config.js";

/** The same build value Vite injects into frame-src. */
export const RECIPIENT_DID_SDK_CONFIG = Object.freeze({
  openKeyOrigin: OPENKEY_ORIGIN,
});

/**
 * Integration point for the js-sdk lane. It deliberately stays undefined
 * until that lane supplies genuine atomic verification, OpenKey selection,
 * and holder-signed reads; the viewer then fails closed before identity I/O.
 */
export const RECIPIENT_DID_VIEWER_ADAPTER: RecipientDidViewerAdapter | undefined = undefined;

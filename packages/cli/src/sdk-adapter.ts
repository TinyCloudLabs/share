import type { RecipientDidSenderAdapter } from "./recipient-did.js";

/** Fixed integration point for the js-sdk lane; undefined is fail-closed. */
export const RECIPIENT_DID_SENDER_ADAPTER: RecipientDidSenderAdapter | undefined = undefined;

/** Kept beside the SDK binding so linking an adapter cannot omit routing policy. */
export const RECIPIENT_DID_ALLOWED_NODE_ORIGINS: readonly string[] = [
  "https://node.tinycloud.xyz",
];

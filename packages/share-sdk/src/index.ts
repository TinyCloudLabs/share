/** Public package barrel. Protocol implementation lives in the SDK source lane. */
export * from "../../sdk/src/index.js";
export { checkBearerDelegation, resourceUriCovers, requiredResourceUri, type CheckBearerDelegationOptions, type DelegationCheckResult } from "@tinycloud/share-envelope";
export type { ShareTransport } from "../../../src/email-share/transport.js";

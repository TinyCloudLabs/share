/**
 * Bearer delegation binding check — MOVED in stage 4 to
 * @tinycloud/share-envelope (src/bearer-delegation.ts) so the CLI's create
 * flow mints with the exact module the viewer verifies with (the resource
 * URI convention and READ_ABILITIES literally cannot drift). This shim keeps
 * the viewer-local import path; see the package module for the full
 * documentation of what the check does and — critically — what it does NOT
 * do (no cryptographic chain verification; that stays the node's job).
 */
export {
  checkBearerDelegation,
  requiredResourceUri,
  type DelegationCheckResult,
} from "@tinycloud/share-envelope";

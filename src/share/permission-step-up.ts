import type { PermissionEntry } from "@tinycloud/web-sdk";
import { takeWalletApprovalFailure, type ShareTinyCloud } from "./openkey-session.js";

/**
 * Asks OpenKey for access beyond what the library signed in with. Share signs in with the SDK's own windows turned off,
 * so the SDK's "requests additional access" question has no window to show. The person has already pressed the button
 * that leads here (or is being told what is happening in the status line), so that question is answered as approved and
 * OpenKey's own screen is where the approval is given. Resolves false when OpenKey does not grant it.
 */
export async function requestInOpenKey(
  tinycloud: Pick<ShareTinyCloud, "requestPermissions">,
  permissions: PermissionEntry[],
  options?: { readonly expiryMs?: number },
): Promise<boolean> {
  // The SDK reads its permission-window handler from this one field; the pinned version is in package.json.
  const previous = Reflect.get(tinycloud, "_testHooks");
  const hooks = typeof previous === "object" && previous !== null ? previous : {};
  if (!Reflect.set(tinycloud, "_testHooks", { ...hooks, showModal: async () => ({ approved: true }) })) {
    throw new Error("permission-request-unavailable");
  }
  try {
    return (await tinycloud.requestPermissions(permissions, options)).approved;
  } catch (error) {
    // OpenKey ends a cancelled approval by rejecting; that is the person saying no, not a failure.
    if (takeWalletApprovalFailure(tinycloud) === "cancelled") return false;
    throw error;
  }
}

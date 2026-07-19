import "../email-share/sender.css";
import { fromBase64Url } from "@tinycloud/share-envelope";
import { mountSender } from "../email-share/view.js";
import { createHttpTransport, type ShareTransport } from "../email-share/transport.js";
import type { ContentSource, SenderScope } from "../email-share/protocol.js";
import { type TrustedNode, validateSource } from "../email-share/protocol.js";
import { assertProductionAuthorityMaterial, assertProductionTrustedNode, PRODUCTION_ENDPOINTS } from "../email-share/runtime.js";
import { loadSharePublicConfig } from "../email-share/config.js";

interface ShareCapability {
  readonly scope: SenderScope;
  readonly source: ContentSource;
}

async function loadCapability(configOrigin: string): Promise<ShareCapability> {
  const response = await fetch(new URL("/api/share/capability", configOrigin), { credentials: "include", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer" });
  if (!response.ok) throw new Error(`share capability unavailable (${response.status})`);
  const value = await response.json() as Record<string, unknown>;
  if (Object.keys(value).length !== 2 || typeof value.scope !== "object" || value.scope === null || typeof value.source !== "object" || value.source === null) throw new TypeError("share capability shape is invalid");
  const scope = value.scope as SenderScope & { readonly senderPrivateKey?: unknown };
  if (!Array.isArray(scope.senderPrivateKey) || scope.senderPrivateKey.length !== 32 || scope.senderPrivateKey.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)) throw new TypeError("share capability signer is unavailable");
  const materialized = { ...scope, senderPrivateKey: new Uint8Array(scope.senderPrivateKey), trustedNode: { ...scope.trustedNode, invitationPublicKey: typeof scope.trustedNode.invitationPublicKey === "string" ? fromBase64Url(scope.trustedNode.invitationPublicKey) : scope.trustedNode.invitationPublicKey } } as SenderScope;
  assertProductionAuthorityMaterial(materialized);
  if (materialized.targetOrigin !== PRODUCTION_ENDPOINTS.nodeOrigin || materialized.nodeAudience !== PRODUCTION_ENDPOINTS.nodeAudience) throw new TypeError("share capability target is not enrolled");
  assertProductionTrustedNode(materialized.trustedNode as TrustedNode);
  const source = validateSource(value.source as ContentSource);
  return { scope: materialized, source };
}

const root = document.getElementById("share-app");
if (root === null) throw new Error("share app root missing");
void (async () => {
  try {
    const publicConfig = await loadSharePublicConfig();
    const capability = await loadCapability(publicConfig.shareOrigin);
    const transport = createHttpTransport({ nodeOrigin: publicConfig.nodeOrigin, credentialsOrigin: publicConfig.credentialsOrigin });
    const uploadEnvelope = async (cid: string, blob: Uint8Array): Promise<void> => {
      const response = await fetch("/registry/blobs", { method: "POST", credentials: "omit", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer", headers: { "content-type": "application/vnd.ipld.raw", "if-none-match": "*" }, body: blob.buffer as ArrayBuffer });
      if (!response.ok) throw new Error(`registry upload failed (${response.status})`);
      void cid;
    };
    mountSender(root, { transport, scope: capability.scope, defaultSource: capability.source, uploadEnvelope });
  } catch (error) {
    root.replaceChildren();
    const message = document.createElement("main");
    message.className = "sender-shell";
    message.setAttribute("role", "alert");
    message.textContent = "Exact-email sharing is unavailable until this origin provides a verified sender capability.";
    root.append(message);
    console.error("share bootstrap rejected", error instanceof Error ? error.message : "unknown");
  }
})();

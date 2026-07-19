import "../email-share/sender.css";
import { mountSender } from "../email-share/view.js";
import { createHttpTransport, type ShareTransport } from "../email-share/transport.js";
import type { ContentSource, SenderScope } from "../email-share/protocol.js";
import { type TrustedNode, validateSource } from "../email-share/protocol.js";
import { assertProductionAuthorityMaterial, assertProductionTrustedNode, PRODUCTION_ENDPOINTS } from "../email-share/runtime.js";

interface ShareBootstrap {
  readonly nodeOrigin?: string;
  readonly credentialsOrigin?: string;
  readonly scope: SenderScope;
  readonly source: ContentSource;
  readonly uploadEnvelope: (cid: string, blob: Uint8Array) => Promise<void>;
}

export function bootstrap(): ShareBootstrap | undefined {
  const value = (window as Window & { __TINY_CLOUD_SHARE_BOOTSTRAP__?: unknown }).__TINY_CLOUD_SHARE_BOOTSTRAP__;
  if (typeof value !== "object" || value === null) return undefined;
  const candidate = value as Partial<ShareBootstrap>;
  if (typeof candidate.uploadEnvelope !== "function" || typeof candidate.scope !== "object" || candidate.scope === null ||
      typeof candidate.source !== "object" || candidate.source === null) return undefined;
  try {
    const nodeOrigin = candidate.nodeOrigin ?? PRODUCTION_ENDPOINTS.nodeOrigin;
    const credentialsOrigin = candidate.credentialsOrigin ?? PRODUCTION_ENDPOINTS.credentialsOrigin;
    if (nodeOrigin !== PRODUCTION_ENDPOINTS.nodeOrigin || credentialsOrigin !== PRODUCTION_ENDPOINTS.credentialsOrigin) return undefined;
    const scope = candidate.scope as SenderScope;
    assertProductionAuthorityMaterial(scope);
    if (scope.targetOrigin !== nodeOrigin || scope.nodeAudience !== PRODUCTION_ENDPOINTS.nodeAudience || scope.authorityMaterial === undefined || typeof scope.authorityMaterial !== "object" || scope.authorityMaterial === null) return undefined;
    const trusted = scope.trustedNode as TrustedNode;
    assertProductionTrustedNode(trusted);
    validateSource(candidate.source as ContentSource);
  } catch (error) { console.error("share bootstrap rejected", error); return undefined; }
  return candidate as ShareBootstrap;
}

const root = document.getElementById("share-app");
if (root === null) throw new Error("share app root missing");
const config = bootstrap();
if (config === undefined) {
  root.replaceChildren();
  const message = document.createElement("main");
  message.className = "sender-shell";
  message.setAttribute("role", "status");
  message.textContent = "Exact-email sharing is unavailable until the host supplies a verified capability.";
  root.append(message);
} else {
  let transport: ShareTransport;
  try { transport = createHttpTransport({ nodeOrigin: config.nodeOrigin ?? PRODUCTION_ENDPOINTS.nodeOrigin, credentialsOrigin: config.credentialsOrigin ?? PRODUCTION_ENDPOINTS.credentialsOrigin }); }
  catch { root.textContent = "Exact-email sharing is unavailable for this origin."; throw new Error("invalid-share-bootstrap-origin"); }
  mountSender(root, { transport, scope: config.scope, defaultSource: config.source, uploadEnvelope: config.uploadEnvelope });
}

import "../email-share/sender.css";
import { fromBase64Url, toBase64Url } from "@tinycloud/share-envelope";
import { mountSender } from "../email-share/view.js";
import { createHttpTransport, type ShareTransport } from "../email-share/transport.js";
import type { ContentSource, SenderScope } from "../email-share/protocol.js";
import { type TrustedNode, validateSource } from "../email-share/protocol.js";
import { assertProductionAuthorityMaterial, assertProductionTrustedNode } from "../email-share/runtime.js";
import { loadSharePublicConfig } from "../email-share/config.js";

interface ShareCapability {
  readonly scope: SenderScope;
  readonly source: ContentSource;
}

class AuthenticationRequired extends Error {}

function capabilityPublicKey(value: unknown): Uint8Array {
  if (typeof value === "string") return fromBase64Url(value);
  if (!Array.isArray(value) || value.length !== 32 || value.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)) throw new TypeError("share capability public key is invalid");
  return new Uint8Array(value);
}

async function loadCapability(configOrigin: string): Promise<ShareCapability> {
  // Keep the request same-origin with the actual host. The trust-derived
  // Share origin remains in the signed scope; this also preserves the browser
  // origin boundary for hermetic loopback transport.
  const capabilityUrl = new URL("/api/share/capability", window.location.origin);
  const selected = new URL(window.location.href).searchParams.get("capabilityId"); if (selected !== null) capabilityUrl.searchParams.set("capabilityId", selected);
  const response = await fetch(capabilityUrl, { credentials: "include", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer" });
  if (response.status === 401) throw new AuthenticationRequired("authentication required");
  if (!response.ok) throw new Error(`share capability unavailable (${response.status})`);
  const value = await response.json() as Record<string, unknown>;
  if (Object.keys(value).length !== 2 || typeof value.scope !== "object" || value.scope === null || typeof value.source !== "object" || value.source === null) throw new TypeError("share capability shape is invalid");
  const scope = value.scope as SenderScope & { readonly signingCapability?: { readonly capabilityId?: unknown; readonly publicKey?: unknown } };
  if (scope.signingCapability === undefined || typeof scope.signingCapability.capabilityId !== "string" || !/^[A-Za-z0-9_-]{22,128}$/.test(scope.signingCapability.capabilityId) || scope.signingCapability.publicKey === undefined) throw new TypeError("share capability signer is unavailable");
  const materialized = { ...scope, signingCapability: { capabilityId: scope.signingCapability.capabilityId, publicKey: capabilityPublicKey(scope.signingCapability.publicKey) }, trustedNode: { ...scope.trustedNode, invitationPublicKey: capabilityPublicKey(scope.trustedNode?.invitationPublicKey) } } as SenderScope;
  assertProductionAuthorityMaterial(materialized);
  assertProductionTrustedNode(materialized.trustedNode as TrustedNode);
  const signer = {
    publicKey: materialized.signingCapability.publicKey,
    sign: async (input: { readonly purpose: "envelope" | "inviteAuthorization"; readonly message: string; readonly binding: Record<string, unknown> }): Promise<Uint8Array> => {
      const response = await fetch("/api/share/sign", { method: "POST", credentials: "include", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer", headers: { accept: "application/json", "content-type": "application/json", "idempotency-key": toBase64Url(crypto.getRandomValues(new Uint8Array(16))) }, body: JSON.stringify({ capabilityId: materialized.signingCapability.capabilityId, ...input }) });
      if (!response.ok) throw new Error("sender signing capability unavailable");
      const body = await response.json() as Record<string, unknown>;
      if (typeof body.signature !== "string") throw new Error("sender signing response invalid");
      return fromBase64Url(body.signature);
    },
  };
  const source = validateSource(value.source as ContentSource);
  return { scope: { ...materialized, signer, shareOrigin: configOrigin }, source };
}

function mountAuthentication(root: HTMLElement, retry: () => Promise<void>): void {
  root.replaceChildren();
  const form = document.createElement("form"); form.className = "sender-form";
  const title = document.createElement("h1"); title.textContent = "Sign in to share";
  const copy = document.createElement("p"); copy.textContent = "Use your authenticated TinyCloud sender account. Signing keys remain on the Share host.";
  const username = document.createElement("input"); username.name = "username"; username.autocomplete = "username"; username.required = true; username.placeholder = "Username"; username.className = "field-input";
  const password = document.createElement("input"); password.type = "password"; password.name = "password"; password.autocomplete = "current-password"; password.required = true; password.placeholder = "Password"; password.className = "field-input";
  const submit = document.createElement("button"); submit.type = "submit"; submit.className = "button button-primary"; submit.textContent = "Sign in";
  const status = document.createElement("p"); status.setAttribute("role", "status");
  form.append(title, copy, username, password, submit, status); root.append(form);
  form.addEventListener("submit", (event) => {
    event.preventDefault(); submit.disabled = true; status.textContent = "Signing in…";
    void fetch("/api/share/auth/login", { method: "POST", credentials: "include", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer", headers: { "content-type": "application/json", accept: "application/json" }, body: JSON.stringify({ username: username.value, password: password.value }) })
      .then((response) => { if (!response.ok) throw new Error("sign-in failed"); return retry(); })
      .catch(() => { status.textContent = "Sign-in failed. Check your credentials and try again."; submit.disabled = false; });
  });
}

const root = document.getElementById("share-app");
if (root === null) throw new Error("share app root missing");
async function bootstrap(): Promise<void> {
  const publicConfig = await loadSharePublicConfig();
  const capability = await loadCapability(publicConfig.shareOrigin);
    const transport = createHttpTransport({ nodeOrigin: window.location.origin, credentialsOrigin: window.location.origin, allowLoopbackTransport: true });
    const uploadEnvelope = async (cid: string, blob: Uint8Array, deleteAfter: string): Promise<void> => {
      const response = await fetch("/registry/blobs", { method: "POST", credentials: "omit", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer", headers: { "content-type": "application/vnd.ipld.raw", "if-none-match": "*", "x-delete-after": deleteAfter }, body: blob.buffer as ArrayBuffer });
      if (!response.ok) throw new Error(`registry upload failed (${response.status})`);
      void cid;
    };
    const publishBinding = async (binding: Record<string, unknown>): Promise<void> => {
      const response = await fetch("/api/share/bindings", { method: "POST", credentials: "include", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer", headers: { accept: "application/json", "content-type": "application/json" }, body: JSON.stringify({ shareCid: binding.shareCid, capabilityId: capability.scope.signingCapability.capabilityId, binding }) });
      if (!response.ok) throw new Error("public share binding unavailable");
    };
    mountSender(root as HTMLElement, { transport, scope: capability.scope, defaultSource: capability.source, uploadEnvelope, publishBinding });
}

void (async () => {
  try { await bootstrap(); }
  catch (error) {
    if (error instanceof AuthenticationRequired) { mountAuthentication(root, bootstrap); return; }
    root.replaceChildren(); const message = document.createElement("main"); message.className = "sender-shell"; message.setAttribute("role", "alert"); message.textContent = "Exact-email sharing is unavailable until this origin provides a verified sender capability."; root.append(message);
    console.error("share bootstrap rejected", error instanceof Error ? error.message : "unknown");
  }
})();

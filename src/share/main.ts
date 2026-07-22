import "../email-share/sender.css";
import { canonicalize, fromBase64Url, toBase64Url } from "@tinycloud/share-envelope";
import { mountSender } from "../email-share/view.js";
import type { SenderPolicy } from "../email-share/sender.js";
import { createHttpTransport, type ShareTransport } from "../email-share/transport.js";
import type { ContentSource, SenderScope } from "../email-share/protocol.js";
import { type TrustedNode, validateSource } from "../email-share/protocol.js";
import { assertProductionAuthorityMaterial, assertProductionTrustedNode } from "../email-share/runtime.js";
import { loadSharePublicConfig } from "../email-share/config.js";
import {
  authenticateWithOpenKey,
  createTinyCloudUploader,
  type OpenKeyShareSession,
} from "./openkey-session.js";

interface ShareCapability {
  readonly scope: SenderScope;
  readonly source: ContentSource;
  readonly policy: SenderPolicy;
}

function capabilityPublicKey(value: unknown): Uint8Array {
  if (typeof value === "string") return fromBase64Url(value);
  if (!Array.isArray(value) || value.length !== 32 || value.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)) throw new TypeError("share capability public key is invalid");
  return new Uint8Array(value);
}

function recordValue(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError(`${label} is invalid`);
  return value as Record<string, unknown>;
}

function stringValue(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== "string" || value.length === 0) throw new TypeError(`share policy ${key} is invalid`);
  return value;
}

function parsePolicySource(value: unknown): ContentSource {
  const source = recordValue(value, "share policy source");
  const kind = stringValue(source, "kind");
  const action = stringValue(source, "action");
  if (kind === "kv" && action === "tinycloud.kv/get") {
    return validateSource({ kind, action, space: stringValue(source, "space"), path: stringValue(source, "path") });
  }
  if (kind === "sql" && action === "tinycloud.sql/read") {
    const rawArguments = recordValue(source.arguments, "share policy SQL arguments");
    const args: Record<string, number> = {};
    for (const [key, argument] of Object.entries(rawArguments)) {
      if (typeof argument !== "number" || !Number.isFinite(argument)) throw new TypeError("share policy SQL arguments are invalid");
      args[key] = argument;
    }
    return validateSource({
      kind,
      action,
      space: stringValue(source, "space"),
      database: stringValue(source, "database"),
      path: stringValue(source, "path"),
      statement: stringValue(source, "statement"),
      arguments: args,
      argumentsDigest: stringValue(source, "argumentsDigest"),
    });
  }
  throw new TypeError("share policy source is invalid");
}

function parseSenderPolicy(value: unknown): SenderPolicy {
  const policy = recordValue(value, "share policy");
  const target = recordValue(policy.target, "share policy target");
  const action = stringValue(policy, "action");
  if (action !== "tinycloud.kv/get" && action !== "tinycloud.sql/read") throw new TypeError("share policy action is invalid");
  return {
    recipientEmail: stringValue(policy, "recipientEmail"),
    source: parsePolicySource(policy.source),
    action,
    resource: stringValue(policy, "resource"),
    expiresAt: stringValue(policy, "expiresAt"),
    target: { origin: stringValue(target, "origin"), nodeAudience: stringValue(target, "nodeAudience"), spaceId: stringValue(target, "spaceId") },
    policyCid: stringValue(policy, "policyCid"),
    policyDigest: stringValue(policy, "policyDigest"),
    contentSourceDigest: stringValue(policy, "contentSourceDigest"),
    delegationCid: stringValue(policy, "delegationCid"),
    authorityMaterialDigest: stringValue(policy, "authorityMaterialDigest"),
    policyBytes: stringValue(policy, "policyBytes"),
    policyAuthorityCid: stringValue(policy, "policyAuthorityCid"),
    policyAuthorityBytes: stringValue(policy, "policyAuthorityBytes"),
    policyEnforcementCid: stringValue(policy, "policyEnforcementCid"),
    policyEnforcementBytes: stringValue(policy, "policyEnforcementBytes"),
  };
}

async function loadCapabilities(configOrigin: string): Promise<readonly ShareCapability[]> {
  // Keep the request same-origin with the actual host. The trust-derived
  // Share origin remains in the signed scope; this also preserves the browser
  // origin boundary for hermetic loopback transport.
  const capabilityUrl = new URL("/api/share/capabilities", window.location.origin);
  const response = await fetch(capabilityUrl, { credentials: "include", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer" });
  if (response.status === 401) throw new Error("OpenKey authentication required");
  if (!response.ok) throw new Error(`share capability unavailable (${response.status})`);
  const value = await response.json() as Record<string, unknown>;
  if (Object.keys(value).length !== 1 || !Array.isArray(value.capabilities) || value.capabilities.length === 0) throw new TypeError("share capability list is invalid");
  return value.capabilities.map((entry) => {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) throw new TypeError("share capability shape is invalid");
    const item = entry as Record<string, unknown>;
    if (typeof item.scope !== "object" || item.scope === null || typeof item.source !== "object" || item.source === null || typeof item.policy !== "object" || item.policy === null || Array.isArray(item.policy)) throw new TypeError("share capability shape is invalid");
    const scope = item.scope as SenderScope & { readonly signingCapability?: { readonly capabilityId?: unknown; readonly publicKey?: unknown } };
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
    const source = validateSource(item.source as ContentSource);
    const policy = parseSenderPolicy(item.policy);
    const capabilityRecipient = (materialized as SenderScope & { readonly recipientEmail?: unknown }).recipientEmail;
    if (canonicalize(policy.source) !== canonicalize(source) || policy.action !== source.action || policy.resource !== source.path || policy.target.origin !== materialized.targetOrigin || policy.target.nodeAudience !== materialized.nodeAudience || policy.target.spaceId !== materialized.spaceId || policy.delegationCid !== materialized.delegationCid || policy.authorityMaterialDigest !== materialized.authorityMaterialDigest || (capabilityRecipient !== undefined && policy.recipientEmail !== capabilityRecipient)) throw new TypeError("share policy is not bound to the selected capability");
    return { scope: { ...materialized, signer, shareOrigin: configOrigin }, source, policy };
  });
}

function lockSourceSelection(root: HTMLElement, capabilities: readonly ShareCapability[]): void {
  const form = root.querySelector<HTMLFormElement>(".sender-form");
  const capability = form?.querySelector<HTMLSelectElement>('select[name="capability"]');
  const sourceKind = form?.querySelector<HTMLSelectElement>('select[name="source-kind"]');
  if (form === null || form === undefined || capability === null || capability === undefined || sourceKind === null || sourceKind === undefined) return;
  const hiddenKind = document.createElement("input");
  hiddenKind.type = "hidden";
  hiddenKind.name = "source-kind";
  form.append(hiddenKind);
  const enforce = (): void => {
    const candidate = capabilities[Number(capability.value)];
    if (candidate === undefined) return;
    hiddenKind.value = candidate.source.kind;
    sourceKind.value = candidate.source.kind;
    sourceKind.disabled = true;
    sourceKind.setAttribute("aria-disabled", "true");
  };
  capability.addEventListener("change", enforce);
  sourceKind.addEventListener("change", enforce, { capture: true });
  enforce();
}

function mountAuthentication(root: HTMLElement, proceed: (session: OpenKeyShareSession, status: HTMLElement) => Promise<void>): void {
  root.replaceChildren();
  const shell = document.createElement("main"); shell.className = "sender-shell auth-shell";
  const header = document.createElement("header"); header.className = "sender-header auth-header";
  const kicker = document.createElement("p"); kicker.className = "sender-kicker"; kicker.textContent = "TinyCloud sharing";
  const title = document.createElement("h1"); title.className = "sender-title"; title.textContent = "Create a share.";
  const lede = document.createElement("p"); lede.className = "sender-lede"; lede.textContent = "Sign in with OpenKey, upload one document, then choose exactly who can access it.";
  header.append(kicker, title, lede);
  const form = document.createElement("form"); form.className = "sender-form auth-form";
  const steps = document.createElement("ol"); steps.className = "share-progress";
  const progressSteps: ReadonlyArray<readonly [string, string]> = [["01", "Sign in"], ["02", "Upload"], ["03", "Share"]];
  for (const [number, label] of progressSteps) {
    const item = document.createElement("li");
    const marker = document.createElement("span");
    marker.textContent = number;
    item.append(marker, document.createTextNode(label));
    steps.append(item);
  }
  const badge = document.createElement("div"); badge.className = "openkey-mark"; badge.setAttribute("aria-hidden", "true"); badge.textContent = "OK";
  const heading = document.createElement("h2"); heading.textContent = "Your key opens your space";
  const copy = document.createElement("p"); copy.className = "auth-copy"; copy.textContent = "OpenKey uses your passkey to authenticate. TinyCloud receives a proof, never your private key.";
  const submit = document.createElement("button"); submit.type = "submit"; submit.className = "button button-primary auth-button"; submit.textContent = "Continue with OpenKey";
  const status = document.createElement("p"); status.className = "auth-status"; status.setAttribute("role", "status"); status.setAttribute("aria-live", "polite");
  form.append(steps, badge, heading, copy, submit, status); shell.append(header, form); root.append(shell);
  form.addEventListener("submit", (event) => {
    event.preventDefault(); submit.disabled = true; status.textContent = "Signing in…";
    void authenticateWithOpenKey((message) => { status.textContent = message; })
      .then((session) => proceed(session, status))
      .catch((error) => { status.textContent = error instanceof Error ? error.message : "OpenKey sign-in could not be completed."; submit.disabled = false; });
  });
}

const root = document.getElementById("share-app");
if (root === null) throw new Error("share app root missing");
async function bootstrap(session: OpenKeyShareSession, status: HTMLElement): Promise<void> {
  const publicConfig = await loadSharePublicConfig();
  const capabilities = await loadCapabilities(publicConfig.shareOrigin);
  const uploadContent = await createTinyCloudUploader(session, publicConfig, capabilities, (message) => { status.textContent = message; });
  const transport = createHttpTransport({ nodeOrigin: window.location.origin, credentialsOrigin: window.location.origin });
  const uploadEnvelope = async (cid: string, blob: Uint8Array, deleteAfter: string): Promise<void> => {
    const response = await fetch("/registry/blobs", { method: "POST", credentials: "omit", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer", headers: { "content-type": "application/vnd.ipld.raw", "if-none-match": "*", "x-delete-after": deleteAfter }, body: blob.buffer as ArrayBuffer });
    if (!response.ok) throw new Error(`registry upload failed (${response.status})`);
    void cid;
  };
  const publishBinding = async (binding: Record<string, unknown>): Promise<void> => {
    const response = await fetch("/api/share/bindings", { method: "POST", credentials: "include", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer", headers: { accept: "application/json", "content-type": "application/json" }, body: JSON.stringify({ shareCid: binding.shareCid, capabilityId: binding.capabilityId, binding }) });
    if (!response.ok) throw new Error("public share binding unavailable");
  };
  mountSender(root as HTMLElement, { transport, capabilities, uploadEnvelope, uploadContent, publishBinding, openKeyAddress: session.address });
  lockSourceSelection(root as HTMLElement, capabilities);
}

mountAuthentication(root, bootstrap);

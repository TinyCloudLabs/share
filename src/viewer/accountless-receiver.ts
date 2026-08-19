/**
 * The accountless receiver: the entry point a recipient of an addressed share
 * actually lands on when the deployment has a Policy Engine enrolled.
 *
 * `runCredentialReceiver` — the other receiver in this directory — needs an
 * active TinyCloud/OpenKey session before it can do anything: it calls
 * `connect()`, requires `client.session()`, and stores the credential durably
 * in the recipient's own space. That is the right flow for someone who already
 * has an account. It is the wrong flow for someone who has only received an
 * email, and it is why the receiver leg used to be brokered through
 * Share-specific TinyCloud Node routes.
 *
 * This receiver makes **zero** identity-provider calls before the document is
 * on screen. The only key involved is minted here, lives in this tab, and is
 * never persisted:
 *
 *   ephemeral key → OpenCredentials email/OTP → Policy Engine → /delegate →
 *   /invoke → local decrypt
 *
 * Every hop is `@tinycloud/sdk-core/policy-access`. This module supplies
 * Share's trusted configuration, the recipient-facing vocabulary, and nothing
 * else — no protocol, no signing, no route.
 */
import { fromBase64Url, open, type ShareEnvelopeV3 } from "@tinycloud/share-envelope";
import type { InvokeFunction } from "@tinycloud/sdk-services";
import {
  PolicyAccessError,
  beginEmailCredentialAcquisition,
  createFetchPolicyAccessTransport,
  type EmailCredentialAcquisition,
  type EphemeralHolderKey,
  type PolicyAccessTransport,
} from "@tinycloud/sdk-core/policy-access";
import { EMAIL_CREDENTIAL_DESCRIPTOR, emailCredentialRequirement } from "../credentials/email.js";
import type { SharePublicConfig } from "../email-share/config.js";
import {
  createReceiverHolder,
  policyEngineBindingFromConfig,
  readAccountlessShare,
  receiverOriginPolicy,
} from "../email-share/policy-access.js";

export type AccountlessReceiverState =
  | "requesting-code"
  | "awaiting-code"
  | "verifying"
  | "authorizing-access"
  | "opening-content";

export interface AccountlessReceiverContent {
  readonly type: "TinyCloudAccountlessShareContent";
  readonly version: 1;
  readonly bytes: Uint8Array;
  readonly mediaType: string;
}

export interface AccountlessReceiverInput {
  readonly envelope: ShareEnvelopeV3;
  readonly shareCid: string;
  readonly config: SharePublicConfig;
  /** Envelope key captured from the link fragment before the URL is scrubbed. */
  readonly envelopeKey: Uint8Array;
  readonly invoke: InvokeFunction;
  readonly openerOrigin: string;
  readonly transport?: PolicyAccessTransport;
  readonly holder?: EphemeralHolderKey;
  readonly onState?: (state: AccountlessReceiverState) => void;
}

export interface AccountlessReceiverSession {
  readonly holder: EphemeralHolderKey;
  /** The address the sender addressed this share to; shown, never collected. */
  readonly recipientEmail: string;
  /** Deliver a one-time code to that address. */
  requestCode(): Promise<void>;
  /** Exchange the code for a credential, then read and decrypt. */
  submitCode(otp: string): Promise<AccountlessReceiverContent>;
}

export class AccountlessReceiverError extends Error {
  readonly name = "AccountlessReceiverError";
  constructor(
    readonly code: "UNSUPPORTED_SHARE" | "ENGINE_NOT_ENROLLED" | "CODE_REJECTED" | "ACCESS_DENIED" | "READ_FAILED",
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

/**
 * The share must name an engine, one exact resource, and one exact recipient.
 * Anything else is a share this receiver has no correct behaviour for, and
 * guessing would mean presenting against a policy the owner did not sign.
 */
function accountlessTargetFromEnvelope(envelope: ShareEnvelopeV3) {
  const binding = envelope.policyEngine;
  if (binding === undefined) {
    throw new AccountlessReceiverError(
      "ENGINE_NOT_ENROLLED",
      "the signed envelope names no Policy Engine",
    );
  }
  if (
    envelope.recipientMatcher.kind !== "exactEmail" ||
    envelope.resource.kind !== "exact" ||
    envelope.actions.length !== 1 ||
    envelope.actions[0] !== "read" ||
    envelope.contentSource.selector !== "exact" ||
    envelope.contentSource.kvResource !== `${envelope.target.spaceId}/kv/${envelope.resource.path}`
    || envelope.localContent === undefined
  ) {
    throw new AccountlessReceiverError(
      "UNSUPPORTED_SHARE",
      "the accountless receiver only opens a single exact read addressed to one recipient",
    );
  }
  return { binding, recipientEmail: envelope.recipientMatcher.value };
}

/**
 * The engine the recipient presents to must be the one the *owner signed into
 * the envelope*, and it must also be one this deployment trusts. Requiring both
 * means neither the invitation bytes nor the host serving the page can redirect
 * the presentation on its own.
 */
function assertEngineIsTrusted(
  envelopeBinding: NonNullable<ShareEnvelopeV3["policyEngine"]>,
  config: SharePublicConfig,
): void {
  const configured = policyEngineBindingFromConfig(config);
  if (configured === undefined) {
    throw new AccountlessReceiverError(
      "ENGINE_NOT_ENROLLED",
      "this deployment has no Policy Engine enrolled",
    );
  }
  if (
    configured.endpoint !== envelopeBinding.endpoint ||
    configured.audience !== envelopeBinding.audience ||
    configured.grantIssuerDid !== envelopeBinding.grantIssuerDid
  ) {
    throw new AccountlessReceiverError(
      "ENGINE_NOT_ENROLLED",
      "the share names a Policy Engine this deployment does not trust",
    );
  }
}

function accessError(cause: unknown): AccountlessReceiverError {
  if (cause instanceof AccountlessReceiverError) return cause;
  const code = cause instanceof PolicyAccessError ? cause.code : undefined;
  if (code === "engine-denied" || code === "credential-denied") {
    return new AccountlessReceiverError("ACCESS_DENIED", "the credential did not authorize this share", { cause });
  }
  return new AccountlessReceiverError("READ_FAILED", "the share could not be opened", { cause });
}

export function openAccountlessShare(
  input: AccountlessReceiverInput,
): AccountlessReceiverSession {
  const { binding, recipientEmail } = accountlessTargetFromEnvelope(input.envelope);
  assertEngineIsTrusted(binding, input.config);

  // One key per tab. Nothing persists it, so closing the tab ends access even
  // before the short-lived grant expires.
  const holder = input.holder ?? createReceiverHolder();
  const transport =
    input.transport ??
    createFetchPolicyAccessTransport({
      originPolicy: receiverOriginPolicy(input.config, {
        endpoint: binding.endpoint,
        audience: binding.audience,
        grantIssuerDid: binding.grantIssuerDid,
      }),
    });
  let acquisition: EmailCredentialAcquisition | undefined;

  return {
    holder,
    recipientEmail,
    async requestCode() {
      input.onState?.("requesting-code");
      try {
        acquisition = await beginEmailCredentialAcquisition({
          issuerOrigin: input.config.credentialsOrigin,
          transport,
          holder,
          // The address comes from the envelope the owner signed, never from a
          // form: this receiver proves control of a mailbox the sender chose.
          email: recipientEmail,
          requirement: emailCredentialRequirement(recipientEmail),
          descriptor: EMAIL_CREDENTIAL_DESCRIPTOR,
          audience: "tinycloud://credentials",
          openerOrigin: input.openerOrigin,
          completionOrigin: input.openerOrigin,
          completionContext: `tinycloud-share:${input.shareCid}`,
        });
        await acquisition.requestOtp();
      } catch (cause) {
        throw accessError(cause);
      }
      input.onState?.("awaiting-code");
    },
    async submitCode(otp: string) {
      if (acquisition === undefined) {
        throw new AccountlessReceiverError("READ_FAILED", "requestCode() has not run");
      }
      input.onState?.("verifying");
      let credential;
      try {
        credential = await acquisition.submitOtp(otp);
      } catch (cause) {
        throw new AccountlessReceiverError("CODE_REJECTED", "that code was not accepted", { cause });
      }
      if (credential.subject !== holder.did) {
        throw new AccountlessReceiverError(
          "ACCESS_DENIED",
          "the issued credential is not bound to this tab's key",
        );
      }

      input.onState?.("authorizing-access");
      try {
        const contentKey = await open(
          fromBase64Url(input.envelope.localContent!.wrappedKey),
          input.envelopeKey,
        );
        if (contentKey.byteLength !== 32) {
          throw new AccountlessReceiverError("READ_FAILED", "the wrapped content key is invalid");
        }
        try {
          const { plaintext } = await readAccountlessShare({
            config: input.config,
            binding: {
              endpoint: binding.endpoint,
              audience: binding.audience,
              grantIssuerDid: binding.grantIssuerDid,
            },
            policyId: binding.policyId,
            capabilitySpace: input.envelope.target.spaceId,
            nodeSpaceId: input.envelope.target.spaceId,
            resourcePath: input.envelope.resource.path,
            requirementId: binding.requirementId,
            credential: credential.credential,
            contentKey,
            expectedCiphertextDigest: input.envelope.localContent!.ciphertextDigest,
            holder,
            invoke: input.invoke,
            transport,
          });
          input.onState?.("opening-content");
          return Object.freeze({
            type: "TinyCloudAccountlessShareContent" as const,
            version: 1 as const,
            bytes: plaintext,
            mediaType: input.envelope.metadata.mediaType ?? "application/octet-stream",
          });
        } finally {
          contentKey.fill(0);
        }
      } catch (cause) {
        throw accessError(cause);
      }
    },
  };
}

const STATE_COPY: Record<AccountlessReceiverState, string> = {
  "requesting-code": "Sending a one-time code to your email…",
  "awaiting-code": "Enter the code we just emailed you.",
  verifying: "Checking your code…",
  "authorizing-access": "Email confirmed. Authorizing this share…",
  "opening-content": "Access granted. Opening the share…",
};

function element<K extends keyof HTMLElementTagNameMap>(
  doc: Document,
  tag: K,
  className: string,
  value?: string,
): HTMLElementTagNameMap[K] {
  const node = doc.createElement(tag);
  node.className = className;
  if (value !== undefined) node.textContent = value;
  return node;
}

/**
 * The recipient-facing surface: confirm the address, enter a code, read the
 * document. There is no sign-in button, because there is no sign-in.
 */
export function mountAccountlessReceiver(
  root: HTMLElement,
  input: AccountlessReceiverInput & {
    readonly onComplete: (content: AccountlessReceiverContent) => Promise<void> | void;
  },
): void {
  const doc = root.ownerDocument;
  let session: AccountlessReceiverSession;
  try {
    session = openAccountlessShare(input);
  } catch (error) {
    const main = element(doc, "main", "viewer-state viewer-claim");
    main.append(
      element(doc, "h1", "viewer-state-title", "This link can't be opened here"),
      element(doc, "p", "viewer-state-detail", "Ask the sender for a fresh invitation."),
    );
    root.replaceChildren(main);
    console.debug("tinycloud share: accountless receiver refused the share", error);
    return;
  }

  const main = element(doc, "main", "viewer-state viewer-claim");
  const status = element(doc, "p", "viewer-state-detail", "No account needed — just confirm the email this was sent to.");
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  const send = element(doc, "button", "viewer-primary-action", "Email me a code") as HTMLButtonElement;
  send.type = "button";
  const form = element(doc, "form", "viewer-otp-form");
  form.hidden = true;
  const otp = element(doc, "input", "viewer-otp-input") as HTMLInputElement;
  otp.name = "otp";
  otp.type = "text";
  otp.inputMode = "numeric";
  otp.autocomplete = "one-time-code";
  otp.setAttribute("aria-label", "One-time code");
  const submit = element(doc, "button", "viewer-primary-action", "Open") as HTMLButtonElement;
  submit.type = "submit";
  form.append(otp, submit);
  main.append(
    element(doc, "h1", "viewer-state-title", "Confirm your email to open this"),
    element(doc, "p", "viewer-state-detail", `This share was sent to ${session.recipientEmail}.`),
    status,
    send,
    form,
  );
  root.replaceChildren(main);
  root.setAttribute("tabindex", "-1");
  root.focus();

  const fail = (error: unknown): void => {
    console.debug("tinycloud share: accountless receiver failed", error);
    status.setAttribute("role", "alert");
    status.setAttribute("aria-live", "assertive");
    status.textContent =
      error instanceof AccountlessReceiverError && error.code === "CODE_REJECTED"
        ? "That code didn't match. Check the email and try again."
        : error instanceof AccountlessReceiverError && error.code === "ACCESS_DENIED"
          ? "Your email is confirmed, but it doesn't open this share. Ask the sender for a new link."
          : "We couldn't open this share. Try again or ask the sender for a new link.";
  };

  send.addEventListener("click", () => {
    send.disabled = true;
    status.textContent = STATE_COPY["requesting-code"];
    void session
      .requestCode()
      .then(() => {
        send.hidden = true;
        form.hidden = false;
        status.textContent = STATE_COPY["awaiting-code"];
        otp.focus();
      })
      .catch((error: unknown) => {
        send.disabled = false;
        fail(error);
      });
  });

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    submit.disabled = true;
    status.textContent = STATE_COPY.verifying;
    void session
      .submitCode(otp.value.trim())
      .then(input.onComplete)
      .catch((error: unknown) => {
        submit.disabled = false;
        fail(error);
      });
  });
}

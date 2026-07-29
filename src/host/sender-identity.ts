import { closeSync, fstatSync, fsyncSync, openSync, readFileSync, writeSync } from "node:fs";
import { resolve } from "node:path";
import { hkdfSync, randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { assertCanonicalPath, assertInsideRoot, assertSecurePath, SECURE_CREATE, SECURE_READ } from "./secure-path.js";
import { didKeyFromEd25519PublicKey } from "./trust-bundle.js";

function fromBase64Url(value: string): Uint8Array { return new Uint8Array(Buffer.from(value, "base64url")); }
function toBase64Url(value: Uint8Array): string { return Buffer.from(value).toString("base64url"); }

const B64_256 = /^[A-Za-z0-9_-]{43}$/;
/** Domain-separated derivation for per-principal sender signing keys. */
const DERIVATION_SALT = "xyz.tinycloud.share/sender-identity/v1";
/**
 * Session principals are wallet DIDs or configured `SHARE_AUTH_USERS_JSON`
 * user ids, which are arbitrary operator-chosen strings. The derivation only
 * needs exact-byte distinctness, so the rule is bounded length and no control
 * characters — narrower than that would authenticate a legacy user and then
 * refuse to derive its sender identity.
 */
export function derivablePrincipal(value: string): boolean {
  if (typeof value !== "string" || value.length === 0 || value.length > 256) return false;
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f) return false;
    // TextEncoder maps every unpaired surrogate to the same U+FFFD bytes, so
    // without this two distinct authenticated principals would derive one
    // private key and one senderDid. The encoding must be injective.
    if (code >= 0xd800 && code <= 0xdfff) return false;
  }
  return true;
}
/** Bounds the derived-identity cache so unlimited sign-ins cannot grow the process. */
const IDENTITY_CACHE_LIMIT = 4096;
const DERIVATION_INFO = "xyz.tinycloud.share/sender-identity/principal/v1\0";

export const DEFAULT_PRODUCTION_SENDER_ROOT_KEY_PATH = "/var/lib/tinycloud/share/sender-root.key";

/**
 * The Ed25519 signing identity a single authenticated principal signs Share
 * envelopes and invitation-authorization requests with. The private key never
 * leaves the host process and is never serialized into any response.
 */
export interface SenderIdentity {
  readonly did: string;
  readonly publicKey: string;
  readonly privateKey: Uint8Array;
}

/**
 * Resolves the sender identity for a verified session principal.
 *
 * The identity is intentionally *stable* per principal rather than ephemeral:
 * tinycloud-node resolves an invitation-authorization request against an
 * operator-provisioned authority-material record whose `senderDid` is fixed at
 * node boot (see `AuthenticatedAuthorityMaterialProvider`), so a per-request
 * key could never be authorized. Stability comes from a persistent host seed;
 * the *binding to a wallet* comes from the derivation input.
 */
export interface SenderIdentitySource {
  forPrincipal(principal: string): SenderIdentity;
}

function identityFromPrivateKey(privateKey: Uint8Array): SenderIdentity {
  if (privateKey.length !== 32) throw new Error("sender identity private key must be 32 bytes");
  const publicKey = ed25519.getPublicKey(privateKey);
  return Object.freeze({ did: didKeyFromEd25519PublicKey(publicKey), publicKey: toBase64Url(publicKey), privateKey });
}

/**
 * The trust-bundle sender key, used for every principal. Only reachable in the
 * explicit test-authority composition: production loads the trust bundle
 * without any sender secret, so `senderPrivateKey` is empty there.
 */
export function staticSenderIdentitySource(senderPrivateKey: string): SenderIdentitySource {
  if (!B64_256.test(senderPrivateKey)) throw new Error("sender identity private key is invalid");
  const identity = identityFromPrivateKey(fromBase64Url(senderPrivateKey));
  return { forPrincipal: () => identity };
}

/**
 * Derives a distinct, stable sender key per authenticated principal from one
 * persistent host seed. A session for wallet A can never produce a signature
 * under wallet B's sender identity, and no sender secret exists in the
 * deployment configuration.
 */
export function derivedSenderIdentitySource(seed: Uint8Array): SenderIdentitySource {
  if (seed.length !== 32) throw new Error("sender root seed must be 32 bytes");
  const cache = new Map<string, SenderIdentity>();
  return {
    forPrincipal(principal: string): SenderIdentity {
      if (typeof principal !== "string" || !derivablePrincipal(principal)) {
        throw new Error("sender identity principal is invalid");
      }
      const cached = cache.get(principal);
      if (cached !== undefined) return cached;
      const derived = new Uint8Array(hkdfSync("sha256", seed, new TextEncoder().encode(DERIVATION_SALT), new TextEncoder().encode(`${DERIVATION_INFO}${principal}`), 32));
      const identity = identityFromPrivateKey(derived);
      if (cache.size >= IDENTITY_CACHE_LIMIT) cache.delete(cache.keys().next().value as string);
      cache.set(principal, identity);
      return identity;
    },
  };
}

function parseSeed(value: string): Uint8Array {
  if (!B64_256.test(value)) throw new Error("sender root key is invalid");
  const seed = fromBase64Url(value);
  if (seed.byteLength !== 32 || toBase64Url(seed) !== value) throw new Error("sender root key is invalid");
  return seed;
}

/**
 * Reads — or creates once, 0600, inside the persistent Share volume — the
 * sender root seed. There is deliberately no inline environment variant: a
 * sender secret must never be expressible in deployment configuration.
 *
 * The path is validated to be a normalized, traversal-free descendant of the
 * verified persistent root, must not collide with any reserved file, and every
 * component is walked symlink-free. Reads and writes go through O_NOFOLLOW
 * descriptors and the descriptor itself is stat-ed, so a writable parent
 * directory cannot redirect the host onto attacker-chosen key material.
 */
export function loadSenderRootSeed(env: NodeJS.ProcessEnv, environment: "production" | "test", options: { readonly root?: string; readonly reserved?: readonly string[] } = {}): Uint8Array {
  const configured = env.SHARE_SENDER_ROOT_KEY_PATH ?? (environment === "production" ? DEFAULT_PRODUCTION_SENDER_ROOT_KEY_PATH : undefined);
  if (configured === undefined) throw new Error("a persistent sender root key path is required when SHARE_SENDER_ENABLED=true");
  const path = options.root === undefined
    ? assertCanonicalPath(configured, "sender root key path")
    : assertInsideRoot(configured, options.root, "sender root key path");
  for (const other of options.reserved ?? []) {
    if (path === resolve(other) || path === `${resolve(other)}.lock`) throw new Error("sender root key path must not collide with other Share key or journal material");
  }
  const readExisting = (): Uint8Array => {
    assertSecurePath(path, false);
    const descriptor = openSync(path, SECURE_READ);
    try {
      const info = fstatSync(descriptor);
      if (!info.isFile() || info.size > 64) throw new Error("sender root key is not a regular 32-byte seed file");
      if ((info.mode & 0o077) !== 0) throw new Error("sender root key must not be group- or world-accessible");
      if (info.uid !== process.getuid?.()) throw new Error("sender root key must be owned by the Share host user");
      return parseSeed(readFileSync(descriptor, "utf8").trim());
    } finally { closeSync(descriptor); }
  };
  try {
    return readExisting();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const generated = randomBytes(32);
  let descriptor: number | undefined;
  try {
    assertSecurePath(path);
    descriptor = openSync(path, SECURE_CREATE, 0o600);
    writeSync(descriptor, toBase64Url(generated), undefined, "utf8");
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    // Durably link the new entry into its directory, so a crash cannot silently
    // rotate every wallet identity on the next boot.
    const parent = openSync(path.slice(0, path.lastIndexOf("/")) || "/", "r");
    try { fsyncSync(parent); } finally { closeSync(parent); }
    return new Uint8Array(generated);
  } catch (error) {
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch { /* best-effort close */ }
    }
    if ((error as NodeJS.ErrnoException).code === "EEXIST") return readExisting();
    throw error;
  }
}

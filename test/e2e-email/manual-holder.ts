import { didKeyFromEd25519PublicKey, fromBase64Url, toBase64Url } from "@tinycloud/share-envelope";
import type { HolderKey } from "../../src/email-share/claim.ts";

export interface ExportableTestHolder extends HolderKey {
  readonly jwk: JsonWebKey;
}

function bytes(value: string | undefined, label: string): Uint8Array {
  if (value === undefined) throw new TypeError(`${label} is missing`);
  const decoded = fromBase64Url(value);
  if (decoded.length !== 32) throw new TypeError(`${label} must be 32 bytes`);
  return decoded;
}

function assertPrivateJwk(value: JsonWebKey): void {
  if (value.kty !== "OKP" || value.crv !== "Ed25519") throw new TypeError("manual holder JWK is not Ed25519");
  bytes(value.x, "manual holder JWK x");
  bytes(value.d, "manual holder JWK d");
  if (value.ext !== true || value.key_ops === undefined || !value.key_ops.includes("sign")) throw new TypeError("manual holder JWK is not exportable for the manual harness");
}

function didForJwk(value: JsonWebKey): string {
  const publicKey = bytes(value.x, "manual holder JWK x");
  return didKeyFromEd25519PublicKey(publicKey);
}

export async function createExportableTestHolder(): Promise<ExportableTestHolder> {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const privateKey = pair.privateKey as CryptoKey;
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  assertPrivateJwk(jwk);
  const did = didForJwk(jwk);
  return { did, privateKey, jwk };
}

export async function importExportableTestHolder(jwk: JsonWebKey): Promise<ExportableTestHolder> {
  assertPrivateJwk(jwk);
  const publicKey = bytes(jwk.x, "manual holder JWK x");
  const privateBytes = bytes(jwk.d, "manual holder JWK d");
  void privateBytes;
  const privateKey = await crypto.subtle.importKey("jwk", jwk, "Ed25519", true, ["sign"]);
  const exported = await crypto.subtle.exportKey("jwk", privateKey);
  assertPrivateJwk(exported);
  if (toBase64Url(publicKey) !== exported.x) throw new TypeError("manual holder JWK public key mismatch");
  return { did: didKeyFromEd25519PublicKey(publicKey), privateKey, jwk: exported };
}

export async function exportExportableTestHolder(holder: ExportableTestHolder): Promise<JsonWebKey> {
  const jwk = await crypto.subtle.exportKey("jwk", holder.privateKey);
  assertPrivateJwk(jwk);
  if (didForJwk(jwk) !== holder.did) throw new TypeError("manual holder DID/JWK mismatch");
  return jwk;
}

/**
 * The named-key client an owner session exposes (`tcw.keys`), as the SDK's path-bound helper drives it: `encrypt` to the share key's public key,
 * returning a v2 envelope wrapped to that key. Test fake only: the wrapped key is not a real wrap, but every field the helper
 * checks is well formed (strict base64, a canonical hash that matches the wrapped key, a ciphertext of at least 28 bytes).
 */
import { sha256 } from "@noble/hashes/sha256";
import { canonicalize } from "@tinycloud/share-envelope";

const WRAPPED_KEY = btoa(String.fromCharCode(...Uint8Array.from({ length: 61 }, (_, index) => (index * 7 + 3) % 256)));
const CANONICAL_HASH = [...sha256(new TextEncoder().encode(canonicalize(WRAPPED_KEY)))].map((byte) => byte.toString(16).padStart(2, "0")).join("");
const CIPHERTEXT = btoa("c".repeat(32));

export interface PathBoundKeysFake {
  encrypt(keyPath: string, plaintext: Uint8Array, options: { networkId: string; metadata?: Record<string, string> }): Promise<{
    v: number; networkId: string; keyPath: string; alg: string; keyVersion: number; encryptedSymmetricKey: string; encryptedSymmetricKeyHash: string; ciphertext: string; metadata?: Record<string, string>;
  }>;
}

export function pathBoundKeys(): PathBoundKeysFake {
  return {
    encrypt: async (keyPath, _plaintext, options) => ({
      v: 2, networkId: options.networkId, keyPath, alg: "x25519-aes256gcm/v1", keyVersion: 1,
      encryptedSymmetricKey: WRAPPED_KEY, encryptedSymmetricKeyHash: CANONICAL_HASH, ciphertext: CIPHERTEXT,
      ...(options.metadata === undefined ? {} : { metadata: options.metadata }),
    }),
  };
}

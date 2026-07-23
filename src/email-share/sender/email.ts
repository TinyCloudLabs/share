/**
 * Exact-email normalization/validation for the TinyCloud email-claim v1
 * sender flow (specs/email-claim-v1/schemas.json `$defs.email`,
 * specs/email-claim-v1/README.md "Email and sources").
 *
 * The contract is an ASCII addr-spec only: the local part is RFC 5322
 * `dot-atom-text` (`atext` runs joined by single dots) and is preserved
 * byte-for-byte; only the domain is ASCII-lowercased. Limits are BYTE
 * limits — since the whole string is ASCII-only by this point, `.length`
 * already counts bytes.
 */

const ATEXT = "A-Za-z0-9!#$%&'*+\\-/=?^_`{|}~";
const LOCAL_DOT_ATOM = new RegExp(`^[${ATEXT}]+(?:\\.[${ATEXT}]+)*$`);
const DOMAIN_LDH = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

function isAsciiOnly(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) > 0x7f) return false;
  }
  return true;
}

/**
 * Normalize and strictly validate an exact-email recipient address. Returns
 * the canonical `local@lowercased-domain` string, or `null` if the input is
 * not a valid single ASCII addr-spec.
 *
 * Rejects (fail closed, never guesses a "close enough" address): leading,
 * trailing, repeated, or interior whitespace; quoted or commented locals;
 * backslashes; multiple `@`; non-ASCII (Unicode) locals or domains; empty
 * local/domain/labels; LDH label violations (leading/trailing hyphen, over
 * 63 bytes); and the contract's overall/local/domain byte limits (3-254 /
 * 1-64 / 1-253).
 */
export function normalizeExactEmail(input: string): string | null {
  if (input.length < 3 || input.length > 254) return null;
  if (!isAsciiOnly(input)) return null;

  const atIndex = input.indexOf("@");
  if (atIndex === -1) return null;
  if (input.indexOf("@", atIndex + 1) !== -1) return null; // multiple @

  const local = input.slice(0, atIndex);
  const domain = input.slice(atIndex + 1);
  if (local.length < 1 || local.length > 64) return null;
  if (domain.length < 1 || domain.length > 253) return null;
  if (!LOCAL_DOT_ATOM.test(local)) return null;

  const domainLower = domain.toLowerCase();
  if (!DOMAIN_LDH.test(domainLower)) return null;

  return `${local}@${domainLower}`;
}

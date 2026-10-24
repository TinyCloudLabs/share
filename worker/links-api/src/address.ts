/**
 * Client address buckets (contract section 4.9).
 *   rateKey: keys the per-address rate limits (IPv4 the address, IPv4-mapped IPv6 its IPv4 address, IPv6 the /64).
 *   liveKey: keys the live-record cap (the same, except IPv6 uses the /48).
 * IPv6 prefix keys are RFC 5952 text. An address that does not parse, or is missing, falls into the one
 * shared bucket `unparseable`.
 */

export const UNPARSEABLE_BUCKET = "unparseable";

const IPV4_RE = /^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$/;

function ipv4Canonical(text: string): string | null {
  return IPV4_RE.test(text) && text.split(".").every((o) => Number(o) <= 255) ? text : null;
}

/** Eight 16-bit groups of an IPv6 literal, or null when it does not parse. */
function ipv6Groups(address: string): number[] | null {
  let s = address;
  const zone = s.indexOf("%");
  if (zone >= 0) {
    s = s.slice(0, zone);
  }
  const lastColon = s.lastIndexOf(":");
  const tail = s.slice(lastColon + 1);
  if (tail.includes(".")) {
    if (ipv4Canonical(tail) === null) {
      return null;
    }
    const [a = 0, b = 0, c = 0, d = 0] = tail.split(".").map(Number);
    s = `${s.slice(0, lastColon + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) {
    return null;
  }
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  let parts: string[];
  if (halves.length === 2) {
    const fill = 8 - head.length - rest.length;
    if (fill < 1) {
      return null;
    }
    parts = [...head, ...new Array<string>(fill).fill("0"), ...rest];
  } else {
    parts = head;
  }
  if (parts.length !== 8 || !parts.every((p) => /^[0-9a-f]{1,4}$/.test(p))) {
    return null;
  }
  return parts.map((p) => parseInt(p, 16));
}

/** RFC 5952: lower case, no leading zeros, the longest run of two or more zero groups (the first on a tie) as `::`. */
function ipv6Canonical(groups: readonly number[]): string {
  let start = -1;
  let length = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) {
      j++;
    }
    if (j - i > length) {
      start = i;
      length = j - i;
    }
    i = j;
  }
  const text = (n: number) => n.toString(16);
  if (length < 2) {
    return groups.map(text).join(":");
  }
  return `${groups.slice(0, start).map(text).join(":")}::${groups.slice(start + length).map(text).join(":")}`;
}

export interface AddressBuckets {
  readonly rateKey: string;
  readonly liveKey: string;
}

export function addressBuckets(address: string | null | undefined): AddressBuckets {
  const shared = { rateKey: UNPARSEABLE_BUCKET, liveKey: UNPARSEABLE_BUCKET };
  if (typeof address !== "string") {
    return shared;
  }
  const s = address.trim().toLowerCase();
  if (!s.includes(":")) {
    const v4 = ipv4Canonical(s);
    return v4 === null ? shared : { rateKey: v4, liveKey: v4 };
  }
  const groups = ipv6Groups(s);
  if (groups === null) {
    return shared;
  }
  const [g5 = 0, g6 = 0, g7 = 0] = groups.slice(5);
  if (groups.slice(0, 5).every((g) => g === 0) && g5 === 0xffff) {
    const v4 = `${g6 >> 8}.${g6 & 0xff}.${g7 >> 8}.${g7 & 0xff}`;
    return { rateKey: v4, liveKey: v4 };
  }
  const prefix = (groupCount: number) =>
    `${ipv6Canonical([...groups.slice(0, groupCount), ...new Array<number>(8 - groupCount).fill(0)])}/${groupCount * 16}`;
  return { rateKey: prefix(4), liveKey: prefix(3) };
}

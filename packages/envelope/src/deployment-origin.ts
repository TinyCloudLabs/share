const DNS_HOSTNAME_RE =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function isIpv4Literal(hostname: string): boolean {
  const octets = hostname.split(".");
  return (
    octets.length === 4 &&
    octets.every(
      (octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255,
    )
  );
}

function isCanonicalDeploymentDnsHostname(hostname: string): boolean {
  return DNS_HOSTNAME_RE.test(hostname) && !isIpv4Literal(hostname);
}

/** Frozen v2 rule: default-port HTTPS DNS origin maps to `did:web:<host>`. */
export function canonicalNodeAudienceForOrigin(origin: string): string | null {
  try {
    const url = new URL(origin);
    if (
      url.protocol !== "https:" ||
      url.origin !== origin ||
      url.port !== "" ||
      !isCanonicalDeploymentDnsHostname(url.hostname)
    ) {
      return null;
    }
    return `did:web:${url.hostname}`;
  } catch {
    return null;
  }
}

export function isCanonicalDeploymentNodeAudience(value: string): boolean {
  const prefix = "did:web:";
  return (
    value.startsWith(prefix) &&
    isCanonicalDeploymentDnsHostname(value.slice(prefix.length))
  );
}

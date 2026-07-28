// The real /share-email/readiness route (rust/opencredentials_witness/src/
// share_email/runtime.rs) only ever returns {healthy:false} on HTTP 503, or
// {healthy:true, capability} on HTTP 200; a generic 2xx waitFor cannot tell
// a booted-but-unready witness apart from one that never composed at all.
export function assertCredentialsReadinessBody(status, body, expectedCapabilityId) {
  if (status !== 200) throw new Error(`OpenCredentials readiness returned HTTP ${status}`);
  if (body === null || typeof body !== "object") throw new Error("OpenCredentials readiness body was not a JSON object");
  if (body.healthy !== true) throw new Error(`OpenCredentials readiness reported healthy=${JSON.stringify(body.healthy)}`);
  if (body.capability?.status !== "ready") throw new Error(`OpenCredentials readiness capability.status was ${JSON.stringify(body.capability?.status ?? null)}, not "ready"`);
  if (body.capability?.id !== expectedCapabilityId) throw new Error(`OpenCredentials readiness capability id was ${JSON.stringify(body.capability?.id ?? null)}, not ${JSON.stringify(expectedCapabilityId)}`);
}

const REDACTION_PLACEHOLDER = "[redacted]";

export function redactSecrets(text, secrets) {
  let redacted = text;
  for (const secret of secrets) {
    if (typeof secret === "string" && secret.length > 0) redacted = redacted.split(secret).join(REDACTION_PLACEHOLDER);
  }
  return redacted;
}

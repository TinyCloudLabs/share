/**
 * Compatibility bridge for an older local package. New browser flows use the
 * reusable SDK directly; this bridge keeps its remaining v3 caller on the
 * embedded Node admission contract.
 */
export async function requestUnifiedChallenge(input: { readonly nodeOrigin: string; readonly policyCid: string; readonly recipientDid: string; readonly requestedCapabilities: readonly unknown[]; readonly fetchFn?: typeof fetch }): Promise<Record<string, unknown>> {
  const response = await (input.fetchFn ?? globalThis.fetch)(new URL("/policy/v3/challenges", input.nodeOrigin), { method: "POST", headers: { accept: "application/json", "content-type": "application/json" }, body: JSON.stringify({ policyCid: input.policyCid, recipientDid: input.recipientDid, requestedCapabilities: input.requestedCapabilities }) });
  if (!response.ok) throw new Error(`policy challenge rejected (${response.status})`);
  return response.json() as Promise<Record<string, unknown>>;
}

export async function claimUnifiedDelegation(input: { readonly nodeOrigin: string; readonly policyCid: string; readonly recipientDid: string; readonly policyRootCid: string; readonly enforcementRootCid: string; readonly requestedCapabilities: readonly unknown[]; readonly challenge: Record<string, unknown>; readonly claim: Record<string, unknown>; readonly presentation: Record<string, unknown>; readonly fetchFn?: typeof fetch }): Promise<{ readonly authorization: string; readonly cid: string; readonly delegationHeader: { readonly Authorization: string } }> {
  const response = await (input.fetchFn ?? globalThis.fetch)(new URL("/policy/v3/delegations", input.nodeOrigin), { method: "POST", headers: { accept: "application/json", "content-type": "application/json" }, body: JSON.stringify({ policyCid: input.policyCid, challengeId: input.challenge.challengeId, nonce: input.challenge.nonce, claim: input.claim, presentation: input.presentation }) });
  if (!response.ok) throw new Error(`policy delegation rejected (${response.status})`);
  const value = await response.json() as { authorization?: unknown; sessionCid?: unknown };
  if (typeof value.authorization !== "string" || typeof value.sessionCid !== "string") throw new Error("policy delegation response is invalid");
  return { authorization: value.authorization, cid: value.sessionCid, delegationHeader: { Authorization: value.authorization } };
}

// SHARE_NODE_ENFORCER_DID must come from the exact runtime trust bundle Node
// and Share both load, not from export-share-invitation-descriptor's reported
// deployment audience. The exporter only needs to run before Node boots (to
// derive the invitation public key), so it can describe a different
// deployment (e.g. did:web:tee.node.tinycloud.xyz) than the one the harness
// actually enrolls (did:web:node.tinycloud.xyz). This helper only ever reads
// the audience Node was actually launched with.
export function nodeEnforcerAudienceFromTrustBundle(nodeTrustBundleJson) {
  let parsed;
  try {
    parsed = JSON.parse(nodeTrustBundleJson);
  } catch {
    throw new Error("node trust bundle must be valid JSON");
  }
  const nodeAudience = parsed?.nodeAudience;
  if (typeof nodeAudience !== "string" || nodeAudience.length === 0) {
    throw new Error("node trust bundle must declare a non-empty nodeAudience");
  }
  return nodeAudience;
}

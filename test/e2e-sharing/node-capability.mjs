export function assertNodeShareV2Capability(info) {
  const capability = info?.shareV2;
  if (capability?.id !== "tinycloud.node-sharing-v2" || capability.version !== 2) {
    throw new Error("real Node /info omitted its sharing-v2 capability");
  }
  if (typeof capability.enforcerDid !== "string" || !capability.enforcerDid.startsWith("did:key:")) {
    throw new Error("real Node /info omitted its Ed25519 enforcer DID");
  }
  return capability;
}

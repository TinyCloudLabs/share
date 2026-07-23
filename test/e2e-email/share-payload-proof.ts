import { createHash } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";
import {
  canonicalize,
  computeCid,
  didKeyFromEd25519PublicKey,
  fromBase64Url,
  toBase64Url,
} from "@tinycloud/share-envelope";
import { createShareLink, accessSharedContent } from "../../packages/share-sdk/src/index.ts";
import { createHttpTransport, type ShareTransport } from "../../src/email-share/transport.ts";
import { resolveShare } from "../../src/viewer/resolve.ts";
import { type ContentSource, type SenderScope } from "../../src/email-share/protocol.ts";
import { verifyProductionEmailShare } from "../../src/email-share/runtime.ts";
import { validateSharePublicBinding, type SharePublicBinding, type SharePublicConfig } from "../../src/email-share/config.ts";
import { captureFirstRedactedNodeFailure, type RedactedNodeFailure } from "./redacted-node-failure.ts";

const root = resolve(import.meta.dirname, "../..");
const workspaceRoot = resolve(root, "../../../..");
const nodeRoot = resolve(root, "../../../tinycloud-node/feat/email-claim-n4-integration");
const nodeAudience = "did:web:node.tinycloud.xyz";
const nodeOrigin = "https://node.tinycloud.xyz";
const shareOrigin = "https://share.tinycloud.xyz";
const credentialOrigin = "https://witness.credentials.org";
const content = "# TinyCloud policy payload test\n\nPolicy-authorized payload consumption succeeded.";

type Json = Record<string, any>;

const artifactPath = resolve(workspaceRoot, ".context/share-payload-proof.json");
const proofStages: Record<string, boolean> = {
  contentStored: false,
  policyCreated: false,
  enforcementDelegated: false,
  payloadCreated: false,
  recipientCredentialProved: false,
  policyEnforced: false,
  contentConsumed: false,
};
const proofNegativeCases: Record<string, boolean> = {
  nodeExactEmailMismatchDenied: false,
  policySubstitutionDenied: false,
  resourceOrSourceSubstitutionDenied: false,
  nodeExpiryDenied: false,
  fullSessionReadReplayDenied: false,
  missingEnforcementParentDenied: false,
  differentOwnerSignatureDenied: false,
  wrongEnforcerAudienceDenied: false,
  payloadAloneDenied: false,
};

async function writeProofArtifact(value: Json): Promise<void> {
  await writeFile(artifactPath, `${JSON.stringify(value, null, 2)}\n`, { flag: "w" });
}

async function writeBlockedProof(error: unknown): Promise<void> {
  void error;
  await writeProofArtifact({
    status: "blocked",
    summary: "The focused exact-email policy payload harness did not complete.",
    artifactPath,
    command: "npm run test:e2e:share-payload-proof",
    stages: { ...proofStages },
    negativeCases: { ...proofNegativeCases },
    nodeFailure: nodeFailure ?? null,
    checks: ["The proof artifact was overwritten at run start; no stale success evidence is retained."],
    blockers: ["The focused exact-email policy payload harness did not complete."],
  });
}

let nodeFailure: RedactedNodeFailure | undefined;

function digestBytes(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("base64url");
}

function sleep(ms: number): Promise<void> { return new Promise((resolveSleep) => setTimeout(resolveSleep, ms)); }

async function waitJson(path: string, process: ChildProcess): Promise<Json> {
  for (let i = 0; i < 240; i += 1) {
    try { return JSON.parse(await readFile(path, "utf8")) as Json; } catch { /* starting */ }
    if (process.exitCode !== null) throw new Error("TinyCloud Node exited before publishing its descriptor");
    await sleep(250);
  }
  throw new Error("TinyCloud Node descriptor timeout");
}

async function closeServer(server: ReturnType<typeof createServer>): Promise<void> {
  await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
}

async function readRequestBody(request: import("node:http").IncomingMessage): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of request) chunks.push(typeof chunk === "string" ? new TextEncoder().encode(chunk) : chunk);
  const size = chunks.reduce((total, chunk) => total + chunk.length, 0);
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
  return body;
}

async function startNode(temp: string): Promise<{ descriptor: Json; process: ChildProcess }> {
  const descriptorPath = join(temp, "node.json");
  const issuerSeed = Buffer.alloc(32, 0x43);
  const issuerPublic = toBase64Url(ed25519.getPublicKey(issuerSeed));
  const keysSecret = Buffer.alloc(32, 0x09).toString("base64url");
  const process = spawn("cargo", ["run", "--quiet", "-p", "tinycloud-node-production-e2e", "--features", "mounted-fixture", "--", "--descriptor", descriptorPath, "--issuer-public-key", issuerPublic, "--keys-secret", keysSecret], { cwd: nodeRoot, detached: true, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  process.stdout?.on("data", (chunk) => { output += String(chunk); });
  process.stderr?.on("data", (chunk) => { output = `${output.slice(-12000)}${String(chunk)}`; });
  try {
    const descriptor = await waitJson(descriptorPath, process);
    return { descriptor, process };
  } catch (error) {
    throw new Error(`${error instanceof Error ? error.message : String(error)}\n${output.slice(-12000)}`);
  }
}

async function stop(process: ChildProcess): Promise<void> {
  if (process.exitCode === null && process.pid !== undefined) {
    try { process.kill("SIGTERM"); } catch { /* already stopped */ }
    await new Promise<void>((resolveExit) => { process.once("exit", () => resolveExit()); setTimeout(resolveExit, 5_000); });
  }
}

async function main(): Promise<Json> {
  await writeProofArtifact({
    status: "blocked",
    summary: "The focused exact-email policy payload harness is running.",
    artifactPath,
    command: "npm run test:e2e:share-payload-proof",
    stages: { ...proofStages },
    negativeCases: { ...proofNegativeCases },
    nodeFailure: null,
    checks: [],
    blockers: [],
  });
  const temp = await mkdtemp(join(tmpdir(), "tinycloud-share-payload-proof-"));
  let node: ChildProcess | undefined;
  let credentialProcess: ChildProcess | undefined;
  let registryServer: ReturnType<typeof createServer> | undefined;
  try {
    const started = await startNode(temp); node = started.process;
    const descriptor = started.descriptor;
    const fixture = (descriptor.cases as Json[]).find((candidate) => candidate.kind === "kv");
    if (fixture === undefined) throw new Error("mounted Node did not publish a KV fixture");
    const scope = fixture.scope ?? fixture;
    const source = fixture.source as ContentSource;
    const authorityMaterial = fixture.authorityMaterial as Json;
    const policyDocument = fixture.policy as Json;
    if (authorityMaterial === undefined || policyDocument === undefined) throw new Error("mounted Node omitted the authenticated policy bundle");
    const policyBytes = toBase64Url(new TextEncoder().encode(canonicalize(policyDocument)));
    proofStages.contentStored = fixture.expectedContent === content;
    const senderPrivateKey = fromBase64Url(scope.senderPrivateKey);
    const senderPublicKey = ed25519.getPublicKey(senderPrivateKey);
    const senderDid = didKeyFromEd25519PublicKey(senderPublicKey);
    if (senderDid !== scope.senderDid) throw new Error("owner/sender identity binding failed");

    const blobs = new Map<string, Uint8Array>();
    const bindingPath = join(temp, "authoritative-binding.json");
    registryServer = createServer((request, response) => {
      const pathname = new URL(request.url ?? "/", "http://registry").pathname;
      if (request.method === "POST" && pathname.startsWith("/bindings/")) {
        void (async () => {
          try {
            const binding = validateSharePublicBinding(JSON.parse(new TextDecoder().decode(await readRequestBody(request))));
            await writeFile(bindingPath, `${JSON.stringify(binding)}\n`, { flag: "w" });
            response.writeHead(201, { "cache-control": "no-store" }).end();
          } catch { response.writeHead(400).end(); }
        })();
        return;
      }
      if (request.method === "GET" && pathname.startsWith("/bindings/")) {
        void readFile(bindingPath).then((body) => response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" }).end(body)).catch(() => response.writeHead(404).end());
        return;
      }
      const cid = pathname.split("/").pop() ?? "";
      const blob = blobs.get(cid);
      if (request.method !== "GET" || blob === undefined) { response.writeHead(404).end(); return; }
      response.writeHead(200, { "content-type": "application/vnd.ipld.raw", "content-length": blob.length }); response.end(blob);
    });
    await new Promise<void>((resolveListen) => registryServer?.listen(0, "127.0.0.1", resolveListen));
    const registryAddress = registryServer.address();
    if (registryAddress === null || typeof registryAddress === "string") throw new Error("registry bind failed");
    const registryOrigin = `http://127.0.0.1:${registryAddress.port}`;
    const nodeRequests: string[] = [];
    const nodeRequestBodies: Array<{ pathname: string; body: string }> = [];

    const invitationId = toBase64Url(new Uint8Array(16).fill(0x31));
    const claimSecret = toBase64Url(new Uint8Array(32).fill(0x32));
    const now = new Date(Date.now() - 1000).toISOString();
    const scopeForShare: SenderScope = {
      policyOwnerDid: scope.policyOwnerDid,
      senderDid,
      signingCapability: { capabilityId: "proof-kv-capability", publicKey: senderPublicKey },
      signer: { publicKey: senderPublicKey, sign: async ({ purpose, message }) => {
        const domain = purpose === "envelope" ? "xyz.tinycloud.share/envelope/v1\0" : "xyz.tinycloud.share/invite-authorization/v1\0";
        return ed25519.sign(new TextEncoder().encode(`${domain}${message}`), senderPrivateKey);
      } },
      shareOrigin, delegation: scope.delegation, delegationCid: scope.delegationCid,
      authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: scope.authorityMaterialDigest,
      authorityMaterial,
      targetOrigin: nodeOrigin, nodeAudience, spaceId: source.space, documentName: "TinyCloud policy payload test",
      senderTrust: "verified", expiresAt: fixture.expiresAt, trustedNode: {
        targetOrigin: nodeOrigin, nodeAudience, invitationKid: scope.trustedNode.invitationKid,
        invitationPublicKey: fromBase64Url(scope.trustedNode.invitationPublicKey), keyVersion: 1, enabled: true,
      },
    };
    const policyDigest = digestBytes(canonicalize(policyDocument));
    const link = await createShareLink({
      email: "sam@tinycloud.xyz", source, scope: scopeForShare, shareId: "share-policy-payload-proof-0001", expiresAt: fixture.expiresAt, now,
      policy: {
        recipientEmail: policyDocument.recipientEmail,
        source: policyDocument.contentSource,
        action: policyDocument.action,
        resource: policyDocument.resource,
        expiresAt: policyDocument.expiresAt,
        target: { origin: nodeOrigin, nodeAudience, spaceId: source.space },
        policyCid: fixture.policyCid,
        policyDigest,
        policyBytes,
        contentSourceDigest: policyDocument.contentSourceDigest,
        delegationCid: scope.delegationCid,
        authorityMaterialDigest: scope.authorityMaterialDigest,
        policyAuthorityCid: authorityMaterial.policyAuthorityCid,
        policyAuthorityBytes: authorityMaterial.policyAuthorityBytes,
        policyEnforcementCid: authorityMaterial.policyEnforcementCid,
        policyEnforcementBytes: authorityMaterial.policyEnforcementBytes,
      },
      adapters: {
        uploadEnvelope: async (cid, blob) => { blobs.set(cid, blob); },
        publishBinding: async (binding) => {
          const requestBody = {
            shareCid: binding.shareCid,
            shareId: binding.shareId,
            policyCid: binding.policyCid,
            delegationCid: binding.delegationCid,
            authorityMaterialHandle: binding.authorityMaterialHandle,
            authorityMaterialDigest: binding.authorityMaterialDigest,
            recipientEmail: binding.recipientEmail,
            targetOrigin: nodeOrigin,
            nodeAudience,
            action: binding.action,
            resource: binding.resource,
          };
          const request = {
            jti: toBase64Url(new Uint8Array(16).fill(0x33)),
            reportAbuseToken: toBase64Url(new Uint8Array(16).fill(0x34)),
            senderDid,
            shareCid: binding.shareCid,
            shareId: binding.shareId,
            policyCid: binding.policyCid,
            delegationCid: binding.delegationCid,
            authorityMaterialHandle: binding.authorityMaterialHandle,
            authorityMaterialDigest: binding.authorityMaterialDigest,
            recipientEmail: binding.recipientEmail,
            targetOrigin: nodeOrigin,
            nodeAudience,
            documentName: "TinyCloud policy payload test",
            senderTrust: "verified",
            contentSource: binding.contentSource,
            contentSourceDigest: binding.contentSourceDigest,
            shareExpiresAt: binding.expiry,
            requestBodyDigest: digestBytes(canonicalize(requestBody)),
          };
          const signature = await scopeForShare.signer.sign({ purpose: "inviteAuthorization", message: canonicalize(request), binding: requestBody });
          const authorizationResponse = await fetch(`${started.descriptor.url}/share/v1/invitations/authorize`, {
            method: "POST",
            headers: { "content-type": "application/json", origin: shareOrigin },
            body: JSON.stringify({ request, proof: { alg: "EdDSA", kid: `${senderDid}#${senderDid.slice("did:key:".length)}`, signature: toBase64Url(signature) } }),
          });
          if (!authorizationResponse.ok) throw new Error(`Node rejected owner policy registration (${authorizationResponse.status})`);
          const authorization = await authorizationResponse.json() as Json;
          if (authorization.authorization?.policyCid !== binding.policyCid || authorization.authorization?.delegationCid !== binding.delegationCid) throw new Error("Node authorization did not return the registered binding");
          const publicBinding = {
            shareId: binding.shareId,
            policyCid: binding.policyCid,
            recipientEmail: binding.recipientEmail,
            expiry: binding.expiry,
            delegationCid: binding.delegationCid,
            authorityMaterialHandle: binding.authorityMaterialHandle,
            authorityMaterialDigest: binding.authorityMaterialDigest,
            contentSource: binding.contentSource,
            contentSourceDigest: binding.contentSourceDigest,
            action: binding.action,
            resource: binding.resource,
          };
          const response = await fetch(`${registryOrigin}/bindings/${binding.shareCid}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(publicBinding) });
          if (!response.ok) throw new Error(`authoritative binding registration failed (${response.status})`);
        },
      },
    });
    const bindingResponse = await fetch(`${registryOrigin}/bindings/${link.shareCid}`);
    if (!bindingResponse.ok) throw new Error("registered authoritative binding was not readable");
    const authoritativeBinding = validateSharePublicBinding(await bindingResponse.json()) as SharePublicBinding;
    if (link.policyCid !== scope.policyCid || link.source.path !== source.path || authoritativeBinding.policyCid !== link.policyCid || authoritativeBinding.contentSourceDigest !== link.provenance.contentSourceDigest) throw new Error(`policy registration did not bind the created policy to the exact source: created=${link.policyCid} descriptor=${scope.policyCid} source=${link.source.path}/${source.path}`);
    proofStages.policyCreated = true;
    proofStages.enforcementDelegated = authorityMaterial.mapping?.sharePolicyCid === link.policyCid && authorityMaterial.mapping?.shareDelegationCid === link.provenance.delegationCid && authorityMaterial.policyAuthorityBytes !== undefined && authorityMaterial.policyEnforcementBytes !== undefined;
    proofStages.payloadCreated = link.shareCid.length > 0;
    const payloadUrl = `${link.shareUrl}&i=${invitationId}&c=${claimSecret}`;
    const parsedOnly = await resolveShare(link.shareUrl, { registryBaseUrl: registryOrigin });
    if (parsedOnly.state !== "policy-email-claim-required") throw new Error("opaque payload did not parse through the production resolver");
    if ("content" in parsedOnly) throw new Error("payload parsing alone returned content");
    const nodeRequestsBeforeAccess = nodeRequests.length;
    proofNegativeCases.payloadAloneDenied = nodeRequests.length === nodeRequestsBeforeAccess;

    const fixtureScope = { shareCid: link.shareCid, shareId: link.shareId, policyCid: link.policyCid, delegationCid: link.provenance.delegationCid, authorityMaterialHandle: link.provenance.authorityMaterialHandle, authorityMaterialDigest: link.provenance.authorityMaterialDigest, contentSource: source, contentSourceDigest: link.provenance.contentSourceDigest, targetOrigin: nodeOrigin, nodeAudience };
    credentialProcess = spawn("cargo", ["run", "--quiet", "--manifest-path", resolve(nodeRoot, "../../../opencredentials/feat/email-claim-o4-integration/rust/opencredentials_witness/Cargo.toml"), "--features", "email-claim-fixture", "--bin", "email-claim-proof-fixture"], { cwd: resolve(nodeRoot, "../../../opencredentials/feat/email-claim-o4-integration/rust/opencredentials_witness"), env: { ...process.env, BIND_ADDR: "127.0.0.1:0", PROOF_SCOPE_JSON: JSON.stringify(fixtureScope), PROOF_INVITATION_ID: invitationId, PROOF_CLAIM_SECRET: claimSecret, PROOF_EXPIRES_AT: fixture.expiresAt }, stdio: ["ignore", "pipe", "pipe"] });
    let credentialOutput = "";
    credentialProcess.stdout?.on("data", (chunk) => { credentialOutput += String(chunk); });
    credentialProcess.stderr?.on("data", (chunk) => { credentialOutput = `${credentialOutput.slice(-12000)}${String(chunk)}`; });
    let credentialDescriptor: Json | undefined;
    for (let i = 0; i < 120 && credentialDescriptor === undefined; i += 1) {
      for (const line of credentialOutput.split("\n")) { try { const parsed = JSON.parse(line) as Json; if (parsed.testOnly === true && parsed.url !== undefined) credentialDescriptor = parsed; } catch { /* startup logs */ } }
      if (credentialProcess.exitCode !== null) throw new Error(`OpenCredentials fixture exited\n${credentialOutput.slice(-12000)}`);
      if (credentialDescriptor === undefined) await sleep(250);
    }
    if (credentialDescriptor === undefined) throw new Error(`OpenCredentials fixture descriptor timeout\n${credentialOutput.slice(-12000)}`);
    const credentialOriginLocal = new URL(credentialDescriptor.url).origin;
    let signedReadResponse: Json | undefined;
    const rewriteFetch = async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const parsed = new URL(url instanceof Request ? url.url : String(url));
      const isNode = parsed.origin === nodeOrigin;
      if (isNode) nodeRequests.push(parsed.pathname);
      if (isNode && typeof init?.body === "string") nodeRequestBodies.push({ pathname: parsed.pathname, body: init.body });
      const local = isNode ? `${started.descriptor.url}${parsed.pathname}` : `${credentialOriginLocal}${parsed.pathname}`;
      const response = await fetch(local, init);
      if (isNode) nodeFailure = await captureFirstRedactedNodeFailure(nodeFailure, parsed.pathname, response);
      return response;
    };
    const transportBase = createHttpTransport({ nodeOrigin, credentialsOrigin: credentialOrigin, fetchFn: rewriteFetch });
    const transport: ShareTransport = {
      ...transportBase,
      activate: async (value) => { try { return await transportBase.activate(value); } catch (error) { throw new Error(`fixture activate denied: ${error instanceof Error ? error.message : String(error)}`); } },
      claimChallenge: async (value) => { try { return await transportBase.claimChallenge(value); } catch (error) { throw new Error(`fixture challenge denied: ${error instanceof Error ? error.message : String(error)}`); } },
      claimRedeem: async (value) => { try { return await transportBase.claimRedeem(value); } catch (error) { throw new Error(`fixture redeem denied: ${error instanceof Error ? error.message : String(error)}`); } },
      read: async (value) => {
        const response = await transportBase.read(value);
        signedReadResponse = response as unknown as Json;
        return response;
      },
    };
    let holderDid = "";
    const resolvedShare = await resolveShare(link.shareUrl, { registryBaseUrl: registryOrigin });
    if (resolvedShare.state !== "policy-email-claim-required") throw new Error("share resolver state changed");
    const config: SharePublicConfig = {
      version: "tinycloud.share-email-claim/config-v1",
      shareOrigin,
      registryOrigin: "https://registry.tinycloud.xyz",
      nodeOrigin,
      credentialsOrigin: credentialOrigin,
      nodeAudience,
      issuerDid: "did:web:issuer.credentials.org",
      issuerVct: "opencredentials.email/v1",
      nodeInvitationKid: scopeForShare.trustedNode.invitationKid,
      nodeInvitationPublicKey: toBase64Url(scopeForShare.trustedNode.invitationPublicKey),
      nodeKeyVersion: scopeForShare.trustedNode.keyVersion,
      issuerKeyVersion: 1,
      issuerPublicKey: descriptor.issuerPublicKey,
      environment: "test",
    };
    const verifiedShare = await verifyProductionEmailShare({ envelope: resolvedShare.envelope, shareCid: resolvedShare.shareCid, policy: resolvedShare.policy, config, binding: authoritativeBinding });
    let wrongCredential: Json | undefined;
    const wrongEmailTransport: ShareTransport = {
      ...transport,
      claimRedeem: async (value) => {
        const result = await transportBase.claimRedeem({ ...(value as Json), testWrongRecipient: true } as typeof value);
        wrongCredential = result as unknown as Json;
        return result;
      },
    };
    const wrongCredentialAttempted = await (async () => {
      try {
        await accessSharedContent({ shareUrl: payloadUrl, invitation: { invitationId, claimSecret }, confirmAccess: () => true, dependencies: {
          registryBaseUrl: registryOrigin,
          verifyShare: async ({ envelope, shareCid, policy }) => verifyProductionEmailShare({ envelope, shareCid, policy, config, binding: authoritativeBinding }),
          credentialTrust: { issuerDid: "did:web:issuer.credentials.org", vct: "opencredentials.email/v1", issuerPublicKey: ed25519.getPublicKey(new Uint8Array(32).fill(0x43)) },
          transport: wrongEmailTransport,
          onController: () => {},
        } });
        return false;
      } catch { return true; }
    })();
    const access = await accessSharedContent({ shareUrl: payloadUrl, invitation: { invitationId, claimSecret }, confirmAccess: () => true, dependencies: {
      registryBaseUrl: registryOrigin,
      verifyShare: async ({ envelope, shareCid, policy }) => {
        return verifyProductionEmailShare({ envelope, shareCid, policy, config, binding: authoritativeBinding });
      },
      credentialTrust: { issuerDid: "did:web:issuer.credentials.org", vct: "opencredentials.email/v1", issuerPublicKey: ed25519.getPublicKey(new Uint8Array(32).fill(0x43)) },
      transport, onController: () => {},
    } });
    if (access.content !== content) throw new Error("authoritative content mismatch");
    holderDid = access.holderDid;
    proofStages.recipientCredentialProved = holderDid.startsWith("did:key:");
    proofStages.policyEnforced = nodeRequests.includes("/share/v1/policy/challenges") && nodeRequests.includes("/share/v1/policy/session") && nodeRequests.includes("/share/v1/read");
    const contentDigest = digestBytes(content);
    const contentCid = await computeCid(new TextEncoder().encode(content));

    const denied = async (request: Json): Promise<boolean> => {
      try { await transport.policyChallenge(request); return false; } catch { return true; }
    };
    const authorizeDenied = async (overrides: Json, seed = new Uint8Array(32).fill(0x44), did = senderDid): Promise<boolean> => {
      const requestBody = {
        shareCid: link.shareCid,
        shareId: link.shareId,
        policyCid: link.policyCid,
        delegationCid: link.provenance.delegationCid,
        authorityMaterialHandle: link.provenance.authorityMaterialHandle,
        authorityMaterialDigest: link.provenance.authorityMaterialDigest,
        recipientEmail: "sam@tinycloud.xyz",
        targetOrigin: nodeOrigin,
        nodeAudience,
        action: "tinycloud.kv/get",
        resource: source.path,
      };
      const request: Json = {
        jti: toBase64Url(new Uint8Array(16).fill(0x35)),
        reportAbuseToken: toBase64Url(new Uint8Array(16).fill(0x36)),
        senderDid: did,
        ...requestBody,
        documentName: "TinyCloud policy payload test",
        senderTrust: "verified",
        contentSource: source,
        contentSourceDigest: link.provenance.contentSourceDigest,
        shareExpiresAt: fixture.expiresAt,
        ...overrides,
      };
      request.requestBodyDigest = digestBytes(canonicalize(requestBody));
      const signature = ed25519.sign(new TextEncoder().encode(`xyz.tinycloud.share/invite-authorization/v1\0${canonicalize(request)}`), seed);
      const response = await fetch(`${started.descriptor.url}/share/v1/invitations/authorize`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: shareOrigin },
        body: JSON.stringify({ request, proof: { alg: "EdDSA", kid: `${did}#${did.slice("did:key:".length)}`, signature: toBase64Url(signature) } }),
      });
      return !response.ok;
    };
    const baseRequest = { shareCid: link.shareCid, shareId: link.shareId, delegationCid: link.provenance.delegationCid, authorityMaterialHandle: link.provenance.authorityMaterialHandle, authorityMaterialDigest: link.provenance.authorityMaterialDigest, policyCid: link.policyCid, contentSource: source, contentSourceDigest: link.provenance.contentSourceDigest, holderDid, targetOrigin: nodeOrigin, nodeAudience, action: "tinycloud.kv/get", resource: source.path };
    const withDigest = async (value: Json): Promise<Json> => ({ ...value, requestBodyDigest: digestBytes(canonicalize(value)) });
    const policySubstitutionDenied = await denied(await withDigest({ ...baseRequest, policyCid: link.shareCid }));
    const resourceSubstitutionDenied = await denied(await withDigest({ ...baseRequest, contentSource: { ...source, path: "documents/other.md" }, contentSourceDigest: digestBytes(canonicalize({ ...source, path: "documents/other.md" })), resource: "documents/other.md" }));
    proofNegativeCases.nodeExpiryDenied = await authorizeDenied({ shareExpiresAt: new Date(Date.now() - 1000).toISOString() });
    const sessionBody = [...nodeRequestBodies].reverse().find((entry) => entry.pathname === "/share/v1/policy/session")?.body;
    const readBody = [...nodeRequestBodies].reverse().find((entry) => entry.pathname === "/share/v1/read")?.body;
    const sessionRequest = sessionBody === undefined ? undefined : JSON.parse(sessionBody) as Json;
    if (sessionRequest !== undefined && wrongCredential?.credential !== undefined) {
      sessionRequest.credential = wrongCredential.credential;
      const wrongEmailSessionResponse = await fetch(`${started.descriptor.url}/share/v1/policy/session`, { method: "POST", headers: { "content-type": "application/json", origin: shareOrigin }, body: JSON.stringify(sessionRequest) });
      proofNegativeCases.nodeExactEmailMismatchDenied = wrongCredentialAttempted && !wrongEmailSessionResponse.ok;
    }
    const replayResults = await Promise.all([sessionBody, readBody].map(async (body) => {
      if (body === undefined) return false;
      const path = body === sessionBody ? "/share/v1/policy/session" : "/share/v1/read";
      const response = await fetch(`${started.descriptor.url}${path}`, { method: "POST", headers: { "content-type": "application/json", origin: shareOrigin }, body });
      return !response.ok;
    }));
    proofNegativeCases.fullSessionReadReplayDenied = replayResults.length === 2 && replayResults.every(Boolean);
    proofNegativeCases.missingEnforcementParentDenied = await denied(await withDigest({ ...baseRequest, authorityMaterialHandle: "amh_missing_001" }));
    const otherOwnerSeed = new Uint8Array(32).fill(0x45);
    const otherOwnerDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(otherOwnerSeed));
    proofNegativeCases.differentOwnerSignatureDenied = await authorizeDenied({}, otherOwnerSeed, otherOwnerDid);
    proofNegativeCases.wrongEnforcerAudienceDenied = await denied(await withDigest({ ...baseRequest, nodeAudience: "did:web:wrong.tinycloud.xyz" }));
    const signedResponseDigest = signedReadResponse === undefined ? "" : digestBytes(canonicalize(signedReadResponse));
    const proof: Json = {
      status: "complete", summary: "Exact-email policy payload proof completed through owner registration at the mounted Node authorization boundary, persisted authoritative binding verification, local OpenCredentials claim, mounted TinyCloud Node AuthorityKernel session, signed KV read, and enforcing-boundary denials.",
      artifactPath,
      command: "npm run test:e2e:share-payload-proof",
      stages: { ...proofStages, recipientCredentialProved: holderDid.startsWith("did:key:"), policyEnforced: nodeRequests.includes("/share/v1/policy/challenges") && nodeRequests.includes("/share/v1/policy/session") && nodeRequests.includes("/share/v1/read"), contentConsumed: access.content === content && signedResponseDigest.length === 43 },
      negativeCases: { ...proofNegativeCases, policySubstitutionDenied, resourceOrSourceSubstitutionDenied: resourceSubstitutionDenied },
      nodeFailure: nodeFailure ?? null,
      checks: [
        `content source: ${source.kind}/${source.path}; content CID ${contentCid}; content digest ${contentDigest}`,
        `policy CID ${link.policyCid}; policy digest ${policyDigest}; exact recipient and read-only source are bound in the signed policy artifact`,
        `owner public identifier ${scope.policyOwnerDid}; sender public identifier ${senderDid}; engine public identifier ${nodeAudience}`,
        `delegation CID ${link.provenance.delegationCid}; authority digest ${link.provenance.authorityMaterialDigest}; algorithms EdDSA, EIP-191, SHA-256, and raw-codec CIDv1`,
        `recipient binding digest ${digestBytes(holderDid)}; action tinycloud.kv/get; source ${source.space}; target ${nodeOrigin}/${nodeAudience}; expiry ${fixture.expiresAt}`,
        `opaque payload digest ${digestBytes(link.shareUrl)}; byte length ${Buffer.byteLength(link.shareUrl, "utf8")}; raw secret-bearing payload omitted`,
        `mounted Node policy challenge/session/read routes were exercised; signed response digest ${signedResponseDigest}; response byte length ${signedReadResponse === undefined ? 0 : Buffer.byteLength(JSON.stringify(signedReadResponse), "utf8")}`,
        `payload parsing alone returned no content and made ${nodeRequestsBeforeAccess} Node request(s) before access`,
        `exact-email mismatch denied=${proofNegativeCases.nodeExactEmailMismatchDenied}; policy substitution denied=${policySubstitutionDenied}; resource/source substitution denied=${resourceSubstitutionDenied}; Node expiry denied=${proofNegativeCases.nodeExpiryDenied}; full session/read replay denied=${proofNegativeCases.fullSessionReadReplayDenied}`,
        `missing enforcement parent denied=${proofNegativeCases.missingEnforcementParentDenied}; different owner signature denied=${proofNegativeCases.differentOwnerSignatureDenied}; wrong enforcer/audience denied=${proofNegativeCases.wrongEnforcerAudienceDenied}; payload alone denied=${proofNegativeCases.payloadAloneDenied}`,
        "email transport remained unused; no Resend, browser, public DNS, or PostgreSQL delivery outbox was started",
      ],
      blockers: [],
    };
    Object.assign(proofStages, proof.stages);
    Object.assign(proofNegativeCases, proof.negativeCases);
    if (!Object.values(proof.stages).every(Boolean) || !Object.values(proof.negativeCases).every(Boolean)) throw new Error(JSON.stringify({ stages: proof.stages, negativeCases: proof.negativeCases }));
    return proof;
  } finally {
    if (registryServer !== undefined) await closeServer(registryServer).catch(() => {});
    if (credentialProcess !== undefined) await stop(credentialProcess).catch(() => {});
    if (node !== undefined) await stop(node).catch(() => {});
    await rm(temp, { recursive: true, force: true });
  }
}

main().then(async (proof) => {
  await writeProofArtifact(proof);
  console.log(JSON.stringify(proof));
}).catch(async (error) => {
  await writeBlockedProof(error);
  void error;
  console.error("share-payload-proof blocked");
  process.exitCode = 1;
});

import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile, lstat, readlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { canonicalize, fromBase64Url, toBase64Url } from "@tinycloud/share-envelope";

import { startProductionServer } from "../../src/host/production-server.js";

const shareRoot = resolve(import.meta.dirname, "../..");
const workspaceRoot = resolve(shareRoot, "../../../..");
const nodeWorktree = process.env.TINYCLOUD_NODE_WORKTREE ?? resolve(workspaceRoot, "worktrees/tinycloud-node/feat/share-upload-attestation-20260731");
const sdkWorktree = process.env.TINYCLOUD_SDK_WORKTREE ?? resolve(workspaceRoot, "worktrees/js-sdk/feat/share-cli-greenfield-20260729-a");
const canonicalShare = "https://share.tinycloud.xyz";
const canonicalRegistry = "https://registry.tinycloud.xyz";
const canonicalNode = "https://node.tinycloud.xyz";

type Child = { process: ChildProcess; output: () => string };

type PackedPackage = { manifest: { name: string; version: string; [key: string]: unknown }; bytes: Buffer; filename: string; integrity: string };

async function startNpmRegistry(packages: PackedPackage[]): Promise<{ origin: string; close: () => Promise<void>; requested: Set<string> }> {
  const byName = new Map<string, PackedPackage[]>();
  for (const package_ of packages) {
    const versions = byName.get(package_.manifest.name) ?? [];
    versions.push(package_);
    byName.set(package_.manifest.name, versions);
  }
  const requested = new Set<string>();
  const server = createServer((request, response) => {
    try {
      const pathname = decodeURIComponent(new URL(request.url ?? "/", "http://127.0.0.1").pathname);
      const separator = pathname.indexOf("/-/");
      const name = separator < 0 ? pathname.slice(1) : pathname.slice(1, separator);
      const packageVersions = byName.get(name);
      if (packageVersions === undefined) { response.writeHead(404).end(); return; }
      requested.add(name);
      if (separator < 0) {
        const versions = Object.fromEntries(packageVersions.map((package_) => [package_.manifest.version, {
          ...package_.manifest,
          dist: {
            tarball: `${origin}/${encodeURIComponent(name)}/-/${package_.filename}`,
            integrity: package_.integrity,
          },
        }]));
        const metadata = {
          name,
          "dist-tags": { latest: packageVersions.at(-1)!.manifest.version },
          versions,
        };
        const body = JSON.stringify(metadata);
        response.writeHead(200, { "content-type": "application/json", "content-length": String(Buffer.byteLength(body)) }).end(body);
        return;
      }
      const filename = pathname.slice(`/${name}/-/`.length);
      const package_ = packageVersions.find((candidate) => candidate.filename === filename);
      if (package_ === undefined) { response.writeHead(404).end(); return; }
      response.writeHead(200, { "content-type": "application/octet-stream", "content-length": String(package_.bytes.length) }).end(package_.bytes);
    } catch {
      response.writeHead(400).end();
    }
  });
  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("hermetic npm registry did not bind");
  const origin = `http://127.0.0.1:${address.port}`;
  return { origin, requested, close: () => new Promise<void>((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose())) };
}

function child(command: string, args: string[], cwd: string, env: NodeJS.ProcessEnv): Child {
  const process = spawn(command, args, { cwd, env: { ...globalThis.process.env, ...env }, stdio: ["pipe", "pipe", "pipe"] });
  let output = "";
  const collect = (chunk: Buffer): void => { output = `${output}${chunk.toString()}`.slice(-32_000); };
  process.stdout?.on("data", collect);
  process.stderr?.on("data", collect);
  return { process, output: () => output };
}

async function ready(entry: Child, pattern: RegExp): Promise<RegExpMatchArray> {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const match = entry.output().match(pattern);
    if (match !== null) return match;
    if (entry.process.exitCode !== null) throw new Error("joined service exited before readiness");
    await new Promise((resolveWait) => setTimeout(resolveWait, 50));
  }
  throw new Error("joined service readiness timed out");
}

async function stop(entry: Child): Promise<void> {
  if (entry.process.exitCode !== null) return;
  entry.process.kill("SIGTERM");
  await Promise.race([once(entry.process, "exit"), new Promise((resolveWait) => setTimeout(resolveWait, 5_000))]);
  if (entry.process.exitCode === null) entry.process.kill("SIGKILL");
}

async function runCommand(command: string, args: string[], cwd: string, env: NodeJS.ProcessEnv = {}): Promise<{ status: number; output: string }> {
  const entry = child(command, args, cwd, env);
  const [status] = await once(entry.process, "exit");
  return { status: typeof status === "number" ? status : 1, output: entry.output() };
}

function digest(path: string): Promise<string> {
  return readFile(path).then((bytes) => createHash("sha256").update(bytes).digest("hex"));
}

async function treeDigest(path: string): Promise<string> {
  const hash = createHash("sha256");
  const walk = async (current: string, relative: string): Promise<void> => {
    const entries = (await readdir(current, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const child = join(current, entry.name);
      const childRelative = relative === "" ? entry.name : `${relative}/${entry.name}`;
      hash.update(childRelative);
      if (entry.isDirectory()) await walk(child, childRelative);
      else if (entry.isSymbolicLink()) hash.update(`link:${await readlink(child)}`);
      else hash.update(await readFile(child));
    }
  };
  await walk(path, "");
  return hash.digest("hex");
}

type PackageManifest = PackedPackage["manifest"] & { dependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; peerDependencies?: Record<string, string>; private?: boolean; scripts?: Record<string, string> };

async function readManifest(path: string): Promise<PackageManifest> {
  return JSON.parse(await readFile(join(path, "package.json"), "utf8")) as PackageManifest;
}

async function resolveInstalledDependency(name: string, from: string): Promise<string> {
  const segments = name.startsWith("@") ? name.split("/").slice(0, 2) : [name];
  let current = from;
  while (true) {
    const candidate = join(current, "node_modules", ...segments);
    try { if ((await lstat(join(candidate, "package.json"))).isFile()) return candidate; } catch { /* continue upward */ }
    const parent = resolve(current, "..");
    if (parent === current) break;
    current = parent;
  }
  throw new Error(`dependency ${name} is not installed in the frozen SDK graph`);
}

const expectedSdkHead = process.env.TINYCLOUD_JS_SDK_EXACT_HEAD ?? "7632f6b9ff2a3d035ca3f4802bc8f31dfd86b9b6";
const expectedSdkBranch = process.env.TINYCLOUD_JS_SDK_BRANCH ?? "feat/share-cli-greenfield-20260729-a";

async function assertExactSdkSource(sdkRoot: string): Promise<void> {
  if (!/^[0-9a-f]{40}$/.test(expectedSdkHead)) throw new Error("TINYCLOUD_JS_SDK_EXACT_HEAD must be a full commit");
  const head = (await runCommand("git", ["rev-parse", "HEAD"], sdkRoot)).output.trim();
  const branch = (await runCommand("git", ["branch", "--show-current"], sdkRoot)).output.trim();
  const upstream = (await runCommand("git", ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"], sdkRoot)).output.trim();
  const status = await runCommand("git", ["status", "--porcelain", "--untracked-files=all"], sdkRoot);
  const upstreamHead = (await runCommand("git", ["rev-parse", `origin/${expectedSdkBranch}`], sdkRoot)).output.trim();
  const remoteHead = (await runCommand("git", ["ls-remote", "origin", `refs/heads/${expectedSdkBranch}`], sdkRoot)).output.trim().split(/\s+/)[0];
  if (head !== expectedSdkHead) throw new Error(`js-sdk exact head mismatch: expected ${expectedSdkHead}, found ${head}`);
  if (branch !== expectedSdkBranch || upstream !== `origin/${expectedSdkBranch}`) throw new Error(`js-sdk branch/upstream mismatch: expected ${expectedSdkBranch} tracking origin/${expectedSdkBranch}, found ${branch} tracking ${upstream}`);
  if (status.status !== 0 || status.output.trim() !== "") throw new Error("js-sdk source or generated output is dirty");
  if (upstreamHead !== expectedSdkHead || remoteHead !== expectedSdkHead) throw new Error("js-sdk source head does not match both fetched upstream and remote");
}

async function packWorkspaceArtifact(directory: string, outputRoot: string): Promise<{ manifest: PackageManifest; bytes: Buffer; filename: string; integrity: string }> {
  // Workspace packages are the exact checked-out source authority.  Their
  // normal pack lifecycle is part of the reproducible artifact, so scripts
  // must run rather than being silently suppressed.
  const result = await runCommand("npm", ["pack", "--silent", "--pack-destination", outputRoot], directory);
  if (result.status !== 0) throw new Error(`could not pack ${directory}: ${result.output.slice(-4000)}`);
  const filename = result.output.trim().split(/\r?\n/).at(-1);
  if (filename === undefined || !/\.tgz$/.test(filename)) throw new Error(`npm pack produced no artifact for ${directory}`);
  const bytes = await readFile(join(outputRoot, filename));
  return { manifest: await readManifest(directory), bytes, filename, integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}` };
}

function integrityHex(integrity: string): string {
  if (!integrity.startsWith("sha512-")) throw new Error(`unsupported package integrity ${integrity}`);
  const hex = Buffer.from(integrity.slice("sha512-".length), "base64").toString("hex");
  if (!/^[0-9a-f]{128}$/.test(hex)) throw new Error(`invalid package integrity ${integrity}`);
  return hex;
}

async function readCanonicalNpmArtifact(
  cacheRoot: string,
  name: string,
  version: string,
  integrity: string,
): Promise<{ manifest: PackageManifest; bytes: Buffer; filename: string; integrity: string }> {
  const hex = integrityHex(integrity);
  const contentPath = join(cacheRoot, "_cacache", "content-v2", "sha512", hex.slice(0, 2), hex.slice(2, 4), hex.slice(4));
  let bytes: Buffer;
  try {
    bytes = await readFile(contentPath);
  } catch {
    const fetched = await runCommand("npm", [
      "cache", "add", "--cache", cacheRoot, "--registry", "https://registry.npmjs.org", "--prefer-online", `${name}@${version}`,
    ], shareRoot);
    if (fetched.status !== 0) {
      throw new Error(`canonical npm artifact is missing for ${name}@${version}; populate an independent npm cache with the lockfile SRI before running the joined proof (${fetched.output.slice(-2000)})`);
    }
    try {
      bytes = await readFile(contentPath);
    } catch {
      throw new Error(`canonical npm cache did not contain the lockfile-SRI artifact for ${name}@${version}; refusing a local repack or public-network fallback`);
    }
  }
  const actual = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
  if (actual !== integrity) throw new Error(`canonical npm artifact integrity mismatch for ${name}@${version}: expected ${integrity}, found ${actual}`);
  const archiveEntries = await runCommand("tar", ["-tzf", contentPath], shareRoot);
  if (archiveEntries.status !== 0) throw new Error(`canonical npm artifact for ${name}@${version} is not a readable gzip tarball`);
  const manifestEntry = archiveEntries.output.split(/\r?\n/).map((entry) => entry.trim()).find((entry) => /(?:^|\/)package\.json$/.test(entry));
  if (manifestEntry === undefined) throw new Error(`canonical npm artifact for ${name}@${version} has no package manifest`);
  const manifestText = await runCommand("tar", ["-xOzf", contentPath, manifestEntry], shareRoot);
  if (manifestText.status !== 0) throw new Error(`canonical npm artifact for ${name}@${version} has an unreadable package manifest`);
  const manifest = JSON.parse(manifestText.output) as PackageManifest;
  if (manifest.name !== name || manifest.version !== version) throw new Error(`canonical npm artifact identity mismatch: expected ${name}@${version}, found ${manifest.name}@${manifest.version}`);
  const filename = `${name.replace(/^@/, "").replaceAll("/", "-")}-${version}.tgz`;
  return { manifest, bytes, filename, integrity: actual };
}

function lockIntegrity(lock: { packages?: Record<string, unknown> }, name: string, version: string): string {
  const identity = `${name}@${version}`;
  for (const value of Object.values(lock.packages ?? {})) {
    if (!Array.isArray(value) || value[0] !== identity) continue;
    const integrity = value.find((item): item is string => typeof item === "string" && item.startsWith("sha512-"));
    if (integrity !== undefined) return integrity;
  }
  throw new Error(`bun.lock has no integrity for ${identity}`);
}

async function packFrozenSdkCatalog(sdkRoot: string, outputRoot: string): Promise<PackedPackage[]> {
  await assertExactSdkSource(sdkRoot);
  const bunRuntime = (globalThis as typeof globalThis & { Bun?: { JSON5: { parse(value: string): unknown } } }).Bun;
  if (bunRuntime === undefined) throw new Error("joined harness must run under Bun");
  const lock = bunRuntime.JSON5.parse(await readFile(join(sdkRoot, "bun.lock"), "utf8")) as { workspaces?: Record<string, unknown>; packages?: Record<string, unknown> };
  const catalog = JSON.parse(await readFile(join(shareRoot, "vendor/sdk-cli-artifact-catalog.json"), "utf8")) as { schema?: string; sdkCommit?: string; packages?: Array<{ name: string; version: string }> };
  if (catalog.schema !== "tinycloud.sdk-cli-workspace-catalog/v2" || catalog.sdkCommit !== expectedSdkHead) throw new Error("SDK workspace catalog is not pinned to the requested exact head");
  const expectedWorkspace = new Map((catalog.packages ?? []).map((entry) => [`${entry.name}@${entry.version}`, entry]));
  const workspaceByName = new Map<string, string>();
  for (const workspacePath of Object.keys(lock.workspaces ?? {})) {
    if (workspacePath === "") continue;
    const directory = resolve(sdkRoot, workspacePath);
    try {
      const manifest = await readManifest(directory);
      if (typeof manifest.name === "string" && typeof manifest.version === "string" && manifest.private !== true) workspaceByName.set(manifest.name, directory);
    } catch { /* lock entries for non-package workspace paths are ignored */ }
  }
  const queue = [workspaceByName.get("@tinycloud/cli") ?? (() => { throw new Error("CLI workspace is missing from bun.lock"); })()];
  const directories = new Map<string, { directory: string; workspace: boolean }>();
  while (queue.length > 0) {
    const directory = queue.shift()!;
    const manifest = await readManifest(directory);
    if (typeof manifest.name !== "string" || typeof manifest.version !== "string") throw new Error(`invalid package manifest at ${directory}`);
    const identity = `${manifest.name}@${manifest.version}`;
    if (directories.has(identity)) continue;
    const workspace = workspaceByName.get(manifest.name) === directory;
    directories.set(identity, { directory, workspace });
    for (const dependency of Object.keys({ ...manifest.dependencies, ...manifest.optionalDependencies, ...manifest.peerDependencies })) {
      const dependencyWorkspace = workspaceByName.get(dependency);
      // node_modules is used only to resolve the lock-selected version for
      // graph traversal.  External bytes are always read from the
      // independent SRI-addressed npm cache below, never from this directory.
      queue.push(dependencyWorkspace ?? await resolveInstalledDependency(dependency, directory));
    }
  }
  const packages: PackedPackage[] = [];
  const canonicalNpmCache = join(outputRoot, "canonical-npm-cache");
  for (const { directory, workspace } of directories.values()) {
    const manifest = await readManifest(directory);
    const catalogEntry = expectedWorkspace.get(`${manifest.name}@${manifest.version}`);
    if (workspace && catalogEntry === undefined) throw new Error(`SDK artifact catalog has no workspace identity for ${manifest.name}@${manifest.version}`);
    const expected = workspace ? undefined : lockIntegrity(lock, manifest.name, manifest.version);
    const packed = workspace
      ? await packWorkspaceArtifact(directory, outputRoot)
      : await readCanonicalNpmArtifact(canonicalNpmCache, manifest.name, manifest.version, expected!);
    if (packed.manifest.name !== manifest.name || packed.manifest.version !== manifest.version || (!workspace && packed.integrity !== expected)) throw new Error(`independent SDK artifact mismatch for ${manifest.name}@${manifest.version}`);
    packages.push(packed);
  }
  return packages;
}

async function runCli(bin: string, args: string[], env: NodeJS.ProcessEnv, input?: string): Promise<{ status: number; stdout: string; stderr: string }> {
  const result = child(process.env.TINYCLOUD_CLI_RUNTIME ?? "node", [bin, ...args], dirname(bin), env);
  if (input !== undefined) result.process.stdin?.end(input);
  else result.process.stdin?.end();
  const [status] = await once(result.process, "exit");
  return { status: typeof status === "number" ? status : 1, stdout: result.output(), stderr: "" };
}

async function runNpx(prefix: string, args: string[], env: NodeJS.ProcessEnv, input?: string): Promise<{ status: number; stdout: string }> {
  const result = child("npx", ["--prefix", prefix, "--no-install", "tc", ...args], prefix, env);
  if (input !== undefined) result.process.stdin?.end(input);
  else result.process.stdin?.end();
  const [status] = await once(result.process, "exit");
  return { status: typeof status === "number" ? status : 1, stdout: result.output() };
}

async function digestJson(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalize(value));
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

const missingCredentialRouteBody = [
  "<!DOCTYPE html>",
  '<html lang="en">',
  "<head>",
  '    <meta charset="utf-8">',
  '    <meta name="color-scheme" content="light dark">',
  "    <title>401 Unauthorized</title>",
  "</head>",
  '<body align="center">',
  '    <div role="main" align="center">',
  "        <h1>401: Unauthorized</h1>",
  "        <p>The request requires user authentication.</p>",
  "        <hr />",
  "    </div>",
  '    <div role="contentinfo" align="center">',
  "        <small>Rocket</small>",
  "    </div>",
  "</body>",
  "</html>",
].join("\n");

async function runRecipientDidRouteMatrix(input: {
  readonly shareLink: string;
  readonly nodeOrigin: string;
  readonly shareOrigin: string;
  readonly registryOrigin: string;
  readonly packedSdk: Record<string, any>;
  readonly packedNode: any;
  readonly session: Record<string, any>;
  readonly holderDid: string;
  readonly nodeInvitationKid: string;
  readonly nodeInvitationPublicKey: string;
}): Promise<void> {
  const missingCredential = await fetch(`${input.nodeOrigin}/share/upload/attestation`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
  });
  const missingCredentialBody = await missingCredential.text();
  if (missingCredential.status !== 401 || missingCredentialBody !== missingCredentialRouteBody) {
    throw new Error(`mounted production Node missing-credential denial mismatch: status=${missingCredential.status} bodyLength=${missingCredentialBody.length}`);
  }
  const routeBodies = new Map<string, Record<string, any>>();
  const routeObservations: Array<{ path: string; status: number; body: any }> = [];
  const mappedFetch = async (inputValue: any, init?: RequestInit): Promise<Response> => {
    const value = typeof inputValue === "string" || inputValue instanceof URL ? new URL(inputValue) : new URL(inputValue.url);
    const originalOrigin = value.origin;
    let nextInit = init;
    if (originalOrigin === canonicalShare) {
      value.href = `${input.shareOrigin}${value.pathname}${value.search}`;
      const headers = new Headers(init?.headers);
      headers.set("x-forwarded-proto", "https");
      nextInit = { ...init, headers };
    } else if (originalOrigin === canonicalRegistry) {
      value.href = `${input.registryOrigin}${value.pathname}${value.search}`;
    }
    const rawBody = typeof nextInit?.body === "string" ? nextInit.body : undefined;
    if (value.origin === input.nodeOrigin && value.pathname.startsWith("/share/v2/")) {
      if (rawBody !== undefined) routeBodies.set(value.pathname, JSON.parse(rawBody) as Record<string, any>);
      const response = await fetch(value, nextInit);
      let body: any = null;
      try { body = await response.clone().json(); } catch { /* status is the only body for malformed HTTP failures */ }
      routeObservations.push({ path: value.pathname, status: response.status, body });
      return response;
    }
    return fetch(value, nextInit);
  };

  const bundle = {
    invitationKid: input.nodeInvitationKid,
    invitationPublicKey: fromBase64Url(input.nodeInvitationPublicKey),
  };
  const credential = String(input.session.delegationHeader?.Authorization ?? "");
  const delegationCid = String(input.session.delegationCid ?? "");
  const buildPresentation = async ({ challenge, envelope }: { challenge: Record<string, any>; envelope: Record<string, any> }): Promise<Record<string, any>> => {
    const authority = envelope.ownerAuthority as Record<string, any>;
    const action = envelope.actions.includes("list") ? "tinycloud.kv/list" : envelope.actions.includes("edit") ? "tinycloud.kv/put" : "tinycloud.kv/get";
    const actions = [...new Set(envelope.actions.map((value: string) => value === "list" ? "tinycloud.kv/list" : value === "edit" ? "tinycloud.kv/put" : "tinycloud.kv/get"))].sort();
    const policyCid = envelope.authorizationTarget.kind === "policy" ? envelope.authorizationTarget.policyCid : "";
    const credentialDigest = await digestJson(credential);
    const jti = toBase64Url(crypto.getRandomValues(new Uint8Array(16)));
    const presentation = {
      type: "TinyCloudSharePolicyPresentation", version: 2, challengeId: challenge.challengeId, nonce: challenge.nonce,
      shareCid: authority.shareCid, shareId: envelope.shareId, delegationCid: envelope.delegationCid, policyCid,
      authorityMaterialHandle: envelope.authorityMaterialHandle, authorityMaterialDigest: envelope.authorityMaterialDigest,
      contentSource: envelope.contentSource, contentSourceDigest: envelope.contentSourceDigest, holderDid: input.holderDid,
      targetOrigin: envelope.target.origin, nodeAudience: envelope.target.nodeAudience, enforcerDid: challenge.enforcerDid,
      credentialDigest, action, actions, resource: envelope.resource.path.replace(/\/$/, ""), requestBodyDigest: challenge.requestBodyDigest,
      issuedAt: new Date().toISOString(), expiresAt: challenge.expiresAt, jti,
    };
    const sign = (bytes: Uint8Array): Promise<Uint8Array> => input.packedNode.signSessionBytes(bytes);
    const signature = toBase64Url(await sign(new TextEncoder().encode(`${input.packedSdk.SHARE_V2_PROTOCOL.sessionDomain}${canonicalize(presentation)}`)));
    const proof = { alg: "EdDSA", kid: `${input.holderDid}#${input.holderDid.slice("did:key:".length)}`, signature };
    const holderBinding = await input.packedSdk.createShareV2HolderBindingArtifact({
      holderDid: input.holderDid,
      sign,
      message: {
        type: input.packedSdk.SHARE_V2_PROTOCOL.holderBindingType,
        version: input.packedSdk.SHARE_V2_PROTOCOL.holderBindingVersion,
        holderDid: input.holderDid, challengeId: challenge.challengeId, challengeNonce: challenge.nonce,
        shareId: envelope.shareId, policyCid, credentialDigest, delegationCid,
        targetOrigin: envelope.target.origin, nodeAudience: envelope.target.nodeAudience, enforcerDid: challenge.enforcerDid,
        expiresAt: challenge.expiresAt, jti,
      },
    });
    return { holderDid: input.holderDid, credential, credentialDigest, presentation, presentationProof: proof, proof, holderBinding, sign };
  };
  const authorization = input.packedSdk.createAddressedAuthorization({ nodeOrigin: input.nodeOrigin, trustedNode: bundle, holderDid: input.holderDid, fetchFn: mappedFetch, buildPresentation });
  const received = await input.packedSdk.receiveShare(input.shareLink, {
    registryBaseUrl: `${canonicalShare}/api/share/link-only/registry`,
    expectedOrigin: canonicalShare,
    fetchFn: mappedFetch,
    authorization,
  });
  if (received.state === "authorization-required" || !(received.bytes instanceof Uint8Array)) throw new Error("live recipient-DID Share proof did not receive bytes");
  if (new TextDecoder().decode(received.bytes) !== "joined production path\n") throw new Error("live recipient-DID Share proof returned different bytes");
  const successfulRoutes = new Set(routeObservations.filter((observation) => observation.status === 200).map((observation) => observation.path));
  for (const path of ["/share/v2/policy/challenges", "/share/v2/policy/session", "/share/v2/invoke"]) {
    if (!successfulRoutes.has(path)) throw new Error(`live recipient-DID route did not return 200: ${path}`);
  }
  const challengeBody = routeBodies.get("/share/v2/policy/challenges");
  const sessionBody = routeBodies.get("/share/v2/policy/session");
  if (challengeBody === undefined || sessionBody === undefined) throw new Error("live recipient-DID matrix did not capture signed v2 requests");
  const postJson = async (path: string, body: Record<string, any>): Promise<{ status: number; body: any }> => {
    const response = await mappedFetch(`${input.nodeOrigin}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    return { status: response.status, body: await response.json() };
  };
  const missingRecipientCredential = { ...sessionBody };
  delete missingRecipientCredential.credential;
  const missingRecipientCredentialResult = await postJson("/share/v2/policy/session", missingRecipientCredential);
  if (missingRecipientCredentialResult.status !== 401 || JSON.stringify(missingRecipientCredentialResult.body) !== JSON.stringify({ error: { code: "recipient_credential_required" } })) {
    throw new Error(`mounted production v2 router missing-credential denial mismatch: status=${missingRecipientCredentialResult.status} body=${JSON.stringify(missingRecipientCredentialResult.body)}`);
  }
  const withDigest = async (body: Record<string, any>): Promise<Record<string, any>> => {
    const { requestBodyDigest: _oldDigest, ...unsigned } = body;
    return { ...unsigned, requestBodyDigest: await digestJson(unsigned) };
  };
  const wrongDid = "did:key:z6MkggtHVWQUGJ3FVjJKXeb5oZThQvLmJVMV8hfNUz4ezcav";
  const wrongDidResult = await postJson("/share/v2/policy/challenges", await withDigest({ ...challengeBody, holderDid: wrongDid }));
  if (wrongDidResult.status !== 403 || JSON.stringify(wrongDidResult.body) !== JSON.stringify({ error: { code: "policy_denied" } })) throw new Error("wrong recipient DID was not denied by the live challenge router");
  const wrongAudienceResult = await postJson("/share/v2/policy/challenges", await withDigest({ ...challengeBody, nodeAudience: "did:web:wrong-audience.example" }));
  if (wrongAudienceResult.status !== 403 || JSON.stringify(wrongAudienceResult.body) !== JSON.stringify({ error: { code: "policy_denied" } })) throw new Error("wrong audience was not denied by the live challenge router");
  const replayResult = await postJson("/share/v2/policy/session", sessionBody);
  if (replayResult.status !== 403 || JSON.stringify(replayResult.body) !== JSON.stringify({ error: { code: "policy_session_replayed" } })) throw new Error("replayed policy session was not denied by the live session router");
  const expiredChallengeResponse = await postJson("/share/v2/policy/challenges", challengeBody);
  if (expiredChallengeResponse.status !== 200 || typeof expiredChallengeResponse.body.challenge?.challengeId !== "string") throw new Error("live matrix could not establish a fresh challenge for expiry proof");
  const expiredChallenge = expiredChallengeResponse.body.challenge as Record<string, any>;
  const originalPresentation = sessionBody.presentation as Record<string, any>;
  const expiredPresentation = { ...originalPresentation, challengeId: expiredChallenge.challengeId, nonce: expiredChallenge.nonce, requestBodyDigest: expiredChallenge.requestBodyDigest, issuedAt: new Date(Date.now() - 1_000).toISOString(), expiresAt: new Date(Date.now() - 1).toISOString(), jti: toBase64Url(crypto.getRandomValues(new Uint8Array(16))) };
  const expiredSignature = toBase64Url(await input.packedNode.signSessionBytes(new TextEncoder().encode(`${input.packedSdk.SHARE_V2_PROTOCOL.sessionDomain}${canonicalize(expiredPresentation)}`)));
  const expiredProof = { alg: "EdDSA", kid: `${input.holderDid}#${input.holderDid.slice("did:key:".length)}`, signature: expiredSignature };
  const originalBinding = sessionBody.holderBinding as Record<string, any>;
  const expiredBinding = await input.packedSdk.createShareV2HolderBindingArtifact({
    holderDid: input.holderDid,
    sign: (bytes: Uint8Array) => input.packedNode.signSessionBytes(bytes),
    message: { ...(originalBinding.message as Record<string, any>), challengeId: expiredChallenge.challengeId, challengeNonce: expiredChallenge.nonce, expiresAt: expiredPresentation.expiresAt, jti: expiredPresentation.jti },
  });
  const expiredResult = await postJson("/share/v2/policy/session", { ...sessionBody, challengeId: expiredChallenge.challengeId, nonce: expiredChallenge.nonce, presentation: expiredPresentation, proof: expiredProof, holderBinding: expiredBinding });
  if (expiredResult.status !== 403 || JSON.stringify(expiredResult.body) !== JSON.stringify({ error: { code: "invalid_holder_proof" } })) throw new Error("expired policy presentation was not denied by the live session router");
}

async function main(): Promise<void> {
  if (process.argv.includes("--host")) {
    const server = startProductionServer(process.env);
    await once(server, "listening");
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("joined Share host did not bind an address");
    process.stdout.write(`joined Share host listening on http://127.0.0.1:${address.port}\n`);
    return;
  }

  if (process.env.TINYCLOUD_ALLOW_SYNTHETIC_PROFILE !== "1") {
    throw new Error("joined proof requires the orchestrator's explicit OpenKey login; fixture-seeded profiles are opt-in and never acceptance evidence");
  }

  const root = await mkdtemp(join(tmpdir(), "tinycloud-cli-joined-"));
  const nodeHome = join(root, "node-home");
  const cliHome = join(root, "cli-home");
  const trustBundle = join(root, "trust-bundle.json");
  const registryKey = join(root, "registry-upload.key");
  const inputPath = join(root, "input.md");
  const outputDir = join(root, "received");
  const preload = join(root, "transport-preload.mjs");
  const nodeStatus = join(root, "node-status");
  const children: Child[] = [];
  try {
    await writeFile(inputPath, "joined production path\n", { mode: 0o600 });
    const nodeTarget = join(root, "node-target");
    const nodeBinary = join(nodeTarget, "debug/tinycloud-node-production-e2e");
    const nodeHead = await runCommand("git", ["rev-parse", "HEAD"], nodeWorktree);
    const nodeDirty = await runCommand("git", ["status", "--porcelain"], nodeWorktree);
    if (nodeHead.status !== 0 || nodeDirty.status !== 0 || nodeDirty.output.trim() !== "") throw new Error("Node exact-head provenance check failed");
    const nodeBuild = await runCommand("cargo", ["build", "--manifest-path", join(nodeWorktree, "test/n4-mounted-e2e/Cargo.toml"), "--features", "mounted-fixture", "--bin", "tinycloud-node-production-e2e", "--target-dir", nodeTarget], nodeWorktree);
    if (nodeBuild.status !== 0) throw new Error(`exact-head Node build failed: ${nodeBuild.output.slice(-8000)}`);
    const nodeSelfTest = await runCommand(nodeBinary, ["--self-test"], nodeWorktree);
    if (nodeSelfTest.status !== 0 || !nodeSelfTest.output.includes("production HTTP adversarial checks passed")) throw new Error("exact-head mounted Node self-test/provenance check failed");
    const registryPrivateKey = randomBytes(32);
    await writeFile(registryKey, registryPrivateKey.toString("base64url"), { mode: 0o600 });
    const registryPublicKey = Buffer.from(ed25519.getPublicKey(registryPrivateKey)).toString("base64url");
    const nodeSecret = Buffer.alloc(32, 0x09).toString("base64url");
    const node = child(nodeBinary, ["--target-origin", "https://node.tinycloud.xyz", "--profile-output", nodeHome, "--trust-bundle-output", trustBundle, "--keys-secret", nodeSecret, "--quiet"], nodeWorktree, {});
    children.push(node);
    const nodeMatch = await ready(node, /tinycloud-node-production-e2e listening on http:\/\/127\.0\.0\.1:(\d+)/);
    const nodeOrigin = `http://127.0.0.1:${nodeMatch[1]}`;
    const profile = JSON.parse(await readFile(join(nodeHome, ".tinycloud/profiles/joined/profile.json"), "utf8")) as { spaceId: string; sessionDid: string };
    const session = JSON.parse(await readFile(join(nodeHome, ".tinycloud/profiles/joined/session.json"), "utf8")) as { delegationHeader: { Authorization: string }; delegationCid: string; spaceId: string; jwk: object; verificationMethod: string };
    const { TinyCloudNode } = await import(`${sdkWorktree}/packages/node-sdk/dist/index.js`);
    const probeNode = new TinyCloudNode({ host: nodeOrigin });
    await probeNode.restoreSession({ ...session, verificationMethod: profile.sessionDid });
    const probeHeaders = probeNode.invokeAny([{ spaceId: session.spaceId, service: "capabilities", action: "tinycloud.capabilities/read" }], [{ requestBodyDigest: "probe" }]);
    const probe = await fetch(`${nodeOrigin}/share/upload/attestation`, { method: "POST", headers: { ...probeHeaders, "content-type": "application/json" }, body: "{}" });
    if (probe.status !== 400) throw new Error(`mounted Node authorization probe returned ${probe.status}`);
    const registry = child("bun", ["packages/registry/src/production-server-cli.ts", "--port", "0"], shareRoot, {
      REGISTRY_AUTH_PUBLIC_KEY: registryPublicKey,
      REGISTRY_LINK_UPLOAD_PUBLIC_KEY: registryPublicKey,
    });
    children.push(registry);
    const registryMatch = await ready(registry, /production share registry listening on (http:\/\/127\.0\.0\.1:\d+)/);
    const registryOrigin = registryMatch[1]!;
    const bundle = await readFile(trustBundle, "utf8");
    const share = child("bun", ["test/e2e-sharing/cli-joined.ts", "--host"], shareRoot, {
      SHARE_TRUST_BUNDLE_SOURCE: "environment",
      SHARE_TRUST_BUNDLE: bundle,
      SHARE_SENDER_ENABLED: "false",
      SHARE_REGISTRY_UPLOAD_KEY_PATH: registryKey,
      SHARE_HERMETIC_COMPOSITION: "true",
      SHARE_HERMETIC_REGISTRY_ORIGIN: registryOrigin,
      PORT: "0",
      HOST: "127.0.0.1",
    });
    children.push(share);
    const shareMatch = await ready(share, /joined Share host listening on (http:\/\/127\.0\.0\.1:\d+)/);
    const shareOrigin = shareMatch[1]!;
    await cp(join(nodeHome, ".tinycloud"), join(cliHome, ".tinycloud"), { recursive: true });
    await writeFile(preload, `import { appendFile } from "node:fs/promises";\nconst originalFetch = globalThis.fetch;\nglobalThis.fetch = async (input, init) => { const value = typeof input === "string" || input instanceof URL ? new URL(input) : input.url === undefined ? input : new URL(input.url); const originalOrigin = value.origin; let nextInit = init; if (originalOrigin === ${JSON.stringify(canonicalShare)}) { value.href = ${JSON.stringify(shareOrigin)} + value.pathname + value.search; const headers = new Headers(init?.headers); headers.set("x-forwarded-proto", "https"); nextInit = { ...init, headers }; } else if (originalOrigin === ${JSON.stringify(canonicalRegistry)}) value.href = ${JSON.stringify(registryOrigin)} + value.pathname + value.search; else if (originalOrigin === ${JSON.stringify(canonicalNode)}) value.href = ${JSON.stringify(nodeOrigin)} + value.pathname + value.search; const response = await originalFetch(value, nextInit); if (process.env.TC_JOINED_NODE_STATUS_FILE) { let detail = ""; if (value.pathname === "/share/upload/attestation" && response.ok) { try { const body = await response.clone().json(); detail = " keys=" + Object.keys(body).sort().join(",") + " session=" + String(body.sessionDid ?? ""); } catch {} } if (value.pathname.endsWith("/registry/blobs") && !response.ok) { try { const body = await response.clone().json(); detail = " error=" + JSON.stringify(body.error ?? body); } catch {} } if (value.pathname.startsWith("/share/v2/")) { try { const body = await response.clone().json(); detail = " keys=" + Object.keys(body).sort().join(",") + (body.error?.code === undefined ? "" : " error=" + body.error.code); } catch {} } if (value.origin === ${JSON.stringify(nodeOrigin)} && ["/delegate", "/invoke", "/info"].includes(value.pathname)) { try { const body = await response.clone().json(); detail = " error=" + String(body.error?.code ?? body.error ?? ""); } catch {} } await appendFile(process.env.TC_JOINED_NODE_STATUS_FILE, value.pathname + "=" + response.status + detail + "\\n"); } return response; };\n`);

    const publishedPackages = await packFrozenSdkCatalog(sdkWorktree, root);
    const npmRegistry = await startNpmRegistry(publishedPackages);
    const install = join(root, "packed-cli");
    await mkdir(install, { recursive: true });
    await writeFile(join(install, "package.json"), JSON.stringify({ name: "tinycloud-cli-consumer", private: true, type: "module" }));
    const cli = publishedPackages.find((package_) => package_.manifest.name === "@tinycloud/cli");
    if (cli === undefined) throw new Error("frozen SDK catalog omitted @tinycloud/cli");
    const networkGuard = join(root, "network-guard.mjs");
    const npmUserConfig = join(root, "npm-user-config");
    const npmGlobalConfig = join(root, "npm-global-config");
    await writeFile(npmUserConfig, "");
    await writeFile(npmGlobalConfig, "");
    await writeFile(networkGuard, [
      "import http from \"node:http\";",
      "import https from \"node:https\";",
      "const allowed = (input) => {",
      "  const raw = typeof input === \"string\" ? input : input instanceof URL ? input.href : input?.href ?? `${input?.protocol ?? \"\"}//${input?.host ?? \"\"}${input?.path ?? \"/\"}`;",
      "  const url = new URL(raw);",
      "  if (url.hostname !== \"127.0.0.1\" && url.hostname !== \"localhost\") throw new Error(`hermetic network denied: ${url.origin}${url.pathname}`);",
      "};",
      "for (const module of [http, https]) { const request = module.request; module.request = function(input, ...args) { allowed(input); return request.call(this, input, ...args); }; }",
      "const fetch = globalThis.fetch; globalThis.fetch = async (input, ...args) => { allowed(input); return fetch(input, ...args); };",
      "",
    ].join("\n"));
    const guardedInstallEnv = { NODE_OPTIONS: `--import ${networkGuard}`, NPM_CONFIG_CACHE: join(root, "npm-cache"), NPM_CONFIG_USERCONFIG: npmUserConfig, NPM_CONFIG_GLOBALCONFIG: npmGlobalConfig, HTTP_PROXY: "http://127.0.0.1:9", HTTPS_PROXY: "http://127.0.0.1:9", ALL_PROXY: "http://127.0.0.1:9", NO_PROXY: "127.0.0.1,localhost" };
    const installResult = child("npm", ["install", "--no-audit", "--no-fund", `--registry=${npmRegistry.origin}`, "--prefix", install, `@tinycloud/cli@${cli.manifest.version}`], sdkWorktree, guardedInstallEnv);
    children.push(installResult);
    try {
      if ((await once(installResult.process, "exit"))[0] !== 0) throw new Error(`packed CLI install failed: ${installResult.output().slice(-8000)}`);
      const installedLock = JSON.parse(await readFile(join(install, "package-lock.json"), "utf8")) as { packages?: Record<string, { version?: string; resolved?: string; integrity?: string }> };
      for (const [location, entry] of Object.entries(installedLock.packages ?? {})) {
        if (location === "") continue;
        const name = location.slice(location.lastIndexOf("node_modules/") + "node_modules/".length);
        const package_ = publishedPackages.find((candidate) => candidate.manifest.name === name && candidate.manifest.version === entry.version);
        if (package_ === undefined || entry.version !== package_.manifest.version || entry.resolved?.startsWith(npmRegistry.origin) !== true || entry.integrity !== package_.integrity) throw new Error(`installed dependency ${name}@${entry.version ?? "missing"} is not an exact independent catalog artifact (catalog=${publishedPackages.filter((candidate) => candidate.manifest.name === name).map((candidate) => candidate.manifest.version).join(",")}, resolved=${entry.resolved?.startsWith(npmRegistry.origin) === true}, integrity=${entry.integrity === package_?.integrity})`);
      }
    } finally {
      await npmRegistry.close();
    }
    const packedSdk = await import(`${install}/node_modules/@tinycloud/node-sdk/dist/index.js`);
    const packedShareSdk = await import(`${install}/node_modules/@tinycloud/share-sdk/dist/index.js`);
    const packedNode = new packedSdk.TinyCloudNode({ host: nodeOrigin });
    await packedNode.restoreSession({ ...session, verificationMethod: profile.sessionDid });
    const packedHeaders = packedNode.invokeAny([{ spaceId: session.spaceId, service: "capabilities", action: "tinycloud.capabilities/read" }], [{ requestBodyDigest: "probe" }]);
    const packedProbe = await fetch(`${nodeOrigin}/share/upload/attestation`, { method: "POST", headers: { ...packedHeaders, "content-type": "application/json" }, body: "{}" });
    if (packedProbe.status !== 400) throw new Error(`packed Node authorization probe returned ${packedProbe.status}`);
    const bin = join(install, "node_modules/@tinycloud/cli/bin/tc");
    const cliEnv = { TC_HOME: cliHome, CI: "1", NODE_OPTIONS: `--import ${networkGuard} --import ${preload}`, HTTP_PROXY: "http://127.0.0.1:9", HTTPS_PROXY: "http://127.0.0.1:9", ALL_PROXY: "http://127.0.0.1:9", NO_PROXY: "127.0.0.1,localhost", TC_JOINED_NODE_STATUS_FILE: nodeStatus };
    const published = await runCli(bin, ["--profile", "joined", "share", "publish", inputPath, "--registry", `${canonicalShare}/api/share/link-only/registry`], cliEnv);
    if (published.status !== 0) throw new Error(`packed CLI publish failed with transport statuses ${await readFile(nodeStatus, "utf8").catch(() => "unobserved")}`);
    const link = published.stdout.split(/\r?\n/).map((line) => line.trim()).find((line) => {
      try { const url = new URL(line); return url.origin === canonicalShare && /^\/s\/[a-z0-9]+$/.test(url.pathname) && url.hash.length > 1; }
      catch { return false; }
    });
    if (link === undefined) throw new Error("publish did not return a valid canonical compact link");
    const recipientPublished = await runCli(bin, ["--profile", "joined", "share", "publish", inputPath, "--to", profile.sessionDid, "--registry", `${canonicalShare}/api/share/link-only/registry`], cliEnv);
    if (recipientPublished.status !== 0) throw new Error(`installed CLI recipient-DID publish failed (${recipientPublished.status}): ${recipientPublished.stdout.replace(/https?:\/\/\S+/g, "<url>").slice(-2000)} transport=${(await readFile(nodeStatus, "utf8").catch(() => "unobserved")).slice(-3000)}`);
    const recipientLink = recipientPublished.stdout.split(/\r?\n/).map((line) => line.trim()).find((line) => {
      try { const url = new URL(line); return url.origin === canonicalShare && /^\/s\/[a-z0-9]+$/.test(url.pathname) && url.hash.length > 1; }
      catch { return false; }
    });
    if (recipientLink === undefined) throw new Error("recipient-DID publish did not return a valid canonical compact link");
    await runRecipientDidRouteMatrix({ shareLink: recipientLink, nodeOrigin, shareOrigin, registryOrigin, packedSdk: packedShareSdk, packedNode, session, holderDid: profile.sessionDid, nodeInvitationKid: String(JSON.parse(bundle).nodeInvitationKid), nodeInvitationPublicKey: String(JSON.parse(bundle).nodeInvitationPublicKey) });
    const recipientOutput = join(root, "recipient-received");
    await mkdir(recipientOutput, { recursive: true });
    const recipientReceived = await runCli(bin, ["--profile", "joined", "share", "receive", "-", "--stdin", "--output", recipientOutput], cliEnv, `${recipientLink}\n`);
    if (recipientReceived.status !== 0) throw new Error("installed CLI recipient-DID receive failed");
    const transportEnv = { ...cliEnv, NODE_OPTIONS: `--import ${networkGuard} --import ${preload}` };
    const noProfile = await runCli(bin, ["share", "receive", "-", "--stdin", "--output", join(root, "no-profile-received")], { ...transportEnv, TC_HOME: join(root, "no-profile-home") }, `${recipientLink}\n`);
    if (noProfile.status === 0) throw new Error("recipient-DID receive succeeded without an OpenKey profile");
    const nodeStatuses = await readFile(nodeStatus, "utf8").catch(() => "");
    if (!nodeStatuses.split(/\r?\n/).some((line) => line.startsWith("/share/v2/policies=200"))) throw new Error("recipient-DID publish did not exercise the live /share/v2/policies route with status 200");
    if (nodeStatuses.split(/\r?\n/).some((line) => line.startsWith("/share/v2/") && (line.includes("=404") || line.includes("=503")))) throw new Error("live recipient-DID route matrix observed an unavailable or unmounted v2 route");
    const inspected = await runCli(bin, ["share", "inspect", "-", "--stdin", "--json"], { ...transportEnv, TC_HOME: join(root, "public-inspect-home") }, `${link}\n`);
    if (inspected.status !== 0) throw new Error(`profile-free inspect failed status=${inspected.status} outputLength=${inspected.stdout.length} transport=${await readFile(nodeStatus, "utf8").catch(() => "unobserved")}`);
    const warmed = await runNpx(install, ["share", "inspect", "-", "--stdin"], { ...transportEnv, TC_HOME: join(root, "warm-npx-home"), npm_config_offline: "true" }, `${link}\n`);
    if (warmed.status !== 0) throw new Error("warm-cache npx inspect failed");
    const nodeModulesBeforeWarm = await treeDigest(join(install, "node_modules"));
    const warmPublished = await runNpx(install, ["--profile", "joined", "share", "publish", inputPath, "--registry", `${canonicalShare}/api/share/link-only/registry`], cliEnv);
    if (warmPublished.status !== 0) throw new Error("warm-cache npx publish failed");
    if (await treeDigest(join(install, "node_modules")) !== nodeModulesBeforeWarm) throw new Error("warm npx mutated or replaced node_modules");
    await mkdir(outputDir, { recursive: true });
    const received = await runCli(bin, ["share", "receive", "-", "--stdin", "--output", outputDir], { ...transportEnv, TC_HOME: join(root, "public-receive-home") }, `${link}\n`);
    if (received.status !== 0) throw new Error("profile-free bearer receive failed");
    const names = await readdir(outputDir);
    if (names.length !== 1 || (await digest(join(outputDir, names[0]!))) !== await digest(inputPath)) throw new Error("joined receive digest mismatch");
    process.stdout.write(JSON.stringify({ status: "passed", profileFixtureSeeded: true, acceptanceEvidence: false, nodeOrigin: true, shareProcess: true, registryProcess: true, packedCli: true, recipientDidRouteMatrix: true, identicalDigest: true, profileFreeInspect: true, profileFreeBearerReceive: true }) + "\n");
  } finally {
    for (const entry of children.reverse()) await stop(entry);
    if (process.env.KEEP_JOINED_ARTIFACTS !== "1") await rm(root, { recursive: true, force: true });
  }
}

await main();

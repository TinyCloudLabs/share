# share.tinycloud.xyz — Viewer Site & Share Registry (v1 spec)

> Status: draft v1 · 2026-07-10 · Companion to `sharing-ux-blueprint.md` (mechanism) — this covers the viewer product and the registry service.
> Inputs: Codex design dialogue round 3 + primary-source research on Storacha/kubo/CID mechanics (July 2026).

## 1. Product shape

One static site, four modes, selected by what the visitor holds:

| Visitor holds | Mode |
|---|---|
| Nothing (bare URL) | **Landing** — product page + paste-a-share-link box (parsed locally, never POSTed or logged) |
| Share link → delegation over an **exact path**, read | **Document viewer** — franken-markdown-quality rendering: markdown + mermaid + syntax highlighting, self-contained, beautiful |
| Share link → delegation over a **prefix**, with list | **Folder browser** — clickable listing, click-through to the viewer per file |
| Delegation includes **write** (`kv/put`) | **Editor** — edit/preview split, saves write back through the recipient's session |

### Mode detection (decided)

UI mode derives from the **effective capabilities** — never from unsigned hints. For policy-target shares that's the intersection of the signed delegation and the embedded policy; for bearer and recipient-DID targets (envelope `authorizationTarget.kind != "policy"`) there is no policy to intersect and the delegation's capabilities stand alone. The viewer must switch on the discriminated `authorizationTarget` before anything else — it also decides which ceremony (none / sign-in / full claim) precedes content:

| Effective capability | UI |
|---|---|
| exact + `kv/get` | Single-file viewer |
| exact + `kv/get` + `kv/put` | Single-file editor |
| prefix + `kv/list` | Folder browser (names only) |
| prefix + `kv/list` + `kv/get` | Folder browser, readable files |
| prefix + `kv/list` + `kv/get` + `kv/put` | Folder browser, files open in editor |
| prefix + `kv/get`, **no** `kv/list` | No folder UI — only known exact paths retrievable |

Two envelope changes this requires:

1. A **signed, typed resource selector** — `{ kind: "exact" | "prefix", path }` — instead of inferring shape from trailing slashes or glob syntax.
2. Optional `display.mode` (`"document" | "source" | "folder"`) as a *presentation preference only*: it may narrow (open a writable file read-only at first) but never widen; when it disagrees with capabilities, capabilities win and the hint is ignored.

## 2. Client architecture

TypeScript/React/Vite static shell. Security-sensitive work is split deliberately:

- **Browser Web Crypto** for AES-256-GCM, SHA-256, randomness — do not ship a second general-purpose crypto implementation in WASM (WASM is fine for isolated parsers/highlighters; it is not a security boundary).
- **Shared TinyCloud SDK module** (same code as CLI/node where possible) for envelope signature verification, canonical policy bytes/CID checks, UCAN invocation + VP assembly, session invocation signing.
- **`multiformats`** for strict CID parsing and client-side `CIDv1(raw, sha2-256)` computation.
- **Unified/remark** GFM pipeline with **raw HTML disabled**; explicit rehype sanitation schema (+ DOMPurify as defense-in-depth).
- **Shiki** in a worker, grammars/themes/WASM bundled.
- **Mermaid** version-pinned, self-hosted, in a dedicated sandbox (§3).
- **CodeMirror 6**, lazy-loaded only when effective `kv/put` exists.

Hard rules:

- **No executable asset from a CDN.** App JS, workers, WASM, mermaid, sanitizer, grammars, editor, CSS, fonts — all bundled and pinned. OpenKey/OpenCredentials are framed services, not script providers.
- Strict CSP + Trusted Types + `Referrer-Policy: no-referrer`. Fragment key and session token are memory-only — never storage, never analytics. No analytics payload may contain links, CIDs, paths, or decrypted metadata.
- A static CSP can't allowlist an arbitrary decrypted `target.origin`; v1 constrains node origins to a deployment allowlist in `connect-src`, with the app additionally requiring exact match against the signed `target.origin`.

## 3. Hostile content pipeline

The privileged document holds the fragment key, the session token, and a signing interface — sender content is untrusted input and must never execute there. Sanitizer-only is insufficient; mermaid has a repeated XSS advisory history.

1. Markdown → AST with embedded HTML off; allowlist schema (headings, lists, tables, code, emphasis, safe links). Dangerous URL schemes rejected; remote images/embeds off by default (product question §9.2).
2. Mermaid source renders inside an **opaque-origin iframe**: `sandbox="allow-scripts"` *without* `allow-same-origin`, CSP `default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:`. It receives diagram text only — never keys, sessions, or the rest of the document. Mermaid `securityLevel: "strict"` runs *inside* this sandbox, not instead of it.
3. Returned SVG comes back over a narrow postMessage protocol, is sanitized **again** against an SVG allowlist, and the final document is placed in a scriptless sandboxed preview iframe.
4. DoS containment: source length, diagram count, render timeout, SVG node count, worker termination.

## 4. Editing semantics (new node API)

**No last-write-wins.** Optimistic concurrency:

- Every `get` returns an opaque version (content revision/CID or node generation token).
- Every save sends `expectedVersion`; the node compare-and-swaps atomically.
- Mismatch → `409` with the current version; the UI preserves the local draft, shows "Adam updated this file," and offers reload / manual reconcile / explicit overwrite (second confirmation + fresh version).
- Autosave is conditional too and halts on first conflict.

No automatic merge in v1. This is new node behavior: `tinycloud.kv/put` today has no versioned conditional-write contract — it must be specced alongside the claim protocol.

## 5. Folder listing semantics

Listing is a disclosure (names, hierarchy, sizes, mtimes). Decided:

- `tinycloud.kv/list` is an **explicit, independently attenuated ability** — prefix `kv/get` never implies enumeration.
- The **node** intersects delegation ∩ policy ∩ caveats ∩ requested prefix before listing; never the client.
- Responses: direct children only; name + type (size/mtime only if product-required); opaque scope-bound pagination cursors; outside-scope and missing-path errors normalized to block existence probing.
- A prefix delegation without `list` still serves agents that know exact paths.

## 6. Share registry v1 — decided: envelopes live on IPFS (single-uploader kubo we operate), edge front door

> Decision trail, kept honest: the round-3 engineering recommendation was a plain R2/S3 bucket (lowest ops, native lifecycle deletion). **Product owner decision (2026-07-11): the delegation envelope lives on IPFS.** These reconcile cleanly — the §6.2 single-uploader kubo posture *is* an IPFS store with real deletion, and because clients verify CIDs and we serve trustless-gateway-shaped responses either way, the only delta is operations: we run the node(s), and R2/CDN becomes an optional edge cache in front rather than the store of record. Storacha remains rejected as the default store (§6.1).

The envelope is addressed by `CIDv1(raw, sha2-256(ciphertext))` — the same identifier IPFS assigns the blob — so clients verify bytes regardless of who serves them, and additional mirrors are drop-ins. The v1 registry:

1. Compute `CIDv1(raw, sha2-256(ciphertext))` (base32, `bafkr…`, ~59 chars — `/s/<cid>` is fine; **no short aliases**: an alias strips the client's expected-CID byte-substitution check, and round 2's no-mutable-names rule stands).
2. Upload via an authenticated, rate-limited, create-only endpoint (`If-None-Match: *`; existing CID may succeed only on byte-identical content). Expected size 1–2 KB, conservative hard cap.
3. Store of record: our kubo blockstore. Ingestion is atomic, not fire-and-forget: **put (`ipfs block put --cid-codec=raw`) → assert returned CID == precomputed CID → pin → persist retention record** (CID, `deleteAfter`, uploader) — only then is the share URL returned to the sender. Ciphertext served through kubo's trustless gateway (`/ipfs/<cid>?format=raw`, `Content-Type: application/vnd.ipld.raw`) so IPFS-native clients (`@helia/verified-fetch`) work unchanged; the front door proxies/caches this (optional R2/CDN edge cache keyed by CID — explicit `Cache-Control` bounded by `deleteAfter`, purge-on-delete with retries, and bounded negative caching).
4. `/` and `/s/<cid>` serve the static viewer shell; agent discovery via content negotiation / `.well-known/tinycloud-share`.
5. Retention: untrusted, clamped `deleteAfter` sidecar; an expiry cron runs `ipfs pin rm` + `repo gc` at envelope expiry + grace period (product question §9.3), and purges any edge-cache copies. Object expiry is privacy hygiene, **never revocation** — the node remains the only revocation authority.
6. The **agent-link device-flow broker** is a separate short-lived-state service behind the same domain; it relays one-time approval/session references and must never receive fragment keys or VPs.
7. Claim notifications originate at the **node** (only it knows a root DID is new); a relay may share front-door infra but is not registry logic.
8. The registry never: lists envelopes, receives VPs, evaluates policies, issues sessions, or revokes.

### 6.1 Why not Storacha as the default store

Verified from Storacha's own docs (July 2026): `client.remove(cid, {shards:true})` removes content from *your account listing and billing* only, with a 30-day minimum retention; all data is backed into **Filecoin deals which Storacha renews indefinitely**; their docs state plainly — *"Do not use Storacha for data that may need to be permanently deleted in the future"* and *"only upload files that you know can be shared with anyone forever, or are securely encrypted."*

For most encrypted data, permanence is survivable via crypto-shredding (destroy the key). **Not here: the AEAD key is the URL fragment — it lives in every chat log that ever carried the link and can never be destroyed.** Permanent ciphertext therefore means invitation metadata (sender DID, recipient email, path, node origin) readable *forever* by anyone who ever held the link. That's the opposite of "share expires Aug 9."

Where Storacha *does* fit (growth path): an **opt-in "durable encrypted link"** for senders who explicitly want permanence, with a clear warning. Mechanics are ready when we want them: `@storacha/client` (the `@web3-storage/*` packages are legacy), UCAN-native upload authorization (Agent DID + Space DID + delegation with `space/blob/add`, `space/index/add`, `upload/add`, `filecoin/offer` — conceptually pleasant next to our stack), `storacha.link` gateway. One implementation note: a ≤256 KiB blob converges to the same `bafkr…` raw CID across js-multiformats, kubo, and Storacha, but Storacha doesn't *contract* that behavior — the uploader must assert returned CID == precomputed CID.

### 6.2 The single-uploader kubo posture (this is the v1 store)

**Can we run our own IPFS node that only we upload to?** Yes, cleanly — and per the product owner decision this is the v1 configuration:

- **Write path**: RPC API on localhost/Unix socket only, or kubo ≥0.25 `API.Authorizations` (per-caller bearer secrets + `AllowedPaths` limited to `/api/v0/block/put` etc.).
- **Read path**: `Gateway.NoFetch=true` (serve local repo only — never an open proxy), `Gateway.DeserializedResponses=false` (trustless-only: raw block/CAR responses).
- **No network participation**: `Routing.Type=none` — no DHT, no announcement; content reachable only via our gateway. (Breaks IPNS; irrelevant for immutable CIDs.)
- **Real deletion** (unlike Storacha): `ipfs pin rm` + `repo gc` on a cron keyed to envelope expiry.
- **HA**: skip IPFS Cluster (built for millions of pins; even Storacha moved off kubo+Cluster) — two kubo nodes with dual `block put` behind an LB is plenty.

**Ops posture, eyes open**: configured this way kubo is close to a plain object server, and we inherit its availability/upgrade/backup/abuse surface — that was the engineering argument for R2-first. Accepted trade (product owner call): the store is protocol-native IPFS from day one. Mitigations: two kubo nodes with dual `block put` behind an LB (skip IPFS Cluster — built for millions of pins), R2/CDN edge cache for read availability, and the upload service asserts `returned CID == precomputed CID` on every put.

### 6.2.1 Ops gaps to spec before build (from the round-4 gap review)

- **Deletion is a goal, not yet a guarantee**: the GC cron needs idempotent retries, a durable expiry queue, leader election (two nodes), and metrics — "cron ran" is not "bytes gone."
- **Backups vs deletion are in direct tension.** Decide one: no backups + replicated live nodes (deletion is real), or backups + bounded backup retention + tombstones honored on restore. Silent full backups quietly break the deletion promise.
- **Dual-node writes need semantics**: write-ack policy (both? quorum?) and replica repair for a missed put.
- **Upload abuse is economic/identity-based only** — blobs are encrypted, content moderation is impossible; the authenticated endpoint needs per-account quotas and anomaly controls.
- **Monitoring** — gateway availability, blockstore size vs retention ledger drift, GC lag, cache purge failures.

### 6.3 CID mechanics (locked)

- `CIDv1`, codec `raw` (0x55), `sha2-256`, canonical lowercase base32 (`bafkrei…`).
- Single block — envelopes are 1–2 KB, far under the 256 KiB chunking threshold; no UnixFS/dag-pb wrapping anywhere.
- js: `CID.create(1, raw.code, await sha256.digest(bytes))`. kubo: `ipfs block put --cid-codec=raw`. Hash the exact ciphertext bytes; no encoding drift.
- Clients always recompute the hash of received bytes against the URL's CID before decrypting.

## 7. Component/dependency list (viewer)

React + TypeScript + Vite · OpenKey SDK + TinyCloud web/credentials SDKs · Web Crypto · `multiformats` · shared envelope/UCAN/VP verification module · unified/remark (raw HTML off) + rehype sanitize schema + DOMPurify · mermaid (pinned, self-hosted, sandboxed) · Shiki (worker, bundled assets) · CodeMirror 6 (lazy) · Trusted Types + strict CSP + no-referrer · scriptless preview iframe · memory-only key/session state.

## 8. Decision record (this spec)

| # | Decision |
|---|---|
| 1 | UI mode derives from effective capabilities (delegation ∩ policy); envelope gains a signed `{kind: exact\|prefix, path}` selector; `display.mode` is a narrowing-only hint |
| 2 | TS/React static shell; Web Crypto + shared SDK for all authorization crypto; zero CDN-served executables |
| 3 | Hostile content: AST allowlist, raw HTML off, mermaid in opaque-origin sandbox, double-sanitized SVG, scriptless preview frame |
| 4 | Writes are conditional (expectedVersion CAS at the node); conflicts surface, drafts preserved; no silent LWW |
| 5 | `kv/list` is explicit and never implied by prefix `get`; node-side scope intersection; anti-probing error normalization |
| 6 | Registry v1 = **single-uploader kubo we operate** (product owner call 2026-07-11; supersedes the R2-first engineering recommendation) + edge front door with optional R2/CDN cache; expiry cron `pin rm` + `repo gc` at expiry+grace |
| 7 | Storacha rejected as default (indefinite Filecoin renewal + fragment-key-in-link kills crypto-shredding); offered later as opt-in durable links |
| 8 | Trustless-gateway response shape everywhere, so mirrors/caches are drop-ins and clients always verify bytes against the CID |
| 9 | Full-CID URLs; no short-alias layer |

## 9. Open product questions

1. Should write capability always expose the editor, or can the sender request read-only presentation despite granting write?
2. Remote images/outbound links in rendered markdown: allow (with privacy/phishing cost) or v1 data-URIs only?
3. Envelope retention grace after share expiry: immediate, 7 days, or 30 days?
4. Offer the explicit "durable encrypted link" (Storacha/IPFS-backed, permanence warning) — v1.x or never?
5. Conflict UX: expose force-overwrite at all, or require manual reconciliation before any save?
6. Folder metadata: names/types only, or sizes + modification times too?
7. Is full-CID URL length acceptable to marketing, or is a (necessarily immutable, digest-carrying) alias protocol worth designing?

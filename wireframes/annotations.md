# TinyCloud Sharing — Wireframe Annotations

Low-fi wireframes for the sharing experience (`../specs/sharing-ux-blueprint.md`).
Numbers match the black circle badges in each SVG.

## 01 — Viewer landing (`01-viewer-landing.svg`)

1. Bare front door at share.tinycloud.xyz — the hero states the product promise in one line.
2. Paste-a-link input: recipients who received a link out-of-band open it here; the `#k` fragment never leaves the browser.
3. Three trust blurbs: end-to-end verifiable · works with your agent · nothing stored unencrypted (the registry only sees ciphertext).
4. Sender acquisition path: "Share something yourself → Get started".

## 02 — Share landing, first-time recipient (`02-share-landing-first-time.svg`)

1. Verified sender header — rendered only after the client verifies the sender-signed envelope; trust runs both ways on a phishing-shaped object.
2. Invitation metadata (file name, sender) is visible pre-auth because Adam chose to send it; content never is.
3. Single primary action; the masked hint (b•••@gmail.com) comes from the envelope's `display.recipientHint`.
4. Expectation-setting before any popup: passkey → email code → ~30 seconds (mitigates passkey hesitancy, funnel risk §9.2).

## 03 — Combined ceremony: passkey + OTP (`03-ceremony-passkey-otp.svg`)

1. OpenKey passkey popup — key creation is one Face ID; copy sets expectations ("No password").
2. Email OTP — 6-digit code sent to the address in the policy; resend after 20s, magic-link fallback in the same email.
3. The claim page stays dimmed behind — the recipient experiences one continuous ceremony, not "sign up for a product, then do a second thing".
4. Behind the ✓, the client silently runs challenge → VP → claim and lands in a DID-bound session.

## 04 — Read-only viewer, single file (`04-viewer-single-file.svg`)

1. Trust header: filename, verified sender, read-only badge, expiry date, signed-in identity, and Download — always visible.
2. Rendered markdown includes diagrams — mermaid blocks render as figures with a caption, not raw text.
3. Code blocks render as-is; [Download] in the header fetches the original file.
4. Footer hint bridges to the agent flow (2b) — recipients discover the agent path without being taught.

## 05 — Viewer, folder mode (`05-viewer-folder.svg`)

1. Folder header: folder name + item count, same trust chrome as the single-file viewer.
2. Breadcrumbs track position inside the shared subtree — the delegation is scoped to exactly this share's folder (`shares/<shareId>/*`).
3. Clickable rows with size + type; files open in the preview pane, subfolders (notes/) drill in.
4. Preview pane renders the selected file with the same renderer as the single-file viewer.

## 06 — Viewer, edit mode (`06-viewer-editor.svg`)

1. A write delegation surfaces as [Save], "editing as bob@gmail.com", and an autosave/version indicator ("saved · v12").
2. Conflict strip (dismissible info style): sender edits never silently clobber — "Adam updated this file 2 min ago — refresh to see latest."
3. Plain-text editing pane; every save is a DID-signed write under Bob's session.
4. Live preview uses the same renderer as read-only mode, mermaid included.

## 07 — Share landing, returning recipient (`07-share-landing-returning.svg`)

1. Known recipient: the durable email credential means no OTP — the page recognizes the returning passkey account.
2. Single action: one Face ID re-runs challenge → session. Opening on a new device just repeats the claim — no re-share needed.
3. Fast-path budget: ~2 seconds from click to content.

## 08 — Agent-link approval, first-time user (`08-agent-link-approval-first-time.svg`)

1. First-timers run the full ceremony on this one page — steps 1–2 (passkey, email) completed inline, step 3 is consent.
2. The requesting agent is named with its host device — Bob approves a specific agent, not a blanket grant.
3. Attenuated scope stated plainly: read-only · this document only · 7 days renewable (default agent sub-delegation).
4. Code match is the anti-phishing binding (OAuth device-flow pattern): this browser session authorizes that agent.
5. Approve produces a Bob-signed sub-delegation to the agent DID → derived, shorter-lived session linked to Bob's claim.

## 09 — Agent-link approval, returning user (`09-agent-link-approval-returning.svg`)

1. Known user lands straight on consent — no step indicator, no OTP; identity row confirms who is approving.
2. The code-match binding is identical to first-time — never skipped.
3. Approve = one Face ID + one tap: two easy steps for the entire agent flow.

## 10 — Sender chat share (`10-sender-chat-share.svg`)

1. The agent states recipient + scope + expiry before Adam confirms — one decision covers everything (the sender's single consent moment).
2. Confirm is one tap: "Is that the right Bob?" catches the wrong-email failure mode at the cheapest possible moment.
3. The link carries the envelope CID + fragment key; Adam sends it over his own channel — TinyCloud never needs Bob's inbox for delivery, only verification.
4. "I'll tell you when Bob claims it" — the multi-claim guardrail surfaced as presence, not paranoia; revocation is one sentence away.

## 11 — First-time sender (`11-sender-first-time.svg`)

1. The agent doesn't inline sender setup — it hands off to the static signup site account.tinycloud.xyz and resumes the share afterwards (§13).
2. Signup means creating the owner key via OpenKey passkey (one Face ID) — the root DID every delegation chains from. Email verification is NOT part of signup; it's pulled in lazily at share time (§13).
3. Hosting choice at signup: TinyCloud hosted (pre-selected, works instantly) or self-hosted — point the account at your own tinycloud-node.
4. Agent-created accounts exist (CLI bootstrap) but are second-class — your account should be yours; an agent-created account can be claimed later.
5. Once the account is ready, the agent resumes with the exact share-confirm moment from screen 10: recipient + scope + expiry, one tap.

## 12 — CLI agent claim (`12-cli-agent-claim.svg`)

1. The CLI verifies the ciphertext CID, decrypts with `#k`, and verifies the sender signature before contacting anything — sender identity comes from the signed envelope.
2. Device-flow pivot: the agent surfaces a short agent-link + user code; everything share-specific stayed inside the encrypted envelope.
3. The agent blocks on human consent — 15-minute TTL on the code; no consent, no access.
4. Approval yields a Bob-signed, attenuated sub-delegation to the agent DID — the node never signs on Adam's behalf.
5. Content is fetched with agent token + agent-signed invocation per request; the token alone never authorizes.

## 13 — Claim notifications + manage sheet (`13-notification-claim.svg`, mobile)

1. First-claim-per-root-DID notification: Adam hears when each new device claims — no renewal spam (notification-fatigue guardrail).
2. Derived agent sessions are recorded under Bob's claim and notified as authorization events, not separate claimants.
3. Durable claim history: every root DID and derived agent session, visible to sender and recipient, each individually revocable.
4. Revocation acts at the enforcing node against the delegation CID — per-device, per-agent, or whole share. Deleting the registry blob is never revocation.

## 14 — Flow map (`14-flow.svg`)

1. Sender paths: known senders share in one confirm (10); first-time senders detour to account.tinycloud.xyz signup, then the agent resumes the share (11).
2. One link serves every recipient type — CID-addressed encrypted envelope in the registry, decryption key in the URL fragment.
3. The link is dual-audience: humans get the landing page, agents get machine instructions — the branch is simply "who opens it".
4. Human branches: full ceremony ≈30s first time (02 → 03), ~2s returning (07).
5. Agent branches always pass through device-flow approval (12 → 08/09) — agent access is never silent.
6. Every new root-DID claim and agent authorization notifies the sender (13); revocation lives at the node, not the registry.
7. The delegation decides the terminal mode: read-only file (04), folder (05), or editor (06).

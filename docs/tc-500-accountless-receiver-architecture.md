# TC-500 — accountless receiver architecture correction

## What changed, and why

The addressed-share receiver used to run through TinyCloud Node: the browser
called `/share/v1/invitations/authorize`, `/share/v1/policy/challenges`,
`/share/v1/policy/session`, and `/share/v1/read`. That put four things inside a
service that should hold none of them:

- credential presentation and verification;
- exact-email matching;
- the policy decision itself;
- a Share-specific session and the decrypted read.

It also meant Share could only ship if Node shipped a Share-shaped API. Node
`main` is generic and has no `/share/*` routes at all, so those calls answer 404
against current Node.

The corrected flow removes Node from every one of those roles:

```
recipient browser ── OpenCredentials  (email + OTP → vc+sd-jwt to an ephemeral key)
                 └── Policy Engine    (/policy/v0/challenge → /policy/v0/resolve)
                 └── TinyCloud Node   (/delegate → /invoke, ciphertext only)
                 └── local decrypt
```

Node is a generic capability and storage enforcer. It sees a UCAN it can verify
and a resource it can serve. It never sees a credential, an email address, a
policy decision, or a content key.

## Where the pieces live

| Concern | Home |
| --- | --- |
| ephemeral holder key, credential acquisition, presentation, delegation import, encrypted read, local decrypt | `@tinycloud/sdk-core/policy-access` |
| accountless holder admission and exact-recipient evidence | policy-engine, `spec/accountless-holder-binding.md` |
| Share's trusted configuration and receiver wiring | `src/email-share/policy-access.ts` |
| same-origin proxy for the two frozen engine routes | `src/host/upstream.ts` |

Share supplies configuration and vocabulary. It supplies no protocol: an
application that is not Share can drive the identical flow through the SDK, and
`examples/policy-access-reader` in the js-sdk repo is exactly that.

## Configuration

`SharePublicConfig` names the canonical Node origin and its public credential
issuer key. The browser sends policy admission only to that Node origin at
`/policy/v3/*`; Share does not configure, proxy, or trust a policy origin.

## What is deliberately unchanged

- **Bearer / link-only sharing is a separate mode** and is untouched. It has no
  policy engine, no credential, and no recipient identity by design.
- The legacy `/share/v1|v2|v3` proxy routes still exist in `upstream.ts`. They
  are dead against Node `main` and are not used by the corrected receiver; they
  are scheduled for removal once the accountless receiver is the default, so
  that this change does not couple an architecture correction to a rollout
  cutover.
- No credential, signature, nonce, replay, audience, expiry, exact-resource, or
  proof-of-possession check was relaxed anywhere. The SDK adds caller-side
  guards *on top of* the engine's, and the engine's accountless admission is
  strictly narrower than its enrolled-agent path.

## What is proven, and what is not

Being precise about this matters more than the design description above, because
the previous iteration of this document described a flow that had never been
executed anywhere.

**Proven against real processes.** `npm run test:e2e:policy-engine-publish`
boots the real `policy-engine-http` binary and runs Share's own sender code
against it over HTTP. It proves the sender→engine hop end to end: the three
owner-signed objects are the bytes the Rust engine accepts, the engine commits
them, a challenge for the published policy then succeeds and is bound to the
engine's audience with a replay nonce, re-publishing an unchanged share is
idempotent, and an owner that has not enrolled this engine's grant issuer is
refused with `policy_engine_record.grant_issuer_authority`. No mock stands on
either side of that boundary.

**Proven by unit tests only.** `readAccountlessShare` and the accountless
receiver's admission rules, engine-trust pinning, holder freshness, and egress
pinning. The engine, issuer, and node are stubbed transports in those tests.

**Not proven.** The joined delivered-email browser trace — real invitation email
→ OTP → direct engine presentation → generic `/delegate` + `/invoke` →
ciphertext → local decrypt → render — has not been run. Two things still block
it:

1. **The sender does not emit `policyEngine` into the envelope yet.** The
   composer still registers its policy on the node's `/share/v3/policies` and
   builds the v3 envelope around that registration. Until it publishes to the
   engine instead and signs the binding in, the accountless route in `main.ts`
   is reachable but never selected.
2. **The body is encrypted to a TinyCloud encryption network, not to a
   locally-held content key.** The accountless receiver decrypts in the tab, so
   it needs a wrapped content key carried in the sealed envelope. Today the
   ciphertext can only be opened by asking the node to decrypt it, which is
   exactly the role this correction removes from the node.

Both are sender-side changes in `src/share/composer.ts`. Neither is blocked by
an external artifact or authority; they are simply not done.

## Rollout order

1. **Node** — embedded accountless policy admission and exact-email evidence.
   Deploy first: nothing downstream works without it.
2. **js-sdk** — `@tinycloud/sdk-core/policy-access`. Publish second; it is a new
   entry point and adds no behaviour to existing ones.
3. **share** — this change. Ship third, using the Node-owned `/policy/v3/*`
   admission contract.

Rollback is disabling accountless receiving at the Node/SDK rollout gate.

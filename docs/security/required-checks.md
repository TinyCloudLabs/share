# Required checks on `main` (ruleset spec)

Spec for Amos, who applies it. Agents don't change repository settings.
Owners: Bobbie (security: `sdk-tests`, `worker-tests`, `gitleaks`), Clarissa (QA: `smoke`).

## Checks

| Context (job name) | Workflow | Runs on | What it proves |
|---|---|---|---|
| `sdk-tests` | `share-sdk.yml` | every PR, push to main | typecheck, vitest (CSP, privacy, user-content origin), `npm run build:deploy` (which runs `scripts/audit-dist.mjs`: no source maps, file-type allowlist, key/token patterns, `gitleaks dir dist`), production origin contract |
| `worker-tests` | `links-api.yml` | every PR (skips inside when no `worker/links-api/**` path changed), push to main | links-api Worker typecheck and tests (`read-auth.test.ts`) |
| `gitleaks` | `gitleaks.yml` | every PR (PR commits only), push to main (full history against `.gitleaksignore`) | no secret in the PR's commits |
| `smoke` | `sender-signin-smoke.yml` | every PR (candidate build), push to main, daily | a throwaway account signs in to Share against production OpenKey and Node, shares, and reads back |

All four are GitHub Actions check runs (`integration_id` 15368).
`sender-encrypted-share-smoke.yml` also has a job named `smoke`, but it runs only on push to main, so a pull request only ever sees the sign-in smoke.

### Preconditions (Naomi's rule: required only after a pass on main)

- Stage 1 (`sdk-tests`, `worker-tests`, `gitleaks`): after this PR merges and all three pass on the merge commit on main. `sdk-tests` already passes on main (66c082df). `worker-tests` and `gitleaks` get their first always-run main pass from this PR's merge.
- Stage 2 (`smoke`): after `smoke` passes on a main commit (it did on 66c082df, run attempt 2, 2026-11-22 09:54Z; attempt 1 and the 06:31Z schedule failed) **and** the Share smoke lead (agent 11c34b62) has been told, before the update is applied.
  `smoke` depends on production OpenKey, Node and the QA mail inbox: an outage there blocks every merge. The admin bypass below is the emergency override; the alternative is to remove `smoke` from the list (stage 2 undo).
  Fork PRs don't get the smoke's secrets, so they can't pass it; an admin bypass merge or a same-repository branch is the way in for outside contributions.

## Before (2026-11-22, read-only)

```
$ gh api repos/TinyCloudLabs/share/rulesets
[]
$ gh api repos/TinyCloudLabs/share/branches/main/protection
{"message":"Branch not protected", ... "status":"404"}
$ gh api orgs/TinyCloudLabs/rulesets
[]
```

Nothing protects `main`: anyone with write access can push directly, and Cloudflare Pages deploys every push to production.

## After, stage 1 (create)

`gh api -X POST repos/TinyCloudLabs/share/rulesets --input stage1.json`, with `stage1.json`:

```json
{
  "name": "main: PR and required checks",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "bypass_actors": [
    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request" }
  ],
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": false,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": false,
        "allowed_merge_methods": ["merge", "squash", "rebase"]
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "do_not_enforce_on_create": false,
        "required_status_checks": [
          { "context": "sdk-tests", "integration_id": 15368 },
          { "context": "worker-tests", "integration_id": 15368 },
          { "context": "gitleaks", "integration_id": 15368 }
        ]
      }
    }
  ]
}
```

- `actor_id` 5 is the repository Admin role. `bypass_mode: pull_request` lets an admin merge a pull request whose checks fail (the emergency override), but not push to `main` without one.
- Review count is 0, so the change is "every commit reaches main through a PR with green checks", not a new review gate.
- Record the returned `id` as `RULESET_ID`.

## After, stage 2 (add `smoke`)

`gh api -X PUT repos/TinyCloudLabs/share/rulesets/$RULESET_ID --input stage2.json`, where `stage2.json` is `stage1.json` with one more entry in `required_status_checks`:

```json
{ "context": "smoke", "integration_id": 15368 }
```

## Undo

- Stage 2: `gh api -X PUT repos/TinyCloudLabs/share/rulesets/$RULESET_ID --input stage1.json`.
- Stage 1: `gh api -X DELETE repos/TinyCloudLabs/share/rulesets/$RULESET_ID` (back to "Before"), or set `"enforcement": "disabled"` with a PUT to keep the definition.

## Verify

```
gh api repos/TinyCloudLabs/share/rules/branches/main --jq '.[].type'
# deletion, non_fast_forward, pull_request, required_status_checks
```

A direct `git push origin main` from a non-admin is then refused, and a PR shows the required checks.

## Limit: the Cloudflare Pages deploy

The Pages projects `share` and `share-usercontent` build `main` through the Cloudflare Git integration, not a GitHub job, so a ruleset gates what reaches `main`, and the audit in `build:deploy` / `build:usercontent` fails the Cloudflare build on a finding. Neither makes Cloudflare wait for the GitHub checks. Moving Cloudflare production to a `production` branch pushed only after green (the tinychat pattern) is a later item.

## gitleaks baseline

`.gitleaksignore` lists the 154 fingerprints of the full-history scan at 66c082df (gitleaks 8.30.1) that remain after `.gitleaks.toml` drops `did:key` identifiers (public keys). Reviewed 2026-11-22; none is a live credential:

| Files | Rule | Why it's safe |
|---|---|---|
| `test/vectors/email-claim-v1/{positive,negative}.json`, `loader.ts` | generic-api-key | deterministic email-claim test vectors (`credentialDigest`, `claimSecret`, `reportAbuseToken`, `envelopeKey` from fixed test seeds) |
| `test/fixtures/legacy-share-worlds.json` | generic-api-key, jwt | "TEST ONLY, throwaway keys" fixture; UCANs issued by test `did:key`s over `tinycloud:test-space` |
| `test/fixtures/tc-405-compact-authorization.json` (deleted) | jwt | test UCANs between test `did:key`s, expired 2026-07-31 |
| `test/fixtures/links-api-vectors.json`, `worker/links-api/test/vectors/short-links-api-vectors.json` | generic-api-key | links-api test vectors (`secretSha256` of a test value, test `did:key`s) |
| `test/composer-*.test.ts`, `test/sharing-composer*.test.ts`, `test/tc1741-custom-expiry.test.ts` | generic-api-key | `openKeyAddress`: test Ethereum addresses (public) |
| `test/library-renewal-candidate.test.ts`, `test/e2e-sharing/failure-diagnostic.test.mjs`, `test/apps-run-session.test.ts`, `test/fixtures/courier-seed/seed.ts` | generic-api-key | named synthetic values (`syntheticKey`, `FAKE_AUTH_DIGEST`) and test `did:key`s |
| `.release-evidence/*.json`, `test/e2e-prod/native-stack.mjs`, `test/e2e-email/integration.mjs` | generic-api-key | commit and deployment digests of OpenCredentials and Node (public pins) |
| `.github/workflows/share-api-docker-smoke.yml` (deleted) | generic-api-key | container image reference and the production policy enforcer `did:key` (public) |

A new finding fails `gitleaks`. If it is a real secret, revoke it and tell security; don't list it. If it is safe, add its fingerprint with the reason in the PR.

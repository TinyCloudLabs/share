# Required checks on `main` (ruleset spec)

Spec for Amos, who applies it. Agents don't change repository settings.
Owners: Clarissa (QA: `sdk-tests`, `smoke`), Bobbie (security: `worker-tests`, `gitleaks`, and the audit inside `sdk-tests`).

## Checks

| Context (job name) | Workflow | Runs on | What it proves |
|---|---|---|---|
| `sdk-tests` | `share-sdk.yml` | every PR, push to main | typecheck, vitest (CSP, privacy, user-content origin), `npm run build:deploy` (which runs `scripts/audit-dist.mjs`: no source maps, file-type allowlist, key/token patterns, `gitleaks dir dist`), production origin contract |
| `worker-tests` | `links-api.yml` | every PR (skips inside when no `worker/links-api/**` path changed), push to main | links-api Worker typecheck and tests (`read-auth.test.ts`) |
| `gitleaks` | `gitleaks.yml` | every PR (PR commits only), push to main (full history against `.gitleaksignore`) | no secret in the PR's commits |
| `smoke` | `sender-signin-smoke.yml` | every PR (candidate build), push to main, daily | a throwaway account signs in to Share against production OpenKey and Node, shares, and reads back |

All four are GitHub Actions check runs (`integration_id` 15368).
`sender-encrypted-share-smoke.yml` also has a job named `smoke`. It runs only on push to main and on dispatch, but on main it can shadow the sign-in `smoke` under the same check name. The Share smoke lead's Terms-click PR renames it to `encrypted-smoke`.

### Preconditions (Naomi's rule: required only after a pass on main)

- Stage 1 (`sdk-tests`, `smoke`; Clarissa's request, Naomi OK 09:50Z): both have passed on main commit 66c082df. `sdk-tests` passed. `smoke` passed on run attempt 2 at 09:54Z; attempt 1 and the 06:31Z schedule failed. Before applying, tell the Share smoke lead (agent 11c34b62).
  `smoke` depends on production OpenKey, Node and the QA mail inbox, so an outage there blocks every merge. The emergency override is the admin bypass below. The alternative is to drop `smoke` from the list.
  Fork PRs don't get the smoke's secrets, so they can't pass it. Outside contributions come in through an admin bypass merge or a same-repository branch.
- Stage 2 (adds `worker-tests`, `gitleaks`): after this PR merges and both pass on the merge commit on main. That merge is their first always-run pass on main.
- **Hold (Naomi, 10:15Z): apply stage 1 only after the Share smoke lead's Terms-click PR is merged on main.** That PR renames the encrypted job from `smoke` to `encrypted-smoke` and makes the sign-in smoke click through OpenKey's Terms. Without it:
  - the required `smoke` can be shadowed by the encrypted job of the same name;
  - `smoke` goes red on every PR once OpenKey turns Terms back on.

  After that merge, check that `smoke` and `sdk-tests` both pass on the merge commit, then apply.

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
          { "context": "smoke", "integration_id": 15368 }
        ]
      }
    }
  ]
}
```

- `actor_id` 5 is the repository Admin role. `bypass_mode: pull_request` lets an admin merge a pull request whose checks fail (the emergency override), but not push to `main` without one.
- Review count is 0, so the change is "every commit reaches main through a PR with green checks", not a new review gate.
- Record the returned `id` as `RULESET_ID`.

## After, stage 2 (add `worker-tests`, `gitleaks`)

`gh api -X PUT repos/TinyCloudLabs/share/rulesets/$RULESET_ID --input stage2.json`, where `stage2.json` is `stage1.json` with two more entries in `required_status_checks`:

```json
{ "context": "worker-tests", "integration_id": 15368 },
{ "context": "gitleaks", "integration_id": 15368 }
```

## Undo

- Stage 2: `gh api -X PUT repos/TinyCloudLabs/share/rulesets/$RULESET_ID --input stage1.json`.
- `smoke` only (outage): PUT `stage1.json` (or `stage2.json`) without the `smoke` entry.
- Stage 1: `gh api -X DELETE repos/TinyCloudLabs/share/rulesets/$RULESET_ID` (back to "Before"), or set `"enforcement": "disabled"` with a PUT to keep the definition.

## Verify

```
gh api repos/TinyCloudLabs/share/rules/branches/main --jq '.[].type'
# deletion, non_fast_forward, pull_request, required_status_checks
```

A direct `git push origin main` from a non-admin is then refused, and a PR shows the required checks.

## Limit: the Cloudflare Pages deploy

The Pages projects `share` and `share-usercontent` build `main` through the Cloudflare Git integration, not a GitHub job, so a ruleset gates what reaches `main`, and the audit in `build:deploy` / `build:usercontent` fails the Cloudflare build on a finding. Neither makes Cloudflare wait for the GitHub checks. Moving Cloudflare production to a `production` branch pushed only after green (the tinychat pattern) is a later item.

## Deploy credentials and previews (Naomi's ruling, 2026-11-22 10:05Z)

Deploy tokens live only in main-limited `production` environments; PR and branch previews are build-only.

Before, read from GitHub on 2026-11-22 (names only):

- No Cloudflare Pages token is in GitHub. Both Pages projects build through the Cloudflare Git integration.
- Environment `production`: branch policy is `main` only. It holds `CLOUDFLARE_TUNNEL_TOKEN`, `PHALA_CLOUD_API_KEY` and `PHALA_SHARE_API_CVM_ID`, plus four non-secret pins. No current workflow names `environment: production`; these belonged to the removed share-api deploy.
- Repository secrets: `QA_MAIL_ADDRESS_SECRET` and `QA_MAIL_READ_TOKEN`. `smoke` reads them on `pull_request`, so any same-repository branch can read them. They are QA mailbox credentials, not deploy tokens.
- Organization secrets visible to this repository: `NPM_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`. Every workflow on every branch can read `NPM_TOKEN`. Share publishes nothing to npm.
- Cloudflare previews: `share` builds every pushed branch. Branch `ci/prerelease-security-check` got a `Cloudflare Pages: share` check run on push, before it had a PR. Each preview runs that branch's own build scripts and publishes a public `pages.dev` URL. `share-usercontent` posted no check run for the branch [INFERENCE: its branch previews are off or restricted]. I couldn't read the Pages build variables (no CF API).

The build reads only public values:

- `VITE_USER_CONTENT_ORIGIN`, `VITE_SHARE_ORIGIN`, `VITE_OPENKEY_ORIGIN`, `VITE_LINKS_API_ORIGIN`, `VITE_ONE_BUILD`, `VITE_SHARE_HERMETIC`, `VITE_SHARE_VIEWER_HERMETIC`;
- `COURIER_DEV_NODE`;
- `USER_CONTENT_VIEWER_ORIGIN`.

It needs no secret, so a preview build is already build-only as long as the Pages variables hold nothing secret.

Turning previews off doesn't affect any check (checked 2026-11-22 for Naomi):

- **PR `smoke`** (`sender-signin-smoke.yml`) never opens a preview URL. On `pull_request` it runs `npm run build:deploy`, sets `SHARE_SMOKE_CANDIDATE=dist`, serves `dist` on 127.0.0.1 over a throwaway certificate, and maps `share.tinycloud.xyz` to that server inside the runner's Chrome (`--host-resolver-rules`, `test/e2e-prod/sender-signin-smoke.mjs:186-192`).
- **Push-to-main `smoke`** and **`sender-encrypted-share-smoke`** wait for the *production* `Cloudflare Pages: share` check. `.github/scripts/pages-check-state.mjs` explicitly ignores preview check runs (those whose summary has "Branch Preview URL"). They then test `https://share.tinycloud.xyz`.
- No workflow or test reads a `*.share*.pages.dev` URL. `pages.dev` appears only in tests asserting a production build names none.

After (Amos):

1. Cloudflare, both projects, Settings, Builds: set "Preview branches" to *None*, or to *Custom* with include `main` only once production moves to a `production` branch. Check that the Preview and Production build variables hold only the public values above.
2. GitHub: remove `share` from the repositories that can read the org secret `NPM_TOKEN`.
3. Optional, needs an owner decision: delete the unused `production` environment secrets (`CLOUDFLARE_TUNNEL_TOKEN`, `PHALA_CLOUD_API_KEY`), or keep them main-only as they are.

Undo:

1. Set "Preview branches" back to *All non-Production branches*.
2. Add `share` back to `NPM_TOKEN`'s repository list.
3. Deleted secrets can't be restored; re-create them from the source of truth. That is why step 3 needs an owner decision.

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

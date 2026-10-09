# Runbook: the settings only a maintainer can change

The library verifies and alerts. These settings enforce. Each item says what to do, why, and what it unlocks.

1. **Create a GitHub App for the judge** (name e.g. `tengoku-judge`). Repository permissions: *Checks: read & write* only. Install it on
   `tengoku` and `tengoku-sandbox` only. Store its App id and private key as repository secrets `JUDGE_APP_ID` and `JUDGE_APP_KEY`.
   Unlocks: the `merge eligibility` check run (`warden eligibility`), which is bound to the App so no other identity can forge it.
   Until then the trust-shadow job may use the Actions identity (App id 15368) and is advisory.
2. **Pin required checks to the App that produces them.** In each repository's ruleset, set `integration_id` on every required status
   check (`pr-gate`, `queue-gate`, and later `scope` and `merge eligibility`). Why: a required check without an integration id can be
   set by any identity with write access (Tau Ceti's own `build` and `bump-guard` are in this state).
3. **Add `non_fast_forward` and `deletion` rules** to the ruleset covering the `trust-ledger` and `ci-records` branches, and make
   pushes there come only from the Actions identity. Why: append-only is a rule, not a convention.
4. **Make `scope` a required check** once the sandbox has run it on a few PRs (`docs/agent-security.md` in the sandbox).
5. **Turn on org-wide Actions policy**: allow only actions pinned to a full commit SHA; set the default `GITHUB_TOKEN` to read-only.
6. **Rotate `CLAUDE_CODE_OAUTH_TOKEN`** after the first run of the jailed agent, and prefer an API key with a spend limit in the
   provider console if you want the credential held by the auth proxy and never by the agent.
7. **Dedicated bot account** `tengoku-bot` with no admin rights; its token (`TENGOKU_BOT_TOKEN`) fine-grained to the one repository.
8. **Review `docs/STATUS.md`** and decide when each advisory check becomes required.

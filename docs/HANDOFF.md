# Handoff: using the warden and the trust program in the maintainer's workflow

For the engineer (human or AI session) who takes this into the daily workflow. Everything here was verified by reading code or by a
test unless it says **not verified**. Start with `docs/STATUS.md` (what is wired where) and `SECURITY.md` (what is not solved).

## The pieces and where they live (all public, Apache-2.0, stdlib Python)
| Repo | Role | Commit at handoff |
| --- | --- | --- |
| competemath/tengoku-warden | Agent security toolkit: tool sets, jail, escape battery, secret scan, scope, caps, audit, auth proxy, eligibility check | `ca35675` |
| competemath/tengoku-juridicator | The judge: deterministic statute, scrutiny tiers, ledger, signatures, AI as a one-way valve | `ce5e87f` |
| competemath/tengoku-wounder | Tests our own gates: planted-defect canaries (Lean content and agent guards), audit lottery | `778d2bf` |
| competemath/tengoku-praiser | Falsifiable reasons to trust: Jinshi and checker results as evidence, provenance, track record, trust card | `c8c53d2` |
| competemath/jinshi | Soundness examinations (kernel replays, mutants, entailed, necessity ...) | `789ba13` |
Open PRs that wire them in: emissary-archangel #10; tengoku-sandbox #412, #413, #414. #411 (shadow trust verdicts) is merged.

## A. As a harness around Claude (any agent we run)
Use these in this order; each is independent.
1. **Tool set, not deny-list.** Build the Claude argv with `warden.toolpolicy.claude_args(policy)` and validate it with
   `check_claude_argv`. A deny-list (`--disallowedTools`) or `--allowedTools` alone leaves every other built-in tool reachable (Tau Ceti's
   reviewer had Bash for about 79 days this way). `python3 -m warden toolpolicy scan-source <file>` fails any spawn site in your own code
   that does it; wire that as a unit test. Reference implementation: emissary-archangel PR #10, `public/local-claude-bridge.mjs`
   (`claudeToolArgs`, `agentEnv`) and `scripts/agent-tests/test_bridge_tools.py`.
2. **Environment from an allowlist** (`envscrub.build_env`). The agent's process should hold the model credential and nothing else.
3. **Untrusted text is fenced, and the verdict is one-time-marked and schema-validated**: `warden.untrusted.build_prompt` and
   `warden.verdict.parse`. Anything an agent reads that a stranger wrote (source docstrings, PR text, comments) goes in a fence.
4. **Caps**: `--max-turns`, `--max-budget-usd` per run (`caps.Budget` for day/case budgets with a hash-chained ledger).
5. **Jail**: separate unprivileged user, per-user egress rules, escape battery before launch (`warden selftest`, 34 probes, fails closed).
   Reference: `translate.yml` and `agent-selftest.yml` in PR #10 (33 of 33 probes denied on a real runner after fixes).
6. **After the run**: `toolpolicy.audit_trace_claude` over the stream-json trace; any tool outside the policy fails the run and nothing it
   produced is banked. Secret-scan everything the agent will publish (`secretscan`, `sanitize`).
**Not verified:** the exact Claude CLI behaviours that need an API call (empty `--tools=` value, the tool names a session reports,
`--max-turns`). The first real run's `trace-report.json` shows the truth; the trace gate fails closed on names it has not seen.
**Credential honesty:** with an OAuth subscription token the agent holds the token (the auth proxy preset is for API-key mode).
The per-user egress allowlist limits where it can send it.

## B. As the review juridicator on automated translation ingestion, armed with Jinshi
The flow today: translate shards bank verified records -> `bank-flush` opens PRs into competemath/tengoku as `tengoku-bot` -> `pr-gate`
and the merge queue (Leak IV, Archangel, build, axioms) decide. The juridicator adds a judgement on top, in shadow first.
1. **What exists and is live** (sandbox PR #411): after `pr-gate` finishes on a PR, `trust-shadow.yml` gathers evidence (content lint,
   sorry scan, check runs), the juridicator decides under `scripts/ci/trust-shadow-policy.json`, the praiser's trust card goes to the run
   summary, one verdict is appended to the `trust-ledger` branch. Label cases later with the `trust-label` workflow; track records and
   precedents come only from labels.
2. **Arm it with Jinshi** (the main piece still to build): add a job that runs Jinshi on the PR's candidate modules (the repo already has
   `scripts/ci/jinshi_check.py`/`jinshi-pr.yml` on draft sandbox PR #410: compile in the sealed step, one `tengoku-jinshi` process per
   module) and converts its findings with `praiser.merit.from_jinshi` into `mechanical.jinshi.<check>` evidence (declare a manifest first;
   a check that did not run is `not_run`, never a pass). The kernel replays (leanchecker, lean4lean, nanoda) become one
   `mechanical.kernel_check` record per checker via `merit.from_checkers`, so independence is countable. Add those kinds under `required`
   for the `content` and `native` classes in the shadow policy and raise `min_independent_checkers` to what you can actually run.
3. **Turn it into a gate gradually**: shadow (now) -> label every merged and every ejected PR for a few days -> compare -> publish the
   `merge eligibility` check (sandbox PR #413, `warden eligibility`) -> make it required only when its false-reject rate on labelled data
   is acceptable. The judge's App identity (see `docs/RUNBOOK.md`) is what makes that check unforgeable; until then it is made by the
   Actions identity. Never make a model's output the thing that approves: AI in the judge can only make a case more cautious
   (`ai_level` 1 or 2; level 3 is locked behind measured calibration).
4. **The AI valve as a reviewer**: `juridicator.ai.advise` with a backend whose `tools == ()` (it refuses otherwise). Run
   `python3 -m wounder injection-eval` against the real backend first and read the obey-rate; do not enable level 2 above a rate you
   would not accept.
**Known facts that matter:** the juridicator rejects on any failed `mechanical.*` check (a failed `injection_eval` would reject; remove it
from `blocking` if you want it advisory); tooling PRs mentioning `sorry` in tool files are noted, not blocked; a crashed script is
inconclusive, never a failure of the PR; the latest run of a check wins over earlier runs. Backfilling the last 38 sandbox PRs found
these (see `docs/trust-shadow.md` in the sandbox).

## C. Order of work I would take
1. Merge emissary-archangel #10, run one jailed translate shard, read `trace-report.json` and the harden-runner audit, flip to `block`.
2. Merge sandbox #412, #413, #414 once their checks are green (`scan` and `tooling-tests` already fail on main), dispatch `ci-records` and
   `ledger-guard` once, create the judge App, add the ledger rulesets.
3. Land the Jinshi evidence job (B.2) in shadow; label; compare.
4. Port the sandbox pieces upstream to competemath/tengoku one purpose per PR.

## D. Things not to do
- Do not copy code or prose from the Tau Ceti repositories (several carry no licence); `docs/TAU-CETI.md` says how we used them.
- Do not turn on `require_signatures` before producers have keys; do not make `scope` or `merge eligibility` required before they have run
  on real PRs and the check is pinned to an App id.
- Do not build Lean locally (the disk filled once); use the sandbox runners.
- Do not treat a passing escape battery as proof of safety: it proves the vectors it probes are closed on that runner today.

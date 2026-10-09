# Credit, comparison, and what we took from Tau Ceti

[Tau Ceti](https://github.com/TauCetiProject) is an AIs-welcome Lean library downstream of Mathlib in which AI agents write and review
the code and humans write the roadmaps and the review rubrics. It is the project that most seriously treats the AI agents themselves as an
untrusted party, and it publishes the evidence of how that went: audits, incidents, fixes and their reasoning, in commit messages, pull
requests, issues and workflow headers. Everything here began by reading that work. We thank the people who did it and wrote it down,
above all **Kim Morrison** (who authored nearly all of it, usually with Claude and Codex as co-authors), and also **David Roe**,
**Bryan Gin-ge Chen**, **Bryan Chen**, **Jeremy Kahn**, **eohjelle**, **roed-math** and **alexanderlhicks**, whose reports and reviews
appear in the findings we learned from.

## How we used it, and the licence

Tau Ceti's TauCeti, TauCetiRoadmap, TauCetiReview, TauCetiProgress and bors-ng repositories are Apache-2.0. TauCetiWorker,
tauceti-claims, TauCetiCI and TauCetiData carry no licence. We copied **no code and no prose** from any of them. Every module here is
independent code written from the *ideas and findings*, and each module's docstring names the Tau Ceti feature, pull request or issue that
inspired it. Where something is Apache-2.0 and we ever do reuse a line, the file will say so and carry the notice.

## The honest comparison

Tau Ceti is stronger than Tengoku was in several places, and weaker in others. Both are true.

**What Tau Ceti does well, and we took as a lesson.** A base-defined workflow that reads the candidate only as immutable git objects;
a self-tested, secretless, networkless sandbox for candidate code with nine probes that abort the job; a one-time verdict marker;
reviewers restricted to a read-only tool set and a regression test that pins it; a closed-schema merge gate and compare-and-swap
landing; admission from an App-issued check bound to the exact head and merge base; platform-sourced CI records; a secret-isolated
cache publisher; the habit of writing down residual risks.

**Where Tau Ceti's own record shows a gap, and where we aim to be better.** (All verified against their repositories on 2026-10-09; the
dated evidence is in the table below.)
- The default for their *worker* agents is **not sandboxed**: host mode with the operator's full token and network and permissions
  bypassed. The sandbox is opt-in.
- There is **no tool allowlist** for worker agents, and no per-run escape-vector battery (their egress test is manual, skipped in CI, one vector).
- "Must not touch these paths" is **prompt text** for worker agents (breached 2026-07-30/31). Enforcement is downstream.
- No **secret scan** of what agents publish; no per-invocation **spend or turn cap**; a flat $1 reservation below the p99 cost.
- **No injection-resistance evaluation**: no payload set and no counts.
- Leases are forgeable and fail open; the review scoreboard is forgeable by any commenter; their CI archive is "append-only" by convention
  only; CODEOWNERS and required contexts are weaker than they read (build/bump-guard not pinned to an App; scope not required).
- The `Killed` substring bug in their CI classifier; a `set_option` grep ban already bypassed; unpinned `curl | sh` installers in places.

## Feature-by-feature

Legend: **module** = code in this repository; **integration** = wired into a Tengoku repository (see the status column of
`docs/STATUS.md`). "Evidence" names the Tau Ceti finding that motivated the feature, with dates, so the lesson is not lost.

| Tau Ceti feature (repo, where) | Why they have it (evidence) | Tengoku equivalent | What we do differently |
| --- | --- | --- | --- |
| Reviewer preamble: content is untrusted, injection is a finding (TauCetiReview `rubrics/_common.md`, PR #17) | Adversarial test PRs #16 and #18 (2026-06-03) | `warden/untrusted.py` (`notice`, `fence`, `fill_template`) | Tells the reviewer when content was truncated (theirs does not: 609 archived runs were truncated, 477 approved); random per-call fences; single-pass templating after their PR #178 bug |
| One-time verdict marker, text after the last occurrence only (TauCetiReview `runner/verdict.py`) | Forged-verdict PRs | `warden/verdict.py`; tengoku-juridicator `marker.py` | Validates the whole schema (theirs validates only the enum; a malformed `findings` can crash a paid run) |
| Reviewer tool set restricted at set level + regression test (PR #123, 2026-08-21) | Trace analysis: Bash in 295 of 427 calls; reachable ~79 days | `warden/toolpolicy.py` (policy, argv checker, **per-run trace audit**, source scanner for spawn flags) | One policy for every CLI we spawn, a trace audit on every run instead of a one-off analysis, and a CI scan that fails if any spawn site uses a deny-list alone |
| Reviewer clean-room environment | R6, keys inherited by reviewers (audit issues #7-#15) | `warden/envscrub.py` | Explicit allowlist, never copy-then-pop (their host mode leaks management keys and GH_TOKEN) |
| `sanitize()` and public diagnostics (TauCetiReview, Worker PRs #144, #217) | Leak of `raw_stderr` in 57 public records (#105) | `warden/sanitize.py`, `warden/secretscan.py` | Correct strip order (theirs strips HTML comments before control characters, so a marker survives); scans diffs, commit messages, PR bodies and logs, not only failure text |
| Bubble container with scoped GitHub proxy (TauCetiWorker, issue #1, PR #5) | "Prompts are guidance, not an enforcement boundary" | `warden/jail.py` + `warden/authproxy.py` + `warden/egress.py` | Isolation is the default, not opt-in; per-uid egress rules and a CONNECT allowlist; proxy denies GraphQL and is path-scoped |
| Startup preflight proves the sandbox exists (Worker PR #116) | Stale daemon, wrong versions | `warden/selftest.py` | Probes *confinement* every launch, as the agent identity (theirs proves presence) |
| bubblewrap nine-probe self-test (TauCeti `pr-build.yml`, PR #5800) | `/proc/1/environ` leak, writable tmpfs root, silent "try" user-namespace flag | `warden/jail.py` (builders) + `warden/selftest.py` (20+ probes) | Adds metadata IP, docker socket, ptrace, DNS, IPv6, credential files, CLAUDE.md/hooks in cwd |
| `git-safe-push`, `gh-safe-pr-create` (Worker `scripts/`) | Churn, duplicate PRs (2026-06-08/09) | `warden/safegit.py` | Real CAS tests against a bare remote (theirs uses stubs), a real PR target marker (theirs is dead code), a pre-push hook as defence in depth, server-side rulesets as the boundary |
| Claim leases (tauceti-claims, `claim.sh`) | "A fleet of four paid four subscriptions" | `warden/leases.py` | Owner is `login/host-uuid/worker` (theirs collides), signed option, no host/pid published, unparseable leases reclaimed, explicit fail-closed mode |
| Scope guard from git objects, `scope` status (TauCeti, PR #12207) | GitHub file-list cap of 300 files | `warden/scope.py` | Also modes, symlinks, byte-prefix append, size caps and **dropped human-owned changes**; designed to be a *required* check pinned to an App |
| "Must not touch" rules, protected paths (Worker prompts, PR #167) | Roadmap issues #111/#112 filed by agents | `warden/scope.py` + `warden/ownership.py` | Enforced technically; one source file generates CODEOWNERS, scope policy and review allowlist, with a divergence test (theirs drifted) |
| Size caps (TauCeti PRs #128, #353) | Reviewability | `warden/scope.py` limits | Same, plus per-file line caps |
| Spend and attempt caps (Worker, PRs #47, #64, #241) | Churn, no ceiling | `warden/caps.py` | Per-invocation turn/second/dollar caps, rolling-p99 reservation, never negative, hash-chained ledger |
| Platform-sourced CI records (TauCetiCI collector) | Agents cannot shade platform numbers | `warden/ciclean.py`, `warden/audit.py` | Hash chain + a guard that fails if any existing record changes; watermark that refuses to advance on a count mismatch; anchored failure classifier; per-actor and per-agent failure rates (data they hold but do not use) |
| Append-only archive (TauCetiData, TauCetiCI) | Auditability | `warden/audit.py` `ledger_guard` | Enforced, not conventional (theirs: five commits modify and four delete existing paths) |
| Admission only from an App-issued `merge eligibility` check bound to head and merge base (bors-ng PR #6) | `bors r+` comments are spoofable and replayable | `warden/eligibility.py` | Binds the hash of the review evidence too; one verifier shared with the juridicator |
| Closed-schema merge gate: modes, byte-prefix append, build from a pinned App id (TauCetiProgress `gate.py`) | Four rounds of adversarial review (2026-07-30/31) | `warden/scope.py`, `warden/audit.py` | Generalised to any append-only file; see the gate list in the scope module |
| Untrusted text fenced before it reaches a writer model (Progress `context.py`) | Anyone can open a PR whose text reaches the writer | `warden/untrusted.py` | Same idea; also an evaluation set that measures whether it works |
| Ruleset snapshots and drift assertion (TauCetiCI A5, Roadmap `auto-merge.yml`, PR #235) | An unreviewed merge into an unprotected branch in 11 seconds | tengoku-sandbox `ruleset-drift` check (integration) | Committed expected rulesets compared with the live ones on a schedule and on demand |
| Pinned installers, App-token least privilege lint (TauCeti issue #3725, PR #7206) | Unpinned `elan-init`; `create-github-app-token@v1` ignored `permission-*` | tengoku-sandbox `workflow_rules.py` extensions (integration) | Fails any `curl | sh` without a hash, any token action not pinned to a version that honours permissions |
| Axiom, duplicate, module and environment audits of AI-written Lean (TauCeti `scripts/*.lean`) | Soundness of AI-written code | Already in Tengoku: Leak IV, Archangel, `axiom_scan.py`, `vacuity.py` and [Jinshi](https://github.com/competemath/jinshi) | Jinshi adds kernel replays by three independent kernels, mutation testing and statement-fidelity examinations |
| Secret-isolated cache publisher, publish-before-land (TauCeti `publish-lake-cache.yml`, issue #3720) | Cache key reachable by code on `main` | Already in Tengoku: attested cache (`gh attestation`) | Credit only |
| Honest residual-risk documents | — | `SECURITY.md` of every repo | We keep the habit |

## Findings we reproduce as lessons

1. A tool *flag* is not a tool *set*. Tau Ceti's Claude reviewer had Bash for about 79 days because the restriction was `--allowedTools`
   alone; a trace analysis found Bash in 295 of 427 calls (their PR #123, 2026-08-21). Our `toolpolicy` refuses a spawn site that lacks `--tools`.
2. A test that pins the permissive flags is a record of the exposure, not a defence.
3. A required check must be pinned to the App that produces it, or any identity with write access can set it.
4. "Append-only" needs a rule that fails the push, not a README.
5. A sandbox that exists is not a sandbox that confines: probe it every run, as the agent identity.
6. The bubblewrap "try" user-namespace flag silently skips; name each namespace.
7. The cache secret must live in a job that runs none of the project's code (their issue #3720).
8. Fork PRs in `pull_request_target`: GitHub changed behaviour on 2026-07-20; read candidates as git objects, never check them out beside a token.
9. A parser that takes "the text after the marker" must also validate what is there; a classifier must not match bare substrings.

This repository's own list of what remains unsolved is `SECURITY.md`.

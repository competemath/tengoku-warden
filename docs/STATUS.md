# Status (2026-10-10)

"Library" = code and tests exist here. "PR open" = wired into a repository by a pull request that is waiting for review. "Live" =
merged and running. Nothing below has been exercised against a real translation run or a real content PR yet; the first one after
merge is the test (see "First real runs").

| Capability | Module | Where it is wired | State |
| --- | --- | --- | --- |
| Tool set instead of deny-list for the translation agent | `toolpolicy` | emissary-archangel [PR #10](https://github.com/competemath/emissary-archangel/pull/10) (bridge `claudeToolArgs`, regression test that fails on the old bridge) | PR open |
| Reviewer for goals gets a tool set | `toolpolicy` | emissary-archangel PR #10 (`goals-suggest.yml`) | PR open |
| Agent environment from an allowlist | `envscrub` | emissary-archangel PR #10 (`agentEnv()`, `agent-run.py`) | PR open |
| Agent user, per-user egress, CONNECT allowlist, escape battery before launch | `jail`, `selftest`, `egress` | emissary-archangel PR #10 (`translate.yml`, `agent-selftest.yml`: 33 of 33 probes denied on a real runner) | PR open |
| Per-run trace audit gates banking | `toolpolicy` | emissary-archangel PR #10 (`agent-trace-gate.py`) | PR open |
| Spend and turn caps per invocation | `caps` | emissary-archangel PR #10 (`--max-turns`, `--max-budget-usd` from env) | PR open; ledger-backed budget is a library |
| Secret scan and redaction of artifacts, PR metadata and bank | `secretscan`, `sanitize` | emissary-archangel PR #10 (`agent-artifacts.py`, `bank-guard.py`); sandbox [PR #412](https://github.com/competemath/tengoku-sandbox/pull/412) | PR open |
| CAS push in the finish job; guarded PR creation | `safegit` | emissary-archangel PR #10 | PR open |
| Pinned installers; rule that forbids unpinned ones | (workflow rules) | emissary-archangel PR #10 (elan, claude-code); sandbox [PR #414](https://github.com/competemath/tengoku-sandbox/pull/414) | PR open |
| Scope, modes and dropped-human-work for bot PRs; ownership single source | `scope`, `ownership` | sandbox PR #412 (`agent-guard.yml`, advisory check named `scope`) | PR open |
| Sealed-step self-test | `selftest` ideas | sandbox PR #412 (`sandbox_selftest.py`, hardened seal in the vacuity step) | PR open |
| Platform-sourced CI records, anchored classifier, watermark, per-actor failure rates | `ciclean`, `audit` | sandbox [PR #413](https://github.com/competemath/tengoku-sandbox/pull/413) (`ci-records.yml`) | PR open |
| Append-only guard for the ledger and record branches | `audit` | sandbox PR #413 (`ledger-guard.yml`) | PR open |
| Ruleset snapshots and drift check | (script) | sandbox PR #413 (`ruleset-drift.yml`) | PR open |
| `merge eligibility` check bound to head, merge base and evidence | `eligibility` | sandbox PR #413 (third job of `trust-shadow.yml`) | PR open; made by the Actions identity until a judge App exists |
| Shadow trust verdicts and ledger | juridicator, wounder, praiser | sandbox PR #411 | **Live** |
| Shared prompt-injection defence for the AI valve | `untrusted`, `verdict`, `sanitize` | juridicator (vendored), `ce5e87f` | **Live** |
| Agent-security canaries (36 cases), injection evaluation and jail battery as evidence | wounder `agentsec` | wounder `778d2bf` | **Live** |
| "The agent ran contained" evidence and trust-card line | praiser `agentrun` | praiser `c8c53d2` | **Live** |
| Scoped credential-injecting proxy | `authproxy` | not wired: needs an API-key model credential (OAuth tokens may not work through a raw proxy) | Library |
| Task leases | `leases` | not wired: nothing needs a lease yet | Library |

## First real runs (what to read when they happen)
1. **Translate shard in agent mode** (emissary-archangel, after PR #10 merges): `out/trace-report.json` and the selftest report in the
   shard log. The trace gate fails closed on tool names it has not seen; if it fails on a harmless one, add that name to the policy.
2. **The harden-runner audit** in the same run: turn it into an allowlist with `python3 -m warden egress-proxy --from-audit` and flip the
   job to `block`.
3. **The first content PR after the sandbox PRs merge**: the vacuity step now runs inside the hardened seal; if Lean cannot compile in it,
   the step fails loudly; `--advisory <probe>` on the step is the escape hatch while it is fixed.
4. **First `ci-records` and `ledger-guard` runs**: dispatch both once and read the summaries.

# tengoku-warden: build contract (for everyone writing modules)

Purpose: treat every AI agent as an untrusted party, in Tengoku and its repositories. The reasoning and credit for what Tau Ceti
Project (github.com/TauCetiProject) found and built are in `docs/TAU-CETI.md` (their reports are in the scratchpad `tc/` while we build).
Their repositories carry no licence except TauCetiReview, TauCetiProgress and bors-ng (Apache-2.0) and TauCeti/TauCetiRoadmap
(Apache-2.0); in every case we write independent code from the *ideas and findings*, never copy code or prose, and we credit them.

## Rules for every module
- Python standard library only. Written for Python 3.9+ syntax (`from __future__ import annotations`; no `match`, no `X | Y` at runtime
  outside annotations) because the Tengoku sandbox lints for py39 and runners may differ. Package `warden/`, tests `tests/test_<module>.py`
  (unittest). No network, no Lean, no AI calls in tests. Tests run in seconds. Do not spend time on mutation campaigns; write focused,
  hostile-input tests (each rule gets one case that must fail and one that must pass) and run them once.
- Pure logic separated from IO: functions take data and return data; thin `main()`/CLI functions do file/process IO. No clock reads inside
  logic (take `now` as a parameter). No global state.
- Fail closed: unknown input, parse error, missing evidence => refuse/deny/inconclusive, never allow.
- Module docstring MUST start with what it does, then a `Credit:` paragraph naming the Tau Ceti repo/feature/PR or finding that inspired
  it (use the reports in .../scratchpad/tc/report-*.md for accurate ids, dates and links), then `What we do differently:`.
  Never paste their code or long phrases.
- CLI: each module with a command-line use exposes `main(argv) -> int` and is reachable as `python3 -m warden <command> ...` through
  `warden/__main__.py` (the integrator, not you, edits `__main__.py` and `__init__.py`; tell the integrator your command names in your report).
- Exit codes: 0 ok/allowed, 1 refused/violations found, 2 bad input.
- Do not git commit. Write only your own files. Report: files written, public API (function signatures), CLI commands, test count and
  result, anything you could not do or decided differently.

## Module map (owner => files)
- A (text safety): `warden/untrusted.py`, `warden/sanitize.py`, `warden/verdict.py`, `warden/secretscan.py`, `corpus/injection/*.json` + `warden/injection_eval.py`
- B (agent jail): `warden/toolpolicy.py`, `warden/envscrub.py`, `warden/jail.py`, `warden/selftest.py`, `warden/egress.py`
- C (git/repo guards): `warden/safegit.py`, `warden/leases.py`, `warden/scope.py`, `warden/ownership.py`
- D (spend/audit/identity): `warden/caps.py`, `warden/audit.py`, `warden/ciclean.py` (CI record collector transform), `warden/authproxy.py`, `warden/eligibility.py`

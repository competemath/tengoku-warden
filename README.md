# tengoku-warden

Agent security for [Tengoku](https://github.com/competemath/tengoku): **every AI agent is treated as an untrusted party.** It reads
untrusted text, so it can be talked into things; it holds credentials, so it can leak them; it writes to repositories, so it can touch
what it should not; it spends money, so it can run away. The warden makes each of those hard to do silently, and measures how hard.

It exists because [Tau Ceti](https://github.com/TauCetiProject) showed, in public and with dates, what it takes to run a library
that AI agents write and review, and where that went wrong before it went right. We read all of it, and built Tengoku's version:
everything Tau Ceti does that applies to us, the places where its own record shows a gap, and a few things nobody has. The credit,
the comparison and the findings are in [docs/TAU-CETI.md](docs/TAU-CETI.md). Please read it first.

## What is in it (standard library only, Python 3.9+)

| Module | What it does |
| --- | --- |
| `untrusted` | The prompt for any model that reads untrusted text: a notice naming the attack shapes, per-call random fences, single-pass templating, truncation told to the reader |
| `sanitize`, `secretscan` | What an agent may publish: correct strip order, mention/link defusal, fixed-phrase diagnostics, a secret scanner for text, diffs, commit messages and logs |
| `verdict` | One-time verdict marker, full schema validation, forged markers ignored, retry-then-error |
| `injection_eval` + `corpus/injection` | 32 payloads in 14 classes and a harness that reports an obey-rate and a missed-detection rate with Wilson intervals |
| `toolpolicy` | Tool allowlists at **set** level for the Claude CLI (and checks for others), an argv checker, a per-run **trace audit**, and a source scanner that fails on any spawn site relying on a deny-list |
| `envscrub` | Child environments built from an explicit allowlist, never copy-then-pop |
| `jail`, `selftest`, `egress` | Builders for a bubblewrap jail, per-user egress rules and an agent user; a 34-probe escape battery run as the agent every launch that fails closed; a CONNECT allowlist proxy |
| `authproxy` | A scoped reverse proxy that injects the credential so the agent's process never holds it; deny by default, path-scoped, no GraphQL unless named |
| `safegit`, `leases` | Compare-and-swap pushes tested against a real bare remote, a guarded PR wrapper with a real target marker; forgeable-no-more task leases |
| `scope`, `ownership` | Path, mode, symlink, size and append-only enforcement read from git objects; one file that generates CODEOWNERS, the scope policy and the review allowlist, with a divergence check |
| `caps`, `audit`, `ciclean` | Per-invocation turn, time and dollar caps with a p99 reservation and a hash-chained ledger; an audit store with a guard that **fails** if any existing record changes; platform-sourced CI record transforms with an anchored failure classifier and a watermark that refuses to advance on a count mismatch |
| `eligibility` | The `merge eligibility` check: built from a verdict, bound to the head, merge base and the hash of the evidence, verified against the App that made it |

```bash
python3 -m warden --help
python3 -W error::ResourceWarning -m unittest discover -s tests -p 'test_*.py'
```

## Where it is used
[docs/STATUS.md](docs/STATUS.md) says, per feature, whether it is a library only or wired into a repository, and what the next step is.
The settings that only a maintainer can change (GitHub Apps, rulesets, secrets) are in [docs/RUNBOOK.md](docs/RUNBOOK.md).

## What it does not do
[SECURITY.md](SECURITY.md) lists what remains unsolved. The short version: wording cannot make a model immune, so the design limits
what a persuaded model can reach; a shared kernel is not a virtual machine; and server-side settings are what actually enforce.

Apache-2.0. Not affiliated with the Tau Ceti Project; we are grateful to it.

# Security

tengoku-warden is the shared agent-security toolkit for Tengoku. Report vulnerabilities privately through GitHub's
"Report a vulnerability" on this repository (Security tab). Do not test attacks against live services; the
[sandbox](https://github.com/competemath/tengoku-sandbox) exists for that.

## What this library is, and is not

It makes specific classes of agent misbehaviour hard to ship silently: a tool set wider than intended, a secret in the agent's reach,
a path an agent should not touch, an unbounded spend, a forged approval, a record changed after the fact. It does not make a model
safe. Prompt injection cannot be eliminated by wording; the design contains it by privilege (what the agent can read, run, reach and
publish), not by trusting the model to refuse.

## Residual risks (written down on purpose)

1. **A model can still be talked into bad output.** The fences, the notice and the marker lower the rate; the injection evaluation set
   measures it; nothing makes it zero. Anything that matters is decided by code the agent cannot write.
2. **The agent's own model credential is readable by the agent** unless it is served through the auth proxy. With an OAuth subscription token
   the proxy may not work, so the fallback is a per-user egress allowlist; an agent could still send the token to the allowlisted model endpoint.
3. **Shared kernel.** A uid-isolated, namespaced process on a shared kernel is not a virtual machine. A kernel escape defeats the jail.
4. **Self-test tells you what it probes.** A passing battery proves those vectors are closed on this runner today, not that none exists.
5. **Server-side enforcement needs the repository settings** (rulesets, required checks pinned to an App, a dedicated GitHub App). The
   library can verify and alert; only the settings can enforce. `docs/RUNBOOK.md` lists them.
6. **Records here are tamper-evident, not tamper-proof**, until the chain head is published somewhere the writer cannot edit.
7. **Heuristic scanners** (secrets, injection phrases) have false negatives by nature.
8. **Time.** Lease and cap logic uses a clock the caller injects; if the caller feeds the local clock, a hostile host can skew it.

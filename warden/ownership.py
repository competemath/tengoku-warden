"""One source of truth for who may change what: CODEOWNERS, the scope policy and the review allowlist.

`agent-paths.json` is `{"human": [globs], "agent": [globs], "review": [globs]}`. From it this module
generates the CODEOWNERS file (`to_codeowners`), a `warden.scope` policy (`to_scope_policy`) and the
list of paths the AI review may stand in for a human on (`to_review_allowlist`), and `divergence`
compares a committed CODEOWNERS file against what the policy would generate, using real CODEOWNERS
semantics (patterns are matched with last-match-wins, `*`, `**`, a trailing `/` and a leading `/`).
A human-owned glob always wins over an agent glob it overlaps, in all three outputs.

Credit: Tau Ceti Project, TauCeti ownership map (CODEOWNERS with `* @humans` and ownerless AI-gated
paths such as TauCeti/, TauCeti.lean, lake-manifest.json and lean-toolchain; PRs #41, #204, #246 and
#6018 widened it one path at a time because the merge queue could not enqueue a PR that needed a
code-owner review the bot cannot give). Their report records that CODEOWNERS, the `scope` regexes and
the Review allowlists drifted apart, and that the ruleset does not enforce CODEOWNERS (bors.toml sets
use_codeowners=false).

What we do differently: the three lists are generated from one file instead of being kept in step by
hand; a divergence check with correct last-match-wins matching fails when the committed CODEOWNERS
differs in effect from the policy (not just in text); the review allowlist is validated to lie inside
the agent paths; ownerless AI-gated paths are explicit, commented lines rather than silence. CODEOWNERS
is advisory unless the ruleset requires code-owner review: this module keeps the files honest, it does
not enforce anything by itself.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from warden import scope

_KEYS = ("human", "agent", "review")
_OWNER_RE = re.compile(r"^(?:@[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?|[^\s@]+@[^\s@]+\.[^\s@]+)\Z")
UNLISTED_PROBES = ("zz-unlisted-root-file.txt", "zz-unlisted/dir/file.txt")


class OwnershipError(ValueError):
    """The policy file is malformed (callers must refuse to proceed)."""


Policy = Dict[str, List[str]]


def _no_dupes(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key %r" % k)
        out[k] = v
    return out


def load_policy(path: str) -> Policy:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.loads(fh.read(), object_pairs_hook=_no_dupes)
    except (OSError, ValueError) as exc:
        raise OwnershipError("cannot read %s: %s" % (path, exc))
    problems = validate_policy(data)
    if problems:
        raise OwnershipError("; ".join(problems))
    return {k: list(data[k]) for k in _KEYS}


def validate_policy(policy) -> List[str]:
    """Return the problems with a policy (empty list means valid). Never raises."""
    if not isinstance(policy, dict):
        return ["policy must be a JSON object"]
    problems: List[str] = []
    extra = set(policy) - set(_KEYS)
    if extra:
        problems.append("unknown keys: %s" % ", ".join(sorted(extra)))
    for k in _KEYS:
        v = policy.get(k)
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            problems.append("%r must be a list of glob strings" % k)
            continue
        if len(set(v)) != len(v):
            problems.append("%r contains duplicate globs" % k)
        for g in v:
            try:
                scope.compile_glob(g)
            except scope.PolicyError as exc:
                problems.append("%r: %s" % (k, exc))
    if problems:
        return problems
    both = set(policy["human"]) & set(policy["agent"])
    if both:
        problems.append("globs both human and agent: %s" % ", ".join(sorted(both)))
    if problems:
        return problems
    for g in policy["review"]:
        for probe in sample_paths(g):
            cls = classify(policy, probe)
            if cls != "agent":
                problems.append("review glob %r covers %r which is %s-owned, not agent-writable"
                                % (g, probe, cls))
                break
    return problems


# ------------------------------------------------------------------------ rules

Rule = Tuple[str, Tuple[str, ...]]


def _generated_rules(policy: Policy, human_owner: str, agent_owner: Optional[str]) -> List[Rule]:
    rules: List[Rule] = [("*", (human_owner,))]
    for g in policy["agent"]:
        rules.append((g, (agent_owner,) if agent_owner else ()))
    for g in policy["human"]:
        rules.append((g, (human_owner,)))
    return rules


def classify(policy: Policy, path: str) -> str:
    """'agent' if the last matching glob (agent, then human) is an agent glob, else 'human'."""
    result = "human"
    for g in policy["agent"]:
        if scope.glob_match(g, path):
            result = "agent"
    for g in policy["human"]:
        if scope.glob_match(g, path):
            result = "human"
    return result


def _check_owner(owner: str, what: str) -> str:
    if not isinstance(owner, str) or not _OWNER_RE.match(owner):
        raise OwnershipError("%s must be @user, @org/team or an email address" % what)
    return owner


def to_codeowners(policy: Policy, human_owner: str, agent_owner: Optional[str] = None) -> str:
    """CODEOWNERS text: `* human`, then agent globs, then human globs (last match wins, so human wins).

    With `agent_owner=None` the agent globs are written as ownerless lines (GitHub's way to remove
    ownership), each preceded by an explicit `# ai-gated` comment.
    """
    problems = validate_policy(policy)
    if problems:
        raise OwnershipError("; ".join(problems))
    _check_owner(human_owner, "human_owner")
    if agent_owner is not None:
        _check_owner(agent_owner, "agent_owner")
    lines = [
        "# Generated by `warden ownership --generate` from agent-paths.json. Do not edit by hand:",
        "# `warden ownership --check` fails when this file differs in effect from the policy.",
        "# The last matching pattern wins; human-owned patterns come last so they win.",
        "* %s" % human_owner,
    ]
    if policy["agent"]:
        lines.append("# AI-gated paths: %s" % ("owned by " + agent_owner if agent_owner else
                                                 "no code owner (a bot cannot give a code-owner review)"))
    for g in policy["agent"]:
        if agent_owner is None:
            lines.append("# ai-gated (ownerless): %s" % g)
            lines.append(g)
        else:
            lines.append("%s %s" % (g, agent_owner))
    if policy["human"]:
        lines.append("# Human-owned paths")
    for g in policy["human"]:
        lines.append("%s %s" % (g, human_owner))
    return "\n".join(lines) + "\n"


def to_scope_policy(policy: Policy, extra: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    """A dict that `warden.scope.Policy.from_dict` accepts: agents may touch agent globs, never human ones."""
    problems = validate_policy(policy)
    if problems:
        raise OwnershipError("; ".join(problems))
    out: Dict[str, object] = {
        "classes": {
            "agent": {"allow": list(policy["agent"]), "touch_protected": False},
            "human": {"allow": ["**"], "touch_protected": True},
        },
        "protected": list(policy["human"]),
    }
    if extra:
        out.update(extra)
    try:
        scope.Policy.from_dict(out)  # prove compatibility now, not at enforcement time
    except scope.PolicyError as exc:
        raise OwnershipError("generated scope policy is invalid: %s" % exc)
    return out


def to_review_allowlist(policy: Policy) -> List[str]:
    """Globs the AI review may stand in for a human on: the policy's `review` list, validated."""
    problems = validate_policy(policy)
    if problems:
        raise OwnershipError("; ".join(problems))
    return list(policy["review"])


# ------------------------------------------------------------------ parsing / matching


def parse_codeowners(text: str) -> Tuple[List[Rule], List[str]]:
    """(rules in file order, unsupported patterns). Comments and blank lines are skipped."""
    rules: List[Rule] = []
    unsupported: List[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens: List[str] = []
        for tok in line.split():
            if tok.startswith("#"):
                break
            tokens.append(tok)
        if not tokens:
            continue
        pattern, owners = tokens[0], tuple(tokens[1:])
        try:
            scope.compile_glob(pattern)
        except scope.PolicyError:
            unsupported.append(pattern)
            continue
        if "[" in pattern or "\\" in pattern:
            unsupported.append(pattern)
            continue
        rules.append((pattern, owners))
    return rules, unsupported


def owners_for(rules: Sequence[Rule], path: str) -> Tuple[str, ...]:
    """Owners of `path` under last-match-wins; no match or an ownerless match gives ()."""
    result: Tuple[str, ...] = ()
    for pattern, owners in rules:
        if scope.glob_match(pattern, path):
            result = owners
    return result


def sample_paths(pattern: str) -> List[str]:
    """Concrete paths that match `pattern` (used to probe how rule sets treat a path class)."""
    anchored = pattern.startswith("/")
    body = pattern[1:] if anchored else pattern
    segs = body.rstrip("/").split("/")
    out: List[str] = []
    mapped: List[str] = []
    for i, seg in enumerate(segs):
        last = i == len(segs) - 1
        if seg == "**":
            mapped.append("d1/f.txt" if last else "d1/d2")
        else:
            mapped.append(seg.replace("*", "x").replace("?", "y"))
    base = "/".join(mapped)
    for cand in (base, base + "/x.txt", "deep/dir/" + base, "deep/dir/" + base + "/x.txt"):
        if cand not in out:
            out.append(cand)
    return [c for c in out if scope.glob_match(pattern, c)]


@dataclass(frozen=True)
class Divergence:
    pattern: str
    probe: Optional[str]
    committed: str
    expected: str
    why: str

    def __str__(self) -> str:
        return "%s: %s (probe %s: committed %s, policy %s)" % (
            self.pattern, self.why, self.probe, self.committed, self.expected)


def _label(owners: Tuple[str, ...], human_owner: Optional[str], agent_owner: Optional[str]) -> str:
    if not owners:
        return "ownerless"
    if human_owner is not None and owners == (human_owner,):
        return "human"
    if agent_owner is not None and owners == (agent_owner,):
        return "agent"
    return " ".join(owners)


def divergence(codeowners_text: str, policy: Policy, *, human_owner: Optional[str] = None,
               agent_owner: Optional[str] = None) -> List[Divergence]:
    """Every path class on which the committed CODEOWNERS differs in effect from the policy.

    `human_owner` defaults to the owner on the committed `*` rule. A missing `*` rule, syntax
    CODEOWNERS does not support (negation, brackets) and any probe path owned differently are
    each reported. An empty list means the file is equivalent to the generated one.
    """
    problems = validate_policy(policy)
    if problems:
        raise OwnershipError("; ".join(problems))
    committed, unsupported = parse_codeowners(codeowners_text)
    out: List[Divergence] = [Divergence(p, None, "unsupported", "-", "pattern syntax not supported by CODEOWNERS")
                             for p in unsupported]
    if human_owner is None:
        defaults = [o for (p, o) in committed if p == "*" and len(o) == 1]
        if defaults:
            human_owner = defaults[-1][0]
        else:
            out.append(Divergence("*", None, "missing", "human default", "no `* <owner>` default rule"))
            human_owner = "@policy-human-owner"
    expected = _generated_rules(policy, human_owner, agent_owner)
    patterns = [p for p, _ in expected] + [p for p, _ in committed]
    seen = set()
    for pattern in patterns:
        for probe in sample_paths(pattern) + list(UNLISTED_PROBES):
            if probe in seen:
                continue
            seen.add(probe)
            have = owners_for(committed, probe)
            want = owners_for(expected, probe)
            if have != want:
                out.append(Divergence(pattern, probe, _label(have, human_owner, agent_owner),
                                      _label(want, human_owner, agent_owner), "owned differently"))
    return out


# --------------------------------------------------------------------------- CLI


def main(argv: Optional[Sequence[str]] = None) -> int:
    """`warden ownership --check CODEOWNERS --policy agent-paths.json` (exit 1 on divergence) or `--generate`."""
    ap = argparse.ArgumentParser(prog="warden ownership", description="keep CODEOWNERS, scope and review lists in step")
    ap.add_argument("--policy", required=True, help="agent-paths.json")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", metavar="CODEOWNERS", help="fail if this file differs in effect from the policy")
    mode.add_argument("--generate", action="store_true", help="print the CODEOWNERS the policy implies")
    mode.add_argument("--scope-policy", action="store_true", help="print the warden.scope policy JSON")
    mode.add_argument("--review-allowlist", action="store_true", help="print the review allowlist, one glob per line")
    ap.add_argument("--human-owner", default=None)
    ap.add_argument("--agent-owner", default=None)
    try:
        args = ap.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return 2 if exc.code not in (0, None) else 0
    try:
        policy = load_policy(args.policy)
        if args.check:
            try:
                with open(args.check, "r", encoding="utf-8") as fh:
                    text = fh.read()
            except OSError as exc:
                print("ownership: cannot read %s: %s" % (args.check, exc), file=sys.stderr)
                return 2
            if args.human_owner:
                _check_owner(args.human_owner, "--human-owner")
            if args.agent_owner:
                _check_owner(args.agent_owner, "--agent-owner")
            diffs = divergence(text, policy, human_owner=args.human_owner, agent_owner=args.agent_owner)
            for d in diffs:
                print(str(d))
            print("ownership: %s" % ("in step" if not diffs else "DIVERGED (%d)" % len(diffs)))
            return 0 if not diffs else 1
        if args.generate:
            if not args.human_owner:
                print("ownership: --generate needs --human-owner", file=sys.stderr)
                return 2
            sys.stdout.write(to_codeowners(policy, args.human_owner, args.agent_owner))
        elif args.scope_policy:
            print(json.dumps(to_scope_policy(policy), indent=2, sort_keys=True))
        else:
            for g in to_review_allowlist(policy):
                print(g)
        return 0
    except OwnershipError as exc:
        print("ownership: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

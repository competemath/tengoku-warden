"""The merge-admission signal that cannot be spoofed by a comment: a check run from one specific GitHub App.

What it does: `build_check_run` turns a Tengoku verdict into the REST body of a check run named `merge eligibility` whose
`external_id` binds the decision to the exact repository, pull request, head commit, merge base, policy and review evidence;
`verify_check` takes the check runs listed for a pull request and answers one of admit, wait, cancel or ignore, trusting
nothing but a completed check from the expected App id, for the live head, whose payload agrees with its conclusion and whose
merge base is still the live one. Anything missing, malformed, stale or from another App is never an admission.

Credit: the Tau Ceti Project's bors-ng fork (leanprover-community/bors-ng fork, PR #6, commit 85b00c6, 2026-10-06;
lib/worker/merge_eligibility.ex; research report 2026-10-09, part C1) made a `merge eligibility` check run, produced by the
review GitHub App and bound to the exact head and merge base, the only automatic admission authority, because the `bors r+`
comment channel is spoofable and replayable. The checks it makes (App id, live head, schema/repo/PR in `external_id`, status
completed, conclusion consistent with the payload, 40-hex merge base, highest check id wins, other Apps' same-named checks
cannot hide it, block labels `keep hold wip human do-not-close`, success admits, neutral waits, failure cancels) are theirs; the
tests for forged App, wrong head, replay, malformed JSON and conclusion mismatch follow their list. Their engine is
Apache-2.0; this is independent code.

What we do differently: the `external_id` also carries the digest of the review EVIDENCE (and of the verdict and the policy),
so a check cannot be replayed onto different evidence, and `verify_check` can be told which evidence digest it expects; the
schema is closed (unknown keys are malformed); App ids must be exact integers; a block label means "ignore", not a silent
admit; and a conclusion that disagrees with the payload is treated as a possible forgery (wait, with a distinct reason), never as
a lesser form of success. Honest limit: one compromised review-App key controls admission; manual overrides, if you keep any,
should be logged distinctly and never share this code path.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

SCHEMA = "tengoku-merge.eligibility/v1"
CHECK_NAME = "merge eligibility"
DECISIONS = ("ACCEPT", "HOLD", "ESCALATE", "REJECT")
CONCLUSION_FOR = {"ACCEPT": "success", "HOLD": "neutral", "ESCALATE": "neutral", "REJECT": "failure"}
DEFAULT_BLOCK_LABELS = ("keep", "hold", "wip", "human", "do-not-close")

_SHA40 = re.compile(r"^[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}\Z")
_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
_KEYS = ("schema", "repo", "pr", "head_sha", "merge_base", "decision", "verdict_digest", "policy_sha256", "evidence_digest")

_TITLES = {
    "success": ("Eligible for merge", "The review verdict is ACCEPT for this exact head and merge base."),
    "neutral": ("Not yet eligible", "The review verdict is HOLD or ESCALATE: more evidence or a human decision is needed."),
    "failure": ("Not eligible", "The review verdict is REJECT for this exact head."),
}


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_of(obj: Any) -> str:
    """`sha256:<hex>` of the canonical JSON of `obj` (the same convention the juridicator uses for its verdicts)."""
    return "sha256:" + hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def _check_pr(pr: Any) -> int:
    if isinstance(pr, bool) or not isinstance(pr, int) or pr <= 0:
        raise ValueError("pr must be a positive integer")
    return pr


def build_external_id(
    *,
    repo: str,
    pr: int,
    head_sha: str,
    merge_base: str,
    decision: str,
    verdict_digest: str,
    policy_sha256: str,
    evidence_digest: str,
) -> str:
    """The canonical JSON the check run carries in `external_id`. Raises ValueError on any malformed field."""
    if not isinstance(repo, str) or not _REPO.match(repo):
        raise ValueError("repo must be owner/name")
    _check_pr(pr)
    for label, sha in (("head_sha", head_sha), ("merge_base", merge_base)):
        if not isinstance(sha, str) or not _SHA40.match(sha):
            raise ValueError("%s must be 40 lowercase hex characters" % label)
    if decision not in DECISIONS:
        raise ValueError("decision must be one of %s" % "/".join(DECISIONS))
    for label, dg in (("verdict_digest", verdict_digest), ("policy_sha256", policy_sha256), ("evidence_digest", evidence_digest)):
        if not isinstance(dg, str) or not _DIGEST.match(dg):
            raise ValueError("%s must be sha256:<64 hex>" % label)
    payload = {
        "schema": SCHEMA,
        "repo": repo,
        "pr": pr,
        "head_sha": head_sha,
        "merge_base": merge_base,
        "decision": decision,
        "verdict_digest": verdict_digest,
        "policy_sha256": policy_sha256,
        "evidence_digest": evidence_digest,
    }
    return canonical_json(payload)


def build_check_run(verdict: Mapping[str, Any], case: Mapping[str, Any], merge_base: str, pr: int) -> Dict[str, Any]:
    """REST body for `POST /repos/{owner}/{repo}/check-runs`.

    `verdict` needs `decision` (ACCEPT|HOLD|ESCALATE|REJECT), `evidence_digest` and `policy_sha256`; `case` needs `repo` and
    `head_sha`. The output text uses fixed phrases only: nothing from the verdict's free text is copied into the check.
    """
    if not isinstance(verdict, Mapping) or not isinstance(case, Mapping):
        raise ValueError("verdict and case must be objects")
    decision = verdict.get("decision")
    if decision not in DECISIONS:
        raise ValueError("verdict decision must be one of %s" % "/".join(DECISIONS))
    conclusion = CONCLUSION_FOR[decision]
    ext = build_external_id(
        repo=case.get("repo"),  # type: ignore[arg-type]
        pr=pr,
        head_sha=case.get("head_sha"),  # type: ignore[arg-type]
        merge_base=merge_base,
        decision=decision,
        verdict_digest=digest_of(dict(verdict)),
        policy_sha256=verdict.get("policy_sha256"),  # type: ignore[arg-type]
        evidence_digest=verdict.get("evidence_digest"),  # type: ignore[arg-type]
    )
    title, summary = _TITLES[conclusion]
    return {
        "name": CHECK_NAME,
        "head_sha": case["head_sha"],
        "status": "completed",
        "conclusion": conclusion,
        "external_id": ext,
        "output": {"title": title, "summary": summary},
    }


@dataclass(frozen=True)
class Admission:
    decision: str  # admit | wait | cancel | ignore
    reasons: Tuple[str, ...] = ()
    check_id: Optional[int] = None

    def to_json(self) -> Dict[str, Any]:
        return {"decision": self.decision, "reasons": list(self.reasons), "check_id": self.check_id}


def _int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _parse_external_id(text: Any) -> Optional[Dict[str, Any]]:
    """The payload if `text` is exactly a well-formed v1 external id (closed keys), else None."""
    if not isinstance(text, str) or len(text) > 4096:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict) or set(data) != set(_KEYS) or data["schema"] != SCHEMA:
        return None
    if not isinstance(data["repo"], str) or not _REPO.match(data["repo"]) or not _int(data["pr"]) or data["pr"] <= 0:
        return None
    if data["decision"] not in DECISIONS:
        return None
    for k in ("head_sha", "merge_base"):
        if not isinstance(data[k], str) or not _SHA40.match(data[k]):
            return None
    for k in ("verdict_digest", "policy_sha256", "evidence_digest"):
        if not isinstance(data[k], str) or not _DIGEST.match(data[k]):
            return None
    return data


def verify_check(
    check_runs: Iterable[Any],
    *,
    expected_app_id: int,
    repo: str,
    pr: int,
    live_head: str,
    live_merge_base: str,
    block_labels: Sequence[str] = DEFAULT_BLOCK_LABELS,
    labels: Sequence[str] = (),
    expected_evidence_digest: Optional[str] = None,
    expected_policy_sha256: Optional[str] = None,
) -> Admission:
    """Decide from the check runs listed for the pull request's live head.

    admit   the highest-id `merge eligibility` check from the expected App is completed, success, for the live head and
            repo/PR, consistent with its payload, with the live merge base (and the expected evidence/policy digests when
            given), and no block label is present.
    wait    evidence is missing, pending, stale, malformed or inconsistent, or the decision is HOLD/ESCALATE (neutral).
            Never an admission, never a withdrawal.
    cancel  the current check says REJECT (failure) for the live head: withdraw any earlier approval.
    ignore  a block label is present: the pull request opted out of automation; take no action either way.

    Only the check with the highest id among those from the expected App with the exact name counts; a malformed newest check
    is not skipped in favour of an older good one. Other Apps' checks with the same name are invisible. The caller must list
    ALL check runs for the head (every page, filter=all) before calling.
    """
    if not _int(expected_app_id) or expected_app_id <= 0 or not _int(pr) or pr <= 0:
        return Admission("wait", ("bad_expectation",))
    if not isinstance(live_head, str) or not _SHA40.match(live_head) or not isinstance(repo, str) or not _REPO.match(repo):
        return Admission("wait", ("bad_expectation",))
    blocked = {str(x).lower() for x in block_labels}
    if any(isinstance(x, str) and x.lower() in blocked for x in labels):
        return Admission("ignore", ("block_label",))
    candidates: List[Mapping[str, Any]] = []
    for c in check_runs if isinstance(check_runs, (list, tuple)) else ():
        if not isinstance(c, Mapping) or c.get("name") != CHECK_NAME or not _int(c.get("id")):
            continue
        app = c.get("app")
        if not isinstance(app, Mapping) or not _int(app.get("id")) or app.get("id") != expected_app_id:
            continue
        candidates.append(c)
    if not candidates:
        return Admission("wait", ("no_eligibility_check",))
    check = max(candidates, key=lambda c: c["id"])
    cid = check["id"]

    def out(decision: str, *reasons: str) -> Admission:
        return Admission(decision, tuple(reasons), cid)

    if check.get("head_sha") != live_head:
        return out("wait", "stale_head")
    if check.get("status") != "completed":
        return out("wait", "check_not_completed")
    payload = _parse_external_id(check.get("external_id"))
    if payload is None:
        return out("wait", "external_id_malformed")
    if payload["repo"].lower() != repo.lower() or payload["pr"] != pr:
        return out("wait", "wrong_repo_or_pr")
    if payload["head_sha"] != live_head:
        return out("wait", "payload_head_mismatch")
    conclusion = check.get("conclusion")
    if conclusion not in ("success", "neutral", "failure") or CONCLUSION_FOR[payload["decision"]] != conclusion:
        return out("wait", "conclusion_mismatch")
    if expected_evidence_digest is not None and payload["evidence_digest"] != expected_evidence_digest:
        return out("wait", "evidence_digest_mismatch")
    if expected_policy_sha256 is not None and payload["policy_sha256"] != expected_policy_sha256:
        return out("wait", "policy_mismatch")
    if conclusion == "failure":
        return out("cancel", "review_rejected")
    if conclusion == "neutral":
        return out("wait", "review_not_accepted")
    if not isinstance(live_merge_base, str) or not _SHA40.match(live_merge_base):
        return out("wait", "live_merge_base_invalid")
    if payload["merge_base"] != live_merge_base:
        return out("wait", "merge_base_stale")
    return out("admit", "eligible")


# --------------------------------------------------------------------------- CLI


def _load_checks(path: str) -> List[Any]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        data = data.get("check_runs")
    if not isinstance(data, list):
        raise ValueError("checks file must be a list or {\"check_runs\": [...]}")
    return data


def main(argv: Optional[Sequence[str]] = None) -> int:
    """`eligibility verify --checks FILE --app-id N --repo R --pr N --head SHA --merge-base SHA [--label L]...`

    Exit 0 only for `admit`; 1 for wait, cancel or ignore; 2 for unusable input. Prints the decision as JSON.
    """
    import argparse

    ap = argparse.ArgumentParser(prog="warden eligibility")
    sub = ap.add_subparsers(dest="cmd")
    v = sub.add_parser("verify")
    v.add_argument("--checks", required=True)
    v.add_argument("--app-id", required=True, type=int)
    v.add_argument("--repo", required=True)
    v.add_argument("--pr", required=True, type=int)
    v.add_argument("--head", required=True)
    v.add_argument("--merge-base", required=True)
    v.add_argument("--label", action="append", default=[])
    v.add_argument("--block-label", action="append", default=None)
    v.add_argument("--evidence-digest")
    v.add_argument("--policy-sha256")
    try:
        ns = ap.parse_args(list(sys.argv[1:] if argv is None else argv))
    except SystemExit as exc:
        return 2 if exc.code not in (0, None) else 0
    if ns.cmd != "verify":
        ap.print_usage(sys.stderr)
        return 2
    try:
        checks = _load_checks(ns.checks)
    except (OSError, ValueError) as exc:
        print("cannot read checks: %s" % str(exc)[:200], file=sys.stderr)
        return 2
    adm = verify_check(
        checks,
        expected_app_id=ns.app_id,
        repo=ns.repo,
        pr=ns.pr,
        live_head=ns.head,
        live_merge_base=ns.merge_base,
        block_labels=tuple(ns.block_label) if ns.block_label is not None else DEFAULT_BLOCK_LABELS,
        labels=tuple(ns.label),
        expected_evidence_digest=ns.evidence_digest,
        expected_policy_sha256=ns.policy_sha256,
    )
    print(json.dumps(adm.to_json(), sort_keys=True))
    if adm.reasons == ("bad_expectation",):
        return 2
    return 0 if adm.decision == "admit" else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

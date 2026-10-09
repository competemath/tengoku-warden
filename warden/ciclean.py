"""Pure transforms for a platform-sourced CI record collector (workflow wiring lives elsewhere).

What it does: turns GitHub Actions API payloads into normalised run records using the platform's own timestamps and identities
(`run_record`), cuts a short, scrubbed failure excerpt out of a job log (`failure_excerpt`), classifies the failure with
anchored, versioned, individually named rules (`classify_failure`), decides which runs to fetch within a call budget
(`plan_collection`), moves the per-repository coverage watermark only when the numbers reconcile (`advance_watermark`), and
computes failure rates with Wilson intervals per actor and per agent (`failure_rates`). No network, no clock reads: every
function takes its inputs, including `now`, as arguments.

Credit: the Tau Ceti Project's TauCetiCI collector (research report 2026-10-09, part A; collect.yml 8bf479e, 2026-09-27) is the
model: records come from the platform, never from an agent, durations are derived from platform timestamps, and a per-repository
cursor advances only past runs actually recorded, holding back for queued, in-progress and unaffordable runs and releasing a run
active for more than 6 hours. We also build on what their history showed: the 2026-09-27 incident (b64d04e) where a run that was
active when collected was missing while the watermark moved past it, the 2026-10-01 incident (d983506) where five repositories
recorded nothing for about three days because a backlog spent the call budget, the stuck waiting run that pinned the watermark
(3f82c1d), and an unreported defect in their classifier: its `timeout` rule matched the bare substring `Killed`, so module names
such as `...KilledByRank` made 271 of 274 failure-conclusion "timeout" jobs with excerpts timeouts only by accident, overstating
the published timeout share (their data, our analysis of it, 2026-10-09).

What we do differently: (1) rules are anchored to whole lines and carry ids, the matched rule id is stored next to the class, the
`VERSION` is stamped, and golden-log tests include the exact `Killed` trap; (2) the watermark REFUSES to advance when the number
of runs recorded plus those deliberately held back does not equal the API `total_count` for the window, so a silent gap cannot
be walked past; (3) records keep `triggering_actor` as well as `actor`, a hash of the raw API response, and every job (the job
fetch budget decides ordering, oldest first, not which runs get jobs at all); (4) failure rates are broken down by actor and by
agent through a human-owned mapping, which their data supports but their analysis never did.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

VERSION = 1  # classifier version; bump when a rule changes and keep old records' version beside them
SCHEMA = "tengoku-warden.ci-run/v1"
_SHA40 = re.compile(r"^[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"^[0-9a-f]{64}\Z")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_TS_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})\Z")
STUCK_AFTER_S = 6 * 3600
MAX_LOG_EXCERPT_LINES = 30
MAX_LINE_CHARS = 300


# --------------------------------------------------------------------------- time helpers


def parse_ts(value: Any) -> Optional[_dt.datetime]:
    """RFC 3339 -> aware UTC datetime, or None when the value is missing or malformed."""
    if not isinstance(value, str):
        return None
    m = _TS_RE.match(value)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(x) for x in m.groups()[:6])
    tz = m.group(7)
    try:
        dt = _dt.datetime(y, mo, d, h, mi, s, tzinfo=_dt.timezone.utc)
    except ValueError:
        return None
    if tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        dt = dt - sign * _dt.timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
    return dt


def fmt_ts(dt: _dt.datetime) -> str:
    return dt.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _secs(a: Any, b: Any) -> Optional[int]:
    da, db = parse_ts(a), parse_ts(b)
    if da is None or db is None:
        return None
    d = int((db - da).total_seconds())
    return d if d >= 0 else None


def _s(value: Any, limit: int = 200) -> Optional[str]:
    if value is None:
        return None
    return _CTRL.sub("", str(value))[:limit]


def _login(obj: Any) -> Optional[str]:
    if isinstance(obj, dict):
        return _s(obj.get("login"), 100)
    return None


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_digest(raw: bytes) -> str:
    """Hash of the raw API response bytes, in the form `run_record` expects for `api_response_sha256`."""
    return "sha256:" + hashlib.sha256(raw).hexdigest()


# --------------------------------------------------------------------------- run records


def run_record(
    api_run: Mapping[str, Any],
    api_jobs: Any,
    api_response_sha256: str,
    *,
    jobs_total_count: Optional[int] = None,
) -> Dict[str, Any]:
    """Normalise one workflow run and its jobs. Raises ValueError on a payload that is not a plausible API run.

    `api_jobs` is the `jobs` array (or the whole `{"jobs": [...]}` response). `api_response_sha256` is the hash of the raw
    bytes the API returned, so a stored record can later be checked against a re-fetch. `jobs_total_count`, when given,
    is the API's `total_count` for the jobs; a shortfall is recorded as `jobs_complete: false`, never hidden.
    """
    if not isinstance(api_run, Mapping):
        raise ValueError("run payload is not an object")
    run_id, attempt = api_run.get("id"), api_run.get("run_attempt", 1)
    if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0:
        raise ValueError("run id missing or invalid")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise ValueError("run_attempt invalid")
    head_sha = api_run.get("head_sha")
    if not isinstance(head_sha, str) or not _SHA40.match(head_sha):
        raise ValueError("head_sha missing or not 40 hex")
    digest = api_response_sha256
    if isinstance(digest, str) and digest.startswith("sha256:"):
        digest = digest[7:]
    if not isinstance(digest, str) or not _HEX64.match(digest):
        raise ValueError("api_response_sha256 must be a sha256 hex digest")
    created = api_run.get("created_at")
    if parse_ts(created) is None:
        raise ValueError("created_at missing or malformed")
    if isinstance(api_jobs, Mapping):
        api_jobs = api_jobs.get("jobs")
    if not isinstance(api_jobs, list):
        raise ValueError("jobs must be a list")

    repo = api_run.get("repository")
    started = api_run.get("run_started_at") or created
    jobs: List[Dict[str, Any]] = []
    for j in api_jobs:
        if not isinstance(j, Mapping):
            raise ValueError("job is not an object")
        jid = j.get("id")
        if isinstance(jid, bool) or not isinstance(jid, int):
            raise ValueError("job id invalid")
        steps = []
        failed_step = None
        for st in j.get("steps") or []:
            if not isinstance(st, Mapping):
                continue
            entry = {
                "number": st.get("number") if isinstance(st.get("number"), int) else None,
                "name": _s(st.get("name")),
                "conclusion": _s(st.get("conclusion"), 40),
                "started_at": _s(st.get("started_at"), 40),
                "completed_at": _s(st.get("completed_at"), 40),
                "duration_s": _secs(st.get("started_at"), st.get("completed_at")),
            }
            steps.append(entry)
            if failed_step is None and entry["conclusion"] in ("failure", "timed_out", "cancelled"):
                failed_step = entry
        labels = [x for x in (j.get("labels") or []) if isinstance(x, str)]
        jobs.append(
            {
                "id": jid,
                "name": _s(j.get("name")),
                "status": _s(j.get("status"), 40),
                "conclusion": _s(j.get("conclusion"), 40),
                "runner_labels": sorted(_s(x, 80) or "" for x in labels),
                "runner_name": _s(j.get("runner_name"), 100),
                "runner_group": _s(j.get("runner_group_name"), 100),
                "created_at": _s(j.get("created_at"), 40),
                "started_at": _s(j.get("started_at"), 40),
                "completed_at": _s(j.get("completed_at"), 40),
                "queue_s": _secs(j.get("created_at"), j.get("started_at")),
                "duration_s": _secs(j.get("started_at"), j.get("completed_at")),
                "failed_step": failed_step,
                "steps": steps,
            }
        )
    jobs.sort(key=lambda x: x["id"])
    return {
        "schema": SCHEMA,
        "repo": _s(repo.get("full_name"), 140) if isinstance(repo, Mapping) else None,
        "run_id": run_id,
        "attempt": attempt,
        "workflow": _s(api_run.get("name")),
        "workflow_path": _s(api_run.get("path")),
        "event": _s(api_run.get("event"), 40),
        "status": _s(api_run.get("status"), 40),
        "conclusion": _s(api_run.get("conclusion"), 40),
        "head_sha": head_sha,
        "head_branch": _s(api_run.get("head_branch")),
        "actor": _login(api_run.get("actor")),
        "triggering_actor": _login(api_run.get("triggering_actor")),
        "created_at": created,
        "run_started_at": _s(started, 40),
        "updated_at": _s(api_run.get("updated_at"), 40),
        "queue_s": _secs(created, started),
        "duration_s": _secs(started, api_run.get("updated_at")),
        "jobs_complete": jobs_total_count is None or jobs_total_count == len(jobs),
        "jobs": jobs,
        "api_response_sha256": "sha256:" + digest,
    }


def record_key(rec: Mapping[str, Any]) -> Tuple[Any, Any, Any]:
    return (rec.get("repo"), rec.get("run_id"), rec.get("attempt"))


# --------------------------------------------------------------------------- failure excerpt


_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")
_LOG_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?Z ?")
_ERROR_LINE = re.compile(
    r"##\[error\]|\berror\b|\bfailed\b|\bfailure\b|exit code|Traceback|\btimed? ?out\b|\bkilled\b|\bterminated\b"
    r"|\bcancel+ed\b|\bfatal\b|\bpanic\b|out of memory|shutdown signal|exceeded the maximum|\bwatchdog\b",
    re.IGNORECASE,
)
_ECHOED_COMMAND = re.compile(r"::(?:error|warning|notice)(?:\s|::)")


def failure_excerpt(
    log_text: str,
    step_window: Optional[Tuple[str, str]] = None,
    *,
    slack_s: int = 1,
) -> List[str]:
    """Up to 30 error lines from a job log, ANSI stripped, 300 characters each, source echoes skipped.

    `step_window` is the failing step's (started_at, completed_at) from the jobs API; only log lines whose own timestamp
    falls inside it (plus `slack_s` either side, since the API rounds to seconds) are considered. Lines without a timestamp
    belong to the preceding stamped line. Lines containing a workflow command like `::error::` are the echoed SOURCE of a
    step (`echo "::error::..."`), not an error that happened, and are skipped. When more than 30 lines match, the first 15
    and last 15 are kept (watchdog and exit-code lines come at the end).
    """
    if not isinstance(log_text, str):
        return []
    lo = hi = None
    if step_window is not None:
        a, b = parse_ts(step_window[0]), parse_ts(step_window[1])
        if a is None or b is None or b < a:
            return []  # fail closed: a bad window gives no excerpt rather than the wrong step's lines
        lo, hi = a - _dt.timedelta(seconds=slack_s), b + _dt.timedelta(seconds=slack_s + 1)
    keep: List[str] = []
    inside = lo is None
    for raw in log_text.splitlines():
        line = _ANSI.sub("", raw)
        m = _LOG_TS.match(line)
        if m and lo is not None:
            ts = parse_ts(m.group(1) + "Z")
            inside = ts is not None and lo <= ts < hi
        if m:
            line = line[m.end():]
        if not inside:
            continue
        line = _CTRL.sub("", line).rstrip()
        if not line or _ECHOED_COMMAND.search(line):
            continue
        if line.startswith(("##[group]", "##[endgroup]")):
            continue
        if _ERROR_LINE.search(line):
            keep.append(line[:MAX_LINE_CHARS])
    if len(keep) > MAX_LOG_EXCERPT_LINES:
        half = MAX_LOG_EXCERPT_LINES // 2
        keep = keep[:half] + keep[-half:]
    return keep


# --------------------------------------------------------------------------- classifier


@dataclass(frozen=True)
class Rule:
    rule_id: str
    klass: str
    pattern: "re.Pattern[str]"


def _r(rule_id: str, klass: str, pattern: str) -> Rule:
    return Rule(rule_id, klass, re.compile(pattern))


_PFX = r"(?:##\[error\])?"
# Every pattern is matched with .search against ONE whole line and starts with ^ and ends with $: a word buried inside a
# module name or a path can never match. Order is priority: the first rule that matches any line wins.
RULES: Tuple[Rule, ...] = (
    _r("timeout.gha_job_limit", "timeout", r"^" + _PFX + r"The job running on runner .{1,100} has exceeded the maximum execution time of \d+ minutes\.$"),
    _r("timeout.gha_step_limit", "timeout", r"^" + _PFX + r"The action '.{1,100}' has timed out after \d+ minutes\.$"),
    _r("timeout.coreutils_exit_124", "timeout", r"^" + _PFX + r"Process completed with exit code 124\.?$"),
    _r("timeout.coreutils_signal", "timeout", r"^timeout: sending signal (?:TERM|KILL|INT) to command '.{1,200}'$"),
    _r("timeout.watchdog_deadline", "timeout", r"^(?:[a-z][a-z0-9_]*[-_])?watchdog: (?:deadline exceeded|timed out)(?: after \d+ ?s)?\b.{0,120}$"),
    _r("runner.lost_communication", "runner_lost", r"^" + _PFX + r"The self-hosted runner: .{1,100} lost communication with the server\..{0,200}$"),
    _r("runner.shutdown_signal", "runner_lost", r"^" + _PFX + r"The runner has received a shutdown signal\..{0,200}$"),
    _r("oom.kernel_killer", "oom", r"^(?:\[[ \d.]+\] )?Out of memory: Killed process \d+ \(.{1,80}\).{0,200}$"),
    _r("oom.bad_alloc", "oom", r"^(?:terminate called after throwing an instance of 'std::bad_alloc'|.{0,40}std::bad_alloc)$"),
    _r("oom.lean_out_of_memory", "oom", r"^(?:INTERNAL PANIC: )?out of memory$"),
    # The shell's job-control line for a SIGKILLed child: '<script>: line N: <pid> Killed   <command>'. `Killed` must be a
    # whole word directly after a numeric pid (or alone on its line), never part of an identifier.
    _r("killed.shell_job_message", "killed", r"^(?:\S.{0,200}: line \d+: +\d+ +Killed(?: +\S.{0,250})?|Killed)$"),
    _r("killed.exit_137", "killed", r"^" + _PFX + r"Process completed with exit code 137\.?$"),
    _r("cancelled.gha_operation_canceled", "cancelled", r"^" + _PFX + r"The operation was canceled\.$"),
    _r("cancelled.gha_cancel_signal", "cancelled", r"^" + _PFX + r"The runner has received a (?:cancel|cancellation) signal\.?$"),
    _r("network.gha_download_failed", "network", r"^" + _PFX + r"(?:Failed to download|Unable to download) .{1,200}$"),
    _r("network.curl_failure", "network", r"^curl: \(\d+\) .{1,200}$"),
    _r("network.git_remote_hung_up", "network", r"^(?:fatal|error): (?:the remote end hung up unexpectedly|RPC failed;.{0,200})$"),
    _r("build.lean_error", "build", r"^error: \S{1,300}\.lean:\d+:\d+: .{0,250}$"),
    _r("build.lake_build_failed", "build", r"^(?:error: )?build failed$"),
    _r("lint.env_failed", "lint", r"^" + _PFX + r"(?:lint-env|lint|#lint)[: ].{0,100}\b(?:failed|errors?)\b.{0,100}$"),
    _r("test.failed", "test", r"^" + _PFX + r"(?:FAILED|FAIL)[: ].{0,250}$"),
    _r("exit.generic", "exit_nonzero", r"^" + _PFX + r"Process completed with exit code [1-9]\d{0,2}\.?$"),
)


def classify_failure(excerpt: Any) -> Tuple[str, str]:
    """(class, rule_id) for an excerpt (a list of lines, or one string). `("unknown", "none")` when nothing matches.

    Every rule is anchored to a whole line, rules are tried in priority order, and the rule id is returned so it can be
    stored beside the class and a wrong rule found later.
    """
    if isinstance(excerpt, str):
        lines = excerpt.splitlines()
    elif isinstance(excerpt, (list, tuple)):
        lines = [x for x in excerpt if isinstance(x, str)]
    else:
        return ("unknown", "bad_input")
    lines = [_ANSI.sub("", ln).strip() for ln in lines]
    lines = [ln for ln in lines if ln]
    if not lines:
        return ("unknown", "empty_excerpt")
    for rule in RULES:
        for ln in lines:
            if rule.pattern.search(ln):
                return (rule.klass, rule.rule_id)
    return ("unknown", "none")


# --------------------------------------------------------------------------- collection planning


@dataclass
class CollectionPlan:
    fetch: List[Tuple[int, int]] = field(default_factory=list)  # (run_id, attempt), oldest first
    already_recorded: List[Tuple[int, int]] = field(default_factory=list)
    pending: List[int] = field(default_factory=list)  # not completed yet: hold the watermark
    deferred: List[int] = field(default_factory=list)  # completed but over budget: hold the watermark
    skipped_invalid: List[Any] = field(default_factory=list)

    def to_json(self) -> Dict[str, Any]:
        return {
            "fetch": [list(x) for x in self.fetch],
            "already_recorded": [list(x) for x in self.already_recorded],
            "pending": self.pending,
            "deferred": self.deferred,
            "skipped_invalid": self.skipped_invalid,
        }


def _index_keys(index: Iterable[Any]) -> set:
    keys = set()
    for k in index:
        if isinstance(k, str) and ":" in k:
            a, b = k.split(":", 1)
            if a.isdigit() and b.isdigit():
                keys.add((int(a), int(b)))
        elif isinstance(k, (tuple, list)) and len(k) == 2 and all(isinstance(x, int) for x in k):
            keys.add((k[0], k[1]))
    return keys


def plan_collection(index: Iterable[Any], runs: Sequence[Mapping[str, Any]], job_fetch_budget: int) -> CollectionPlan:
    """Decide which completed, not-yet-recorded runs get their jobs fetched, oldest first, within `job_fetch_budget` calls.

    `index` holds the recorded keys as (run_id, attempt) pairs or "run_id:attempt" strings. Each fetch costs one jobs call
    (a run with more than one page of jobs costs more; the caller meters that). Oldest-first keeps the recorded set contiguous
    so the watermark can move; whatever the budget cannot cover is `deferred` and must be passed to `advance_watermark` as
    unrecorded so it holds the watermark back.
    """
    if isinstance(job_fetch_budget, bool) or not isinstance(job_fetch_budget, int) or job_fetch_budget < 0:
        raise ValueError("job_fetch_budget must be a non-negative integer")
    have = _index_keys(index)
    plan = CollectionPlan()
    todo: List[Tuple[str, int, int]] = []
    seen = set()
    for r in runs:
        rid = r.get("id") if isinstance(r, Mapping) else None
        att = r.get("run_attempt", 1) if isinstance(r, Mapping) else None
        created = parse_ts(r.get("created_at")) if isinstance(r, Mapping) else None
        if isinstance(rid, bool) or not isinstance(rid, int) or isinstance(att, bool) or not isinstance(att, int) or created is None:
            plan.skipped_invalid.append(rid if isinstance(rid, int) else None)
            continue
        if (rid, att) in seen:
            continue
        seen.add((rid, att))
        if r.get("status") != "completed":
            plan.pending.append(rid)
        elif (rid, att) in have:
            plan.already_recorded.append((rid, att))
        else:
            todo.append((fmt_ts(created), rid, att))
    todo.sort()
    for i, (_c, rid, att) in enumerate(todo):
        if i < job_fetch_budget:
            plan.fetch.append((rid, att))
        else:
            plan.deferred.append(rid)
    plan.pending.sort()
    return plan


# --------------------------------------------------------------------------- watermark


@dataclass
class WatermarkResult:
    advanced: bool
    watermark: Optional[str]  # the new value, or `prev` unchanged when not advanced
    reasons: List[str] = field(default_factory=list)  # stable codes, safe to alert on
    window: Tuple[Optional[str], Optional[str]] = (None, None)  # [start, end) the caller must have queried
    counted: int = 0  # runs this function could account for
    api_total_count: Optional[int] = None
    held_by: List[int] = field(default_factory=list)

    def to_json(self) -> Dict[str, Any]:
        return {
            "advanced": self.advanced,
            "watermark": self.watermark,
            "reasons": self.reasons,
            "window": list(self.window),
            "counted": self.counted,
            "api_total_count": self.api_total_count,
            "held_by": self.held_by,
        }


def window_for(prev: Optional[str], now: str, lag_s: int = 900) -> Tuple[Optional[str], str]:
    """The half-open window [start, end) of `created_at` the caller must query so the counts below mean something."""
    n = parse_ts(now)
    if n is None:
        raise ValueError("now is not an RFC 3339 timestamp")
    return (prev, fmt_ts(n - _dt.timedelta(seconds=lag_s)))


def advance_watermark(
    prev: Optional[str],
    recorded_runs: Sequence[Mapping[str, Any]],
    in_progress_runs: Sequence[Mapping[str, Any]],
    api_total_count: Any,
    now: str,
    *,
    unrecorded_runs: Sequence[Mapping[str, Any]] = (),
    lag_s: int = 900,
    stuck_after_s: int = STUCK_AFTER_S,
) -> WatermarkResult:
    """Move the watermark (all runs created before it are recorded) only as far as the evidence allows.

    The window is `window_for(prev, now, lag_s)`: runs created in [prev, now - lag). `api_total_count` is the API's own count
    for that same window. The result REFUSES (watermark unchanged, reason `count_mismatch`) unless
    recorded + in-progress + unrecorded runs in the window account for exactly `api_total_count`: a run that vanished from the
    list, a repository that recorded nothing, or an API page we never fetched cannot be walked past. When the numbers do
    reconcile, the watermark advances to the window end, or back to the creation time of the oldest queued/in-progress/
    unrecorded run if there is one. An in-progress run older than `stuck_after_s` (6 h) no longer holds the watermark (it is
    still counted, and reported as `stuck:<id>`). Runs are matched by run id; a run listed in two groups is an error.
    The lag keeps very new runs the API may not list yet out of the window. Note the platform returns at most 1000 runs for a
    filtered query: a window with `api_total_count` above that can never reconcile and must be narrowed by the caller.
    """
    def refuse(code: str, **kw: Any) -> WatermarkResult:
        return WatermarkResult(False, prev, [code], counted=kw.get("counted", 0), api_total_count=api_total_count if isinstance(api_total_count, int) else None)

    start = None
    if prev is not None:
        start = parse_ts(prev)
        if start is None:
            return refuse("bad_prev")
    now_dt = parse_ts(now)
    if now_dt is None:
        return refuse("bad_now")
    if isinstance(api_total_count, bool) or not isinstance(api_total_count, int) or api_total_count < 0:
        return refuse("api_total_count_missing")
    end = now_dt - _dt.timedelta(seconds=lag_s)
    window = (fmt_ts(start) if start else None, fmt_ts(end))
    if start is not None and end <= start:
        return WatermarkResult(False, prev, ["empty_window"], window, 0, api_total_count)

    seen: Dict[int, str] = {}
    held: List[Tuple[_dt.datetime, int]] = []
    reasons: List[str] = []

    def take(runs: Sequence[Mapping[str, Any]], group: str) -> Optional[str]:
        for r in runs:
            rid = r.get("id") if isinstance(r, Mapping) else None
            created = parse_ts(r.get("created_at")) if isinstance(r, Mapping) else None
            if isinstance(rid, bool) or not isinstance(rid, int) or created is None:
                return "bad_run_in_" + group
            if created >= end or (start is not None and created < start):
                continue  # outside this window
            if rid in seen:
                return "run_listed_twice"
            seen[rid] = group
            if group == "recorded":
                continue
            if group == "in_progress":
                begun = parse_ts(r.get("run_started_at")) or created
                if (now_dt - begun).total_seconds() > stuck_after_s:
                    reasons.append("stuck:%d" % rid)
                    continue
            held.append((created, rid))
        return None

    for runs, group in ((recorded_runs, "recorded"), (in_progress_runs, "in_progress"), (unrecorded_runs, "unrecorded")):
        bad = take(runs, group)
        if bad:
            return refuse(bad)
    if len(seen) != api_total_count:
        return WatermarkResult(
            False, prev, ["count_mismatch"] + reasons, window, len(seen), api_total_count
        )
    new = end
    if held:
        held.sort()
        new = max(held[0][0], start) if start else held[0][0]
        reasons.append("held_back:%d" % len(held))
    advanced = start is None or new > start
    return WatermarkResult(advanced, fmt_ts(new) if advanced else prev, reasons, window, len(seen), api_total_count, sorted(h[1] for h in held) if held else [])


# --------------------------------------------------------------------------- failure rates


FAILURE_CONCLUSIONS = ("failure", "timed_out", "startup_failure")
COUNTED_CONCLUSIONS = ("success",) + FAILURE_CONCLUSIONS


def wilson(k: int, n: int, z: float = 1.96) -> Optional[Tuple[float, float]]:
    """Wilson score interval for k failures in n runs; None when n is 0."""
    if n <= 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def _stat(k: int, n: int) -> Dict[str, Any]:
    ci = wilson(k, n)
    return {
        "n": n,
        "failures": k,
        "rate": (k / n) if n else None,
        "wilson_low": ci[0] if ci else None,
        "wilson_high": ci[1] if ci else None,
    }


def failure_rates(records: Iterable[Mapping[str, Any]], actor_to_agent: Mapping[str, str]) -> Dict[str, Any]:
    """Failure share with 95% Wilson intervals overall, per `actor`, per `triggering_actor` and per agent.

    Only runs that finished with success, failure, timed_out or startup_failure count (cancelled, skipped and in-progress runs
    say nothing about quality). The agent comes from `actor_to_agent` (a human-owned login -> agent mapping), looking at
    `actor` first, then `triggering_actor`; runs neither maps to are grouped as `unattributed`, never dropped. Duplicate
    (repo, run_id, attempt) records are counted once.
    """
    seen = set()
    tallies: Dict[str, Dict[str, List[int]]] = {"overall": {"all": [0, 0]}, "by_actor": {}, "by_triggering_actor": {}, "by_agent": {}}

    def bump(group: str, key: str, failed: bool) -> None:
        t = tallies[group].setdefault(key, [0, 0])
        t[1] += 1
        t[0] += 1 if failed else 0

    for rec in records:
        if not isinstance(rec, Mapping) or rec.get("conclusion") not in COUNTED_CONCLUSIONS:
            continue
        k = record_key(rec)
        if k in seen:
            continue
        seen.add(k)
        failed = rec["conclusion"] in FAILURE_CONCLUSIONS
        actor, trig = rec.get("actor") or "unknown", rec.get("triggering_actor") or rec.get("actor") or "unknown"
        agent = actor_to_agent.get(actor) or actor_to_agent.get(trig) or "unattributed"
        bump("overall", "all", failed)
        bump("by_actor", actor, failed)
        bump("by_triggering_actor", trig, failed)
        bump("by_agent", agent, failed)
    out: Dict[str, Any] = {"overall": _stat(*tallies["overall"]["all"])}
    for group in ("by_actor", "by_triggering_actor", "by_agent"):
        out[group] = {key: _stat(*t) for key, t in sorted(tallies[group].items())}
    return out

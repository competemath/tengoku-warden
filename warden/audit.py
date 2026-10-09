"""Append-only audit records whose append-only property is enforced, not promised.

What it does: (1) `Chain` writes schema-checked audit records as hash-chained NDJSON, one file per period, the chain running
across the files; (2) `verify_dir` re-checks the whole directory and `head` returns the value to publish out of band;
(3) `ledger_guard` is a required-check for pull requests and pushes: using git objects only, it FAILS if any path that already
existed under the record globs was modified, deleted or changed type between `base` and `head` (only additions pass), if
`head` does not descend from `base` (a rewritten history), or if any single commit in between did such a thing and a later
one hid it; (4) `RECORD_SCHEMA` is a closed-key schema and is enforced on every write and again on every verification.

Credit: the Tau Ceti Project's TauCetiCI keeps its CI records "append-only" by convention (research report on TauCetiCI,
2026-10-09, A2): the collector pushes with contents:write to an unprotected main, there is no hash chain, and the
`schema/run.v1.json` its documentation cites does not exist. Their TauCetiData archive for review runs is likewise described as
append-only but 5 commits modified and 4 deleted existing record or blob paths (TauCetiReview/TauCetiData report, F15). Their
repositories are the reason this module exists; their empirical finding that 359 record files were each added once and never
modified is the property we make checkable.

What we do differently: a hash chain so any edit, reorder or removal breaks every later hash; a head you can pin elsewhere so a
deleted tail or a replaced file is caught; a guard that reads git objects (no checkout, no working tree, no repository config or
replace refs) and fails closed on any error; and a real, closed schema that is validated before a record is written.

Recommended hosting (the guard alone is a check, not a lock): put the records in a repository whose default branch has a
ruleset with `non_fast_forward` and `deletion` rules, restrict who can push to a dedicated GitHub App, make this guard a REQUIRED
status check pinned to that App's integration id, give that App no bypass on the ruleset, and publish `head()` somewhere the
collector cannot write (a release note, a signed tag, a second repository). Honest limit: an actor who can both rewrite the
branch and the published head defeats the chain; signatures are not implemented here.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from .caps import GENESIS, LedgerError, canonical_json, entry_line, lock_fd, make_entry, parse_chain, read_all, write_all

SCHEMA_ID = "tengoku-warden.audit/v1"
RECORD_KIND = "audit.record"
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_ACTION = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)*\Z")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}\Z")
_PERIOD = re.compile(r"^\d{4}-\d{2}(-\d{2})?\Z")
_FILE = re.compile(r"^(?P<prefix>[a-z0-9_]+)-(?P<period>\d{4}-\d{2}(?:-\d{2})?)\.ndjson\Z")
MAX_RECORD_BYTES = 4096
MAX_DETAIL_KEYS = 16

# Closed schema: a key not listed here is an error. type: "str" | "enum" | "const" | "detail".
RECORD_SCHEMA: Dict[str, Dict[str, Any]] = {
    "schema": {"type": "const", "value": SCHEMA_ID, "required": True},
    "ts": {"type": "str", "pattern": _TS, "required": True},  # supplied by the caller, UTC, second resolution
    "actor": {"type": "str", "max": 100, "required": True},  # who acted (login, service, run id)
    "agent": {"type": "str", "max": 100, "required": False},  # which AI agent, from a human-owned mapping
    "action": {"type": "str", "pattern": _ACTION, "max": 64, "required": True},
    "target": {"type": "str", "max": 300, "required": False},
    "outcome": {"type": "enum", "values": ("allow", "deny", "error", "info"), "required": True},
    "case": {"type": "str", "max": 200, "required": False},
    "rule": {"type": "str", "max": 100, "required": False},
    "evidence": {"type": "str", "pattern": _DIGEST, "required": False},  # sha256:<hex> of the evidence this refers to
    "detail": {"type": "detail", "required": False},  # flat map of short scalars, at most 16 keys
}


class RecordError(ValueError):
    """The record does not satisfy RECORD_SCHEMA."""


class ChainError(Exception):
    """The audit directory failed verification, or an append was refused."""


def validate_record(rec: Any) -> List[str]:
    """Return a list of problems ([] means valid). Closed keys, exact types, no control characters, bounded size."""
    errs: List[str] = []
    if not isinstance(rec, dict):
        return ["record must be an object"]
    for k in rec:
        if k not in RECORD_SCHEMA:
            errs.append("unknown key %r" % (k if isinstance(k, str) and len(k) < 40 else "?"))
    for k, spec in RECORD_SCHEMA.items():
        if k not in rec:
            if spec["required"]:
                errs.append("missing key %r" % k)
            continue
        v = rec[k]
        t = spec["type"]
        if t == "const":
            if v != spec["value"] or not isinstance(v, str):
                errs.append("%s must be %r" % (k, spec["value"]))
        elif t == "enum":
            if not isinstance(v, str) or v not in spec["values"]:
                errs.append("%s must be one of %s" % (k, "/".join(spec["values"])))
        elif t == "str":
            if not isinstance(v, str) or not v:
                errs.append("%s must be a non-empty string" % k)
                continue
            if len(v) > spec.get("max", 300):
                errs.append("%s too long" % k)
            if _CTRL.search(v):
                errs.append("%s has control characters" % k)
            pat = spec.get("pattern")
            if pat is not None and not pat.match(v):
                errs.append("%s has the wrong shape" % k)
        elif t == "detail":
            if not isinstance(v, dict) or len(v) > MAX_DETAIL_KEYS:
                errs.append("detail must be a flat object with at most %d keys" % MAX_DETAIL_KEYS)
                continue
            for dk, dv in v.items():
                if not isinstance(dk, str) or not (1 <= len(dk) <= 40) or _CTRL.search(dk):
                    errs.append("detail key is invalid")
                if isinstance(dv, bool) or dv is None:
                    continue
                if isinstance(dv, int):
                    if abs(dv) > 2 ** 53:
                        errs.append("detail number too large")
                elif isinstance(dv, str):
                    if len(dv) > 200 or _CTRL.search(dv):
                        errs.append("detail string invalid")
                else:
                    errs.append("detail values must be short scalars")
    if not errs:
        try:
            if len(canonical_json(rec).encode("utf-8")) > MAX_RECORD_BYTES:
                errs.append("record larger than %d bytes" % MAX_RECORD_BYTES)
        except (TypeError, ValueError):
            errs.append("record is not JSON serialisable")
    return errs


def check_record(rec: Any) -> Dict[str, Any]:
    errs = validate_record(rec)
    if errs:
        raise RecordError("; ".join(errs[:5]))
    return rec


# --------------------------------------------------------------------------- the chain across period files


@dataclass
class VerifyResult:
    ok: bool
    entries: int = 0
    head: str = GENESIS
    files: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_json(self) -> Dict[str, Any]:
        return {"ok": self.ok, "entries": self.entries, "head": self.head, "files": self.files, "errors": self.errors}


def _list_files(path: str, prefix: str) -> List[Tuple[str, str]]:
    out = []
    for name in sorted(os.listdir(path)):
        m = _FILE.match(name)
        if m and m.group("prefix") == prefix:
            out.append((m.group("period"), name))
    return sorted(out)


def verify_dir(path: str, expected_head: Optional[str] = None, prefix: str = "audit") -> VerifyResult:
    """Verify every period file, in order, as one chain, and every record against RECORD_SCHEMA. Never raises on bad data."""
    res = VerifyResult(ok=False)
    try:
        files = _list_files(path, prefix)
    except OSError as exc:
        res.errors.append("directory unreadable: %s" % exc.__class__.__name__)
        return res
    prev, seq = GENESIS, 0
    for _period, name in files:
        full = os.path.join(path, name)
        try:
            st = os.lstat(full)
            if not stat.S_ISREG(st.st_mode):
                res.errors.append("%s: not a regular file" % name)
                return res
            with open(full, "rb") as fh:
                data = fh.read()
            entries, prev = parse_chain(data, prev, seq)
        except LedgerError as exc:
            res.errors.append("%s: %s" % (name, exc))
            return res
        except OSError as exc:
            res.errors.append("%s: unreadable: %s" % (name, exc.__class__.__name__))
            return res
        for e in entries:
            if e["kind"] != RECORD_KIND:
                res.errors.append("%s: entry %d has kind %r" % (name, e["seq"], e["kind"]))
                return res
            errs = validate_record(e["body"])
            if errs:
                res.errors.append("%s: entry %d violates the schema: %s" % (name, e["seq"], errs[0]))
                return res
        seq += len(entries)
        res.files.append(name)
    res.entries, res.head = seq, prev
    if expected_head is not None and prev != expected_head:
        res.errors.append("head %s does not match the published head" % prev)
        return res
    res.ok = True
    return res


def head(path: str, prefix: str = "audit") -> str:
    """The chain head to publish out of band. Raises ChainError when the directory does not verify."""
    r = verify_dir(path, prefix=prefix)
    if not r.ok:
        raise ChainError("; ".join(r.errors))
    return r.head


class Chain:
    """Writer for the audit directory. One process at a time per directory is enforced with an advisory lock."""

    def __init__(self, directory: str, prefix: str = "audit") -> None:
        if not re.fullmatch(r"[a-z0-9_]+", prefix):
            raise ValueError("prefix must be lowercase letters, digits and underscores")
        self.directory = str(directory)
        self.prefix = prefix

    @contextlib.contextmanager
    def _lock(self) -> Iterator[None]:
        os.makedirs(self.directory, exist_ok=True)
        fd = os.open(os.path.join(self.directory, ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            lock_fd(fd)
            yield
        finally:
            os.close(fd)

    def head(self) -> str:
        return head(self.directory, self.prefix)

    def append(self, record: Dict[str, Any], period: str) -> Dict[str, Any]:
        """Validate, then append to the file for `period` (YYYY-MM or YYYY-MM-DD, never earlier than the latest file)."""
        check_record(record)
        if not isinstance(period, str) or not _PERIOD.match(period):
            raise ChainError("period must be YYYY-MM or YYYY-MM-DD")
        with self._lock():
            res = verify_dir(self.directory, prefix=self.prefix)
            if not res.ok:
                raise ChainError("refusing to append to a chain that does not verify: %s" % "; ".join(res.errors))
            files = _list_files(self.directory, self.prefix)
            if files and period < files[-1][0]:
                raise ChainError("period %s is earlier than the latest file %s" % (period, files[-1][0]))
            entry = make_entry(res.entries, RECORD_KIND, record, res.head)
            name = "%s-%s.ndjson" % (self.prefix, period)
            fd = os.open(os.path.join(self.directory, name), os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o644)
            try:
                write_all(fd, entry_line(entry))
            finally:
                os.close(fd)
            with contextlib.suppress(OSError):  # make the new file's directory entry durable
                dfd = os.open(self.directory, os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            return entry


# --------------------------------------------------------------------------- the git guard


_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
MAX_COMMITS = 2000


@dataclass
class Violation:
    path: str
    status: str  # git's letter: M modified, D deleted, T type change, U unmerged, X unknown
    commit: str  # "" for the net base..head diff, else the commit that did it

    def to_json(self) -> Dict[str, str]:
        return {"path": self.path, "status": self.status, "commit": self.commit}


@dataclass
class GuardResult:
    ok: bool
    violations: List[Violation] = field(default_factory=list)
    added: int = 0
    error: str = ""

    def to_json(self) -> Dict[str, Any]:
        return {"ok": self.ok, "added": self.added, "error": self.error, "violations": [v.to_json() for v in self.violations]}


def glob_to_regex(glob: str) -> "re.Pattern[str]":
    """`**` matches across directories, `*` and `?` stay within one path segment. Anchored at both ends."""
    if not isinstance(glob, str) or not glob or glob.startswith("/") or "\x00" in glob:
        raise ValueError("a record glob must be a non-empty repository-relative pattern")
    out, i = [], 0
    while i < len(glob):
        c = glob[i]
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("^" + "".join(out) + r"\Z", re.DOTALL)


def _git_env() -> Dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "LC_ALL": "C",
    }


def _git(repo: str, *args: str, ok_codes: Sequence[int] = (0,)) -> subprocess.CompletedProcess:
    cmd = ["git", "--no-replace-objects", "-C", repo] + list(args)
    cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_git_env(), timeout=120)
    if cp.returncode not in ok_codes:
        raise RuntimeError("git %s failed (%d): %s" % (args[0], cp.returncode, cp.stderr.decode("utf-8", "replace")[:200]))
    return cp


def parse_raw_z(out: bytes) -> List[Tuple[str, str]]:
    """Parse `diff-tree -z --raw --no-renames` output into [(status letter, path)]. Anything unexpected raises ValueError."""
    toks = out.split(b"\0")
    if toks and toks[-1] == b"":
        toks.pop()
    items: List[Tuple[str, str]] = []
    i = 0
    while i < len(toks):
        meta = toks[i]
        if not meta.startswith(b":") or i + 1 >= len(toks):
            raise ValueError("unexpected diff-tree output")
        fields = meta[1:].split(b" ")
        if len(fields) != 5:
            raise ValueError("unexpected diff-tree metadata")
        status = fields[4].decode("ascii", "replace")[:1] or "X"
        if status in ("R", "C"):
            raise ValueError("rename/copy status with --no-renames")
        items.append((status, toks[i + 1].decode("utf-8", "surrogateescape")))
        i += 2
    return items


def ledger_guard(repo: str, base: str, head: str, record_globs: Sequence[str], per_commit: bool = True) -> GuardResult:
    """FAIL if any existing path matching `record_globs` was modified, deleted or retyped between `base` and `head`.

    Reads git objects only (`diff-tree -r -z --raw --no-renames`, replace refs and all repository/global config ignored).
    `base` and `head` must be full object ids, not refs. `head` must descend from `base`. With `per_commit` every commit in
    `base..head` is checked too, so a change that a later commit reverts cannot hide. Every error is a failure.
    """
    try:
        if not record_globs:
            raise ValueError("record_globs must not be empty")
        pats = [glob_to_regex(g) for g in record_globs]
        for label, sha in (("base", base), ("head", head)):
            if not isinstance(sha, str) or not _SHA.match(sha):
                raise ValueError("%s must be a full lowercase object id" % label)
        if set(base) == {"0"}:
            raise ValueError("base is the null object id (new branch): choose the merge base instead")
    except ValueError as exc:
        return GuardResult(False, error=str(exc))
    violations: List[Violation] = []
    seen = set()

    def scan(commit_label: str, *diff_args: str) -> int:
        cp = _git(repo, "diff-tree", "-r", "-z", "--raw", "--no-renames", "--no-commit-id", *diff_args)
        added = 0
        for status, path in parse_raw_z(cp.stdout):
            if not any(p.match(path) for p in pats):
                continue
            if status == "A":
                added += 1
            elif (path, status) not in seen:
                seen.add((path, status))
                violations.append(Violation(path, status, commit_label))
        return added

    try:
        _git(repo, "cat-file", "-e", base + "^{commit}")
        _git(repo, "cat-file", "-e", head + "^{commit}")
        anc = _git(repo, "merge-base", "--is-ancestor", base, head, ok_codes=(0, 1))
        if anc.returncode != 0:
            return GuardResult(False, error="head does not descend from base (history was rewritten or base is wrong)")
        added = scan("", base, head)
        if per_commit:
            commits = _git(repo, "rev-list", "--reverse", "%s..%s" % (base, head)).stdout.decode("ascii").split()
            if len(commits) > MAX_COMMITS:
                return GuardResult(False, error="more than %d commits in range" % MAX_COMMITS)
            for c in commits:
                scan(c, "-m", c)
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as exc:
        return GuardResult(False, error=str(exc)[:300])
    return GuardResult(not violations, violations, added)


# --------------------------------------------------------------------------- CLI


def main(argv: Optional[Sequence[str]] = None) -> int:
    """
    audit verify DIR [--head H] [--prefix P]     exit 1 if the chain or a record is bad
    audit head DIR [--prefix P]                  print the head to publish
    audit guard --repo R --base SHA --head SHA --glob G [--glob G ...] [--no-per-commit]
    """
    import argparse

    ap = argparse.ArgumentParser(prog="warden audit")
    sub = ap.add_subparsers(dest="cmd")
    v = sub.add_parser("verify")
    v.add_argument("dir")
    v.add_argument("--head")
    v.add_argument("--prefix", default="audit")
    h = sub.add_parser("head")
    h.add_argument("dir")
    h.add_argument("--prefix", default="audit")
    g = sub.add_parser("guard")
    g.add_argument("--repo", required=True)
    g.add_argument("--base", required=True)
    g.add_argument("--head", required=True)
    g.add_argument("--glob", action="append", required=True)
    g.add_argument("--no-per-commit", action="store_true")
    try:
        ns = ap.parse_args(list(sys.argv[1:] if argv is None else argv))
    except SystemExit as exc:
        return 2 if exc.code not in (0, None) else 0
    if ns.cmd == "verify":
        r = verify_dir(ns.dir, ns.head, ns.prefix)
        print(json.dumps(r.to_json(), sort_keys=True))
        return 0 if r.ok else 1
    if ns.cmd == "head":
        try:
            print(head(ns.dir, ns.prefix))
        except ChainError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    if ns.cmd == "guard":
        gr = ledger_guard(ns.repo, ns.base, ns.head, ns.glob, per_commit=not ns.no_per_commit)
        print(json.dumps(gr.to_json(), sort_keys=True))
        if gr.ok:
            return 0
        return 1 if gr.violations else 2
    ap.print_usage(sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

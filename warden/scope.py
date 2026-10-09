"""Path-scope enforcement from git objects: which files may this actor's change touch?

Reads ONLY git objects (two commits and their blobs), never the working tree or the
index, and runs git so that hostile repository configuration cannot influence it.
`changed()` lists every change between two commits, `check()` applies a JSON `Policy`
(allowed path globs per actor class, protected human-owned globs, size caps, allowed
file modes, append-only files, delete/binary bans) and returns violations, and
`dropped_human_owned()` flags a push that removes or reverts human-owned work that the
previous head already carried.

Credit: Tau Ceti Project, TauCeti `scope` status (pr-build.yml, scripts/lint_scope_files.py,
lint-scope.sh; the 300-file API truncation finding, issues/PR #12085 and #12207, 2026-10-05),
the size caps of TauCeti PRs #128 and #353, the Progress merge gate's mode and byte-prefix
append checks (TauCetiProgress, Apache-2.0, ideas only), and the 2026-06-23 incident (PRs
#351/#370/#371) where an agent stripped the CI parts of a human-owned PR to get green. Tau
Ceti's worker rule "do not touch these paths" was prompt text and was breached on 2026-07-30
and 2026-07-31 (Roadmap issues #111 and #112); their rule against dropping human-owned work
lives only in AGENTS.md.

What we do differently: the path rule is enforceable by code that takes (repo, base, head,
policy, actor class) and nothing from the agent; modes, size caps, deletions, binary files
and append-only logs are one policy, not scattered scripts; renames are never detected (a
move out of an allowed path is a delete plus an add, each judged on its own path); the
dropped-human-work check exists as code instead of a sentence in AGENTS.md; and every
failure to read or parse is a violation, never a pass. The result is only as strong as the
place it runs: make it a required status or a pre-receive check, not an advisory one.

Glob syntax (shared with `warden.ownership`, CODEOWNERS style): `*` any characters inside
one path segment, `?` one character, `**` any number of segments, a leading `/` anchors at
the repository root, a trailing `/` means a directory (and everything below it), a pattern
with no `/` other than a trailing one matches at any depth, and a pattern whose last
segment has no wildcard also covers everything below it. Character classes are not
supported (brackets are literal).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

ZERO_OID = "0" * 40
_OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
MAX_BLOB_BYTES = 32 * 1024 * 1024

_DEFAULTS = {
    "max_files": 2000,
    "max_added": 2000,
    "max_deleted": 2000,
    "max_new_file_lines": 1000,
}
_POLICY_KEYS = {
    "classes", "protected", "max_files", "max_added", "max_deleted",
    "max_new_file_lines", "new_file_lines_globs", "allowed_modes", "append_only",
    "forbid_delete", "forbid_binary",
}
_CLASS_KEYS = {"allow", "touch_protected"}


class GitError(Exception):
    """git failed, produced unparseable output, or was refused by our own checks."""


class PolicyError(ValueError):
    """The policy JSON is malformed. Callers must treat this as a refusal."""


# --------------------------------------------------------------------------- globs

_GLOB_CACHE: Dict[str, "re.Pattern[str]"] = {}


def _seg_regex(seg: str) -> str:
    out = []
    for ch in seg:
        if ch == "*":
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(ch))
    return "".join(out)


def compile_glob(pattern: str) -> "re.Pattern[str]":
    """Compile a CODEOWNERS-style glob to a regex over repo-relative `/` paths."""
    if not isinstance(pattern, str) or not pattern.strip():
        raise PolicyError("empty glob")
    if pattern in _GLOB_CACHE:
        return _GLOB_CACHE[pattern]
    if pattern != pattern.strip() or "\n" in pattern or "\x00" in pattern:
        raise PolicyError("glob has surrounding whitespace or control characters: %r" % pattern)
    if pattern.startswith("!") or pattern.startswith("#"):
        raise PolicyError("negation and comment globs are not supported: %r" % pattern)
    anchored = pattern.startswith("/")
    body = pattern[1:] if anchored else pattern
    dir_only = body.endswith("/")
    body = body.rstrip("/")
    if not body:
        raise PolicyError("glob matches nothing useful: %r" % pattern)
    if "//" in body:
        raise PolicyError("empty segment in glob: %r" % pattern)
    segs = body.split("/")
    anywhere = (not anchored) and len(segs) == 1
    parts: List[str] = []
    for i, seg in enumerate(segs):
        last = i == len(segs) - 1
        if seg == "**":
            if last:
                parts.append(".+")
            else:
                parts.append("(?:[^/]+/)*")
            continue
        parts.append(_seg_regex(seg) + ("" if last else "/"))
    rx = "".join(parts)
    last_seg = segs[-1]
    descend = dir_only or last_seg == "**" or not any(c in last_seg for c in "*?")
    if last_seg == "**":
        tail = ""
    elif descend:
        tail = "(?:/.+)?" if not dir_only else "/.+"
    else:
        tail = ""
    prefix = "(?:.*/)?" if anywhere else ""
    compiled = re.compile("^" + prefix + rx + tail + "\\Z", re.DOTALL)
    _GLOB_CACHE[pattern] = compiled
    return compiled


def glob_match(pattern: str, path: str) -> bool:
    return compile_glob(pattern).match(path) is not None


def matches_any(patterns: Iterable[str], path: str) -> bool:
    return any(glob_match(p, path) for p in patterns)


# --------------------------------------------------------------------------- policy


def _globs(value, what: str) -> Tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise PolicyError("%s must be a list of strings" % what)
    for g in value:
        compile_glob(g)  # raises PolicyError on junk
    return tuple(value)


def _nonneg(value, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PolicyError("%s must be a non-negative integer" % what)
    return value


@dataclass(frozen=True)
class ActorClass:
    allow: Tuple[str, ...]
    touch_protected: bool = False


@dataclass(frozen=True)
class Policy:
    classes: Dict[str, ActorClass]
    protected: Tuple[str, ...] = ()
    max_files: int = _DEFAULTS["max_files"]
    max_added: int = _DEFAULTS["max_added"]
    max_deleted: int = _DEFAULTS["max_deleted"]
    max_new_file_lines: int = _DEFAULTS["max_new_file_lines"]
    new_file_lines_globs: Tuple[str, ...] = ("**",)
    allowed_modes: Tuple[str, ...] = ("100644",)
    append_only: Tuple[str, ...] = ()
    forbid_delete: Tuple[str, ...] = ()
    forbid_binary: bool = False

    @classmethod
    def from_dict(cls, data) -> "Policy":
        """Strict parse: unknown keys, wrong types, bad globs and bad modes raise PolicyError."""
        if not isinstance(data, dict):
            raise PolicyError("policy must be a JSON object")
        unknown = set(data) - _POLICY_KEYS
        if unknown:
            raise PolicyError("unknown policy keys: %s" % ", ".join(sorted(unknown)))
        raw_classes = data.get("classes")
        if not isinstance(raw_classes, dict) or not raw_classes:
            raise PolicyError("'classes' must be a non-empty object of actor classes")
        classes: Dict[str, ActorClass] = {}
        for name, spec in raw_classes.items():
            if not isinstance(spec, dict) or set(spec) - _CLASS_KEYS or "allow" not in spec:
                raise PolicyError("class %r needs {'allow': [...], 'touch_protected'?: bool}" % name)
            tp = spec.get("touch_protected", False)
            if not isinstance(tp, bool):
                raise PolicyError("class %r: touch_protected must be a boolean" % name)
            classes[name] = ActorClass(_globs(spec["allow"], "class %r allow" % name), tp)
        modes = data.get("allowed_modes", ["100644"])
        if (not isinstance(modes, list) or not modes
                or not all(isinstance(m, str) and re.fullmatch(r"[0-7]{6}", m) for m in modes)):
            raise PolicyError("allowed_modes must be a non-empty list of 6-digit octal strings")
        fd = data.get("forbid_delete", [])
        if fd is True:
            fd = ["**"]
        elif fd is False:
            fd = []
        fb = data.get("forbid_binary", False)
        if not isinstance(fb, bool):
            raise PolicyError("forbid_binary must be a boolean")
        return cls(
            classes=classes,
            protected=_globs(data.get("protected", []), "protected"),
            max_files=_nonneg(data.get("max_files", _DEFAULTS["max_files"]), "max_files"),
            max_added=_nonneg(data.get("max_added", _DEFAULTS["max_added"]), "max_added"),
            max_deleted=_nonneg(data.get("max_deleted", _DEFAULTS["max_deleted"]), "max_deleted"),
            max_new_file_lines=_nonneg(
                data.get("max_new_file_lines", _DEFAULTS["max_new_file_lines"]), "max_new_file_lines"),
            new_file_lines_globs=_globs(data.get("new_file_lines_globs", ["**"]), "new_file_lines_globs"),
            allowed_modes=tuple(modes),
            append_only=_globs(data.get("append_only", []), "append_only"),
            forbid_delete=_globs(fd, "forbid_delete"),
            forbid_binary=fb,
        )

    @classmethod
    def load(cls, path: str) -> "Policy":
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.loads(fh.read(), object_pairs_hook=_no_dupes)
        except (OSError, ValueError) as exc:
            raise PolicyError("cannot read policy %s: %s" % (path, exc))
        return cls.from_dict(data)


def _no_dupes(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key %r" % k)
        out[k] = v
    return out


# --------------------------------------------------------------------------- git


def _git_env() -> Dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/local/bin"),
        "HOME": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_EXTERNAL_DIFF": "",
        "LC_ALL": "C",
    }


def run_git(repo: str, args: Sequence[str], *, timeout: int = 120) -> bytes:
    """Run git with repository config neutralised; return stdout bytes or raise GitError."""
    cmd = ["git", "--no-pager", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull,
           "-c", "core.pager=cat", "-c", "diff.external=", "-c", "core.alternateRefsCommand=",
           "-C", repo] + list(args)
    try:
        proc = subprocess.run(cmd, env=_git_env(), stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitError("git could not run: %s" % exc)
    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", "replace").strip()[:400]
        raise GitError("git %s failed (%d): %s" % (args[0] if args else "", proc.returncode, msg))
    return proc.stdout


def resolve_commit(repo: str, rev: str) -> str:
    if not isinstance(rev, str) or not rev or rev.startswith("-") or "\x00" in rev or "\n" in rev:
        raise GitError("bad revision %r" % (rev,))
    out = run_git(repo, ["rev-parse", "--verify", "--quiet", "--end-of-options", rev + "^{commit}"])
    oid = out.decode("ascii", "replace").strip()
    if not _OID_RE.match(oid):
        raise GitError("revision %r did not resolve to a commit" % rev)
    return oid


@dataclass(frozen=True)
class Change:
    status: str  # A, D, M, T (rename detection is off, so never R or C)
    path: str
    old_mode: str
    new_mode: str
    old_oid: str
    new_oid: str
    added: int = 0
    deleted: int = 0
    binary: bool = False


def _dec(b: bytes) -> str:
    return b.decode("utf-8", "surrogateescape")


def changed(repo: str, base: str, head: str) -> List[Change]:
    """Every change from `base` to `head`, including deletions and mode changes, never truncated.

    Uses `diff-tree -r -z --raw --no-renames` plus numstat. Raises GitError on any failure,
    on a count mismatch between the two listings, or on output it cannot parse.
    """
    b = resolve_commit(repo, base)
    h = resolve_commit(repo, head)
    common = ["diff-tree", "-r", "-z", "--no-renames", "--no-textconv", "--no-ext-diff",
              "--ignore-submodules=none", "--no-abbrev"]
    raw = run_git(repo, common + ["--raw", b, h]).split(b"\x00")
    num = run_git(repo, common + ["--numstat", b, h]).split(b"\x00")
    entries: List[Tuple[str, str, str, str, str, str]] = []
    i = 0
    while i < len(raw) and raw[i] != b"":
        meta = raw[i]
        if not meta.startswith(b":") or i + 1 >= len(raw):
            raise GitError("unparseable diff-tree record")
        fields = meta[1:].split(b" ")
        if len(fields) != 5:
            raise GitError("unparseable diff-tree metadata")
        om, nm, oo, no, st = (x.decode("ascii", "replace") for x in fields)
        if st[:1] in ("R", "C"):
            raise GitError("rename/copy detected although disabled")
        entries.append((st[:1], _dec(raw[i + 1]), om, nm, oo, no))
        i += 2
    stats: Dict[str, Tuple[int, int, bool]] = {}
    for rec in num:
        if rec == b"":
            continue
        parts = _dec(rec).split("\t", 2)
        if len(parts) != 3:
            raise GitError("unparseable numstat record")
        a, d, p = parts
        if a == "-" and d == "-":
            stats[p] = (0, 0, True)
        elif a.isdigit() and d.isdigit():
            stats[p] = (int(a), int(d), False)
        else:
            raise GitError("unparseable numstat counts")
    if len(stats) != len(entries):
        raise GitError("raw and numstat listings disagree (%d vs %d)" % (len(entries), len(stats)))
    out: List[Change] = []
    for st, path, om, nm, oo, no in entries:
        if path not in stats:
            raise GitError("numstat missing path %r" % path)
        a, d, binary = stats[path]
        out.append(Change(st, path, om, nm, oo, no, a, d, binary))
    return out


# --------------------------------------------------------------------------- check


@dataclass(frozen=True)
class Violation:
    code: str
    path: Optional[str]
    detail: str

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {"code": self.code, "path": self.path, "detail": self.detail}


@dataclass
class Result:
    violations: List[Violation] = field(default_factory=list)
    files: int = 0
    added: int = 0
    deleted: int = 0

    @property
    def ok(self) -> bool:
        return not self.violations

    def codes(self) -> List[str]:
        return sorted({v.code for v in self.violations})

    def to_dict(self) -> Dict[str, object]:
        return {"ok": self.ok, "files": self.files, "added": self.added, "deleted": self.deleted,
                "violations": [v.to_dict() for v in self.violations]}


def _unsafe_path(path: str) -> Optional[str]:
    if not path or path.startswith("/"):
        return "empty or absolute path"
    if any(ord(c) < 32 or ord(c) == 127 for c in path):
        return "control character in path"
    for comp in path.split("/"):
        if comp in ("", ".", ".."):
            return "path component %r" % comp
        if comp.lower() == ".git":
            return "path inside a .git directory"
    return None


def _blob(repo: str, oid: str) -> bytes:
    size = int(run_git(repo, ["cat-file", "-s", oid]).strip() or b"-1")
    if size < 0 or size > MAX_BLOB_BYTES:
        raise GitError("blob %s too large to verify (%d bytes)" % (oid[:12], size))
    return run_git(repo, ["cat-file", "blob", oid])


def check(repo: str, base: str, head: str, policy: Policy, actor_class: str) -> Result:
    """Apply `policy` to the change base..head for `actor_class`. Any doubt is a violation."""
    res = Result()
    cls = policy.classes.get(actor_class)
    if cls is None:
        res.violations.append(Violation("unknown_actor_class", None, "no such class: %r" % (actor_class,)))
        return res
    try:
        changes = changed(repo, base, head)
    except GitError as exc:
        res.violations.append(Violation("unreadable_diff", None, str(exc)))
        return res
    res.files = len(changes)
    res.added = sum(c.added for c in changes)
    res.deleted = sum(c.deleted for c in changes)
    if not changes:
        res.violations.append(Violation("empty_diff", None, "no changes between base and head"))
        return res
    add = res.violations.append
    if res.files > policy.max_files:
        add(Violation("too_many_files", None, "%d files > %d" % (res.files, policy.max_files)))
    if res.added > policy.max_added:
        add(Violation("too_many_added_lines", None, "%d added > %d" % (res.added, policy.max_added)))
    if res.deleted > policy.max_deleted:
        add(Violation("too_many_deleted_lines", None, "%d deleted > %d" % (res.deleted, policy.max_deleted)))
    for c in changes:
        p = c.path
        bad = _unsafe_path(p)
        if bad:
            add(Violation("unsafe_path", p, bad))
            continue
        if c.status not in ("A", "D", "M", "T"):
            add(Violation("unexpected_status", p, "status %r" % c.status))
        if not matches_any(cls.allow, p):
            add(Violation("path_not_allowed", p, "outside the %r allowlist (%s)" % (actor_class, c.status)))
        if not cls.touch_protected and matches_any(policy.protected, p):
            add(Violation("protected_path", p, "human-owned path (%s)" % c.status))
        if c.status != "D" and c.new_mode not in policy.allowed_modes:
            add(Violation("mode_not_allowed", p, "mode %s (was %s)" % (c.new_mode, c.old_mode)))
        if c.status == "D" and matches_any(policy.forbid_delete, p):
            add(Violation("delete_forbidden", p, "deleting this path is not allowed"))
        if c.binary and policy.forbid_binary:
            add(Violation("binary_forbidden", p, "binary content"))
        if (c.status == "A" and not c.binary and c.added > policy.max_new_file_lines
                and matches_any(policy.new_file_lines_globs, p)):
            add(Violation("new_file_too_long", p, "%d lines > %d" % (c.added, policy.max_new_file_lines)))
        if matches_any(policy.append_only, p) and c.status != "A":
            if c.status != "M" or c.old_mode != c.new_mode:
                add(Violation("append_only_violated", p, "append-only file was %s" % c.status))
            else:
                try:
                    old, new = _blob(repo, c.old_oid), _blob(repo, c.new_oid)
                except (GitError, ValueError) as exc:
                    add(Violation("append_only_unverifiable", p, str(exc)))
                else:
                    if not (len(new) > len(old) and new.startswith(old)):
                        add(Violation("append_only_violated", p,
                                      "new content is not the old bytes plus an append"))
    return res


# ------------------------------------------------------------------ dropped human work


@dataclass(frozen=True)
class Dropped:
    path: str
    kind: str  # "deleted" or "modified"

    def to_dict(self) -> Dict[str, str]:
        return {"path": self.path, "kind": self.kind}


def dropped_human_owned(repo: str, prev_head: str, head: str, human_globs: Sequence[str],
                        *, allow_paths: Sequence[str] = ()) -> List[Dropped]:
    """Human-owned paths whose content in `head` differs from `prev_head` (removed or reverted).

    Run it on every new push to a branch that already carried human work. Because it compares
    the previous head with the new head directly, it sees a revert to the base that the
    base..head diff shows as no change at all. After a rebase onto a moved base, paths changed
    by the base itself show up too: a human reviewer waives them via `allow_paths`. Raises
    GitError when the diff cannot be read (callers must then refuse the push).
    """
    for g in human_globs:
        compile_glob(g)
    out: List[Dropped] = []
    for c in changed(repo, prev_head, head):
        if not matches_any(human_globs, c.path) or matches_any(allow_paths, c.path):
            continue
        if c.status == "D":
            out.append(Dropped(c.path, "deleted"))
        elif c.status in ("M", "T"):
            out.append(Dropped(c.path, "modified"))
    return out


# --------------------------------------------------------------------------- CLI


def main(argv: Optional[Sequence[str]] = None) -> int:
    """`warden scope --repo . --policy P --base B --head H --class C [--prev-head X] [--json]`."""
    ap = argparse.ArgumentParser(prog="warden scope", description="check a change against a scope policy")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--policy", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--class", dest="actor_class", required=True)
    ap.add_argument("--prev-head", default=None,
                    help="previous head of the branch: also flag dropped human-owned changes")
    ap.add_argument("--json", action="store_true")
    try:
        args = ap.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return 2 if exc.code not in (0, None) else 0
    try:
        policy = Policy.load(args.policy)
    except PolicyError as exc:
        print("scope: bad policy: %s" % exc, file=sys.stderr)
        return 2
    result = check(args.repo, args.base, args.head, policy, args.actor_class)
    dropped: List[Dropped] = []
    if args.prev_head:
        try:
            dropped = dropped_human_owned(args.repo, args.prev_head, args.head, policy.protected)
        except GitError as exc:
            result.violations.append(Violation("unreadable_diff", None, "prev-head: %s" % exc))
        for d in dropped:
            result.violations.append(Violation("human_work_dropped", d.path, d.kind))
    if args.json:
        print(json.dumps(result.to_dict(), sort_keys=True))
    else:
        for v in result.violations:
            print("%s\t%s\t%s" % (v.code, v.path or "-", v.detail))
        print("scope: %s (%d files, +%d -%d)" % ("ok" if result.ok else "REFUSED",
                                                  result.files, result.added, result.deleted))
    return 0 if result.ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

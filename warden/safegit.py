"""Compare-and-swap git pushes and guarded pull-request creation.

`push_cas` moves a remote ref only if it still holds the value the caller last saw
(`--force-with-lease=<ref>:<oid>`), or creates it only if it does not exist yet; it refuses
any call that would amount to an unconditional force. `delete_ref_cas` deletes a ref the
same way. `update_ref_cas_gh_args` builds the `gh api` call that updates a ref through the
GitHub API without force. `install_prepush_hook` blocks raw `git push` in one clone.
`validate_pr` / `pr_create_argv` check a pull request (target marker, base allowlist,
lengths, secret scan) before the `gh pr create` command line is produced.

Credit: Tau Ceti Project, TauCetiWorker `git-safe-push` (commit a1e4fb2, 2026-06-13: lease
on the expected oid, create-only when the expected oid is empty) and `gh-safe-pr-create`
(the `<!--tauceti-target:v1 ...-->` body marker), and TauCetiProgress' merge job, which moves
`refs/heads/main` with `force=false` through the API. Findings we build on: their only test of
git-safe-push used stubs so the compare-and-swap was never exercised; the PR wrapper's claim
and marker environment variables were set by nothing at HEAD (dead code) and it had no tests;
both wrappers were advisory because a plain `git push --force` or `gh pr create` still worked.

What we do differently: the compare-and-swap is tested against a real bare remote (racing
pushes, a second creator loses, stale lease); an unconditional force cannot be expressed
through this API; the target marker is parsed with a closed key set and is really enforced;
secret scanning of the title and body is part of validation (with an explicit way to treat a
missing scanner as failure). The pre-push hook is defence in depth against accidents and
careless agents, NOT a security boundary: anything that can run `git push --no-verify`,
edit `.git/hooks`, set `core.hooksPath` or read the capability file can bypass it. The
boundary is server-side: rulesets, per-branch tokens, required status checks.
"""
from __future__ import annotations

import importlib
import json
import os
import re
import secrets
import shlex
import stat
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

ZERO_OID = "0" * 40
CAP_ENV = "TENGOKU_SAFEGIT_CAP"
CAP_FILE = "tengoku-safegit-cap"
HOOK_MARK = "tengoku-warden:pre-push v1"
_OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_BAD_REF_CHARS = re.compile(r"[\x00-\x20\x7f~^:?*\[\\]")


class UnsafePush(ValueError):
    """The requested operation is refused before git is run."""


@dataclass(frozen=True)
class GitResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class PushResult:
    ok: bool
    reason: str  # ok | exists | lease_mismatch | remote_rejected | hook_rejected | error
    detail: str = ""
    current: Optional[str] = None  # remote value seen, when we know it


# --------------------------------------------------------------------------- helpers


def check_oid(value, name: str = "oid") -> str:
    if not isinstance(value, str) or not _OID_RE.match(value):
        raise UnsafePush("%s must be a full lowercase hex object id" % name)
    return value


def check_ref(ref) -> str:
    """A full ref name: `refs/...`, no whitespace, no revision syntax, no `..`, no `.lock`."""
    if (not isinstance(ref, str) or not ref.startswith("refs/") or len(ref) > 255
            or _BAD_REF_CHARS.search(ref) or ".." in ref or "@{" in ref
            or ref.endswith("/") or ref.endswith(".") or ref.endswith(".lock")
            or "//" in ref or "/." in ref or ref == "refs/"):
        raise UnsafePush("not a safe full ref name: %r" % (ref,))
    return ref


def _check_remote(remote) -> str:
    if (not isinstance(remote, str) or not remote or remote.startswith("-")
            or any(c in remote for c in "\x00\n\r")):
        raise UnsafePush("bad remote %r" % (remote,))
    return remote


def _base_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    env = dict(os.environ)
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                 "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_COMMON_DIR",
                 "GIT_PAGER", "GIT_EXTERNAL_DIFF"):
        env.pop(name, None)
    env["LC_ALL"] = "C"
    env["GIT_TERMINAL_PROMPT"] = "0"
    if extra:
        env.update(extra)
    return env


def run_git(repo: str, args: Sequence[str], *, env: Optional[Dict[str, str]] = None,
            input_bytes: Optional[bytes] = None, timeout: int = 120) -> GitResult:
    """Run git in `repo` with the process environment (credentials intact) minus repo-location vars."""
    cmd = ["git", "-C", repo, "--no-pager"] + list(args)
    try:
        proc = subprocess.run(cmd, env=_base_env(env), input=input_bytes if input_bytes is not None else b"",
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return GitResult(127, "", "git could not run: %s" % exc)
    return GitResult(proc.returncode, proc.stdout.decode("utf-8", "replace"),
                     proc.stderr.decode("utf-8", "replace"))


def _git_dir(repo: str, env: Optional[Dict[str, str]]) -> Optional[str]:
    r = run_git(repo, ["rev-parse", "--absolute-git-dir"], env=env)
    return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None


def _capability_env(repo: str, env: Optional[Dict[str, str]]) -> Dict[str, str]:
    """The environment a wrapped push needs so the pre-push hook lets it through."""
    out = dict(env or {})
    gd = _git_dir(repo, env)
    if gd:
        try:
            with open(os.path.join(gd, CAP_FILE), "r", encoding="ascii") as fh:
                out[CAP_ENV] = fh.read().strip()
        except OSError:
            pass
    return out


def ls_remote(repo: str, remote: str, pattern: Optional[str] = None, *,
              env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Map ref -> oid for the remote's refs matching `pattern`. Raises RuntimeError on failure."""
    _check_remote(remote)
    args = ["ls-remote", "--refs", remote]
    if pattern:
        args.append(pattern)
    r = run_git(repo, args, env=env)
    if r.returncode != 0:
        raise RuntimeError("ls-remote failed: %s" % r.stderr.strip()[:300])
    out: Dict[str, str] = {}
    for line in r.stdout.splitlines():
        oid, _, ref = line.partition("\t")
        if _OID_RE.match(oid) and ref:
            out[ref] = oid
    return out


def _classify(r: GitResult, create_only: bool) -> PushResult:
    text = r.stdout + "\n" + r.stderr
    if r.returncode == 0:
        return PushResult(True, "ok")
    low = text.lower()
    if "stale info" in low or "already exists" in low or "fetch first" in low:
        return PushResult(False, "exists" if create_only else "lease_mismatch", text.strip()[:400])
    if "tengoku-warden" in low and "refused" in low:
        return PushResult(False, "hook_rejected", text.strip()[:400])
    if "remote rejected" in low or "declined" in low or "protected" in low:
        return PushResult(False, "remote_rejected", text.strip()[:400])
    return PushResult(False, "error", text.strip()[:400])


# --------------------------------------------------------------------------- pushes


def push_cas(repo: str, remote: str, ref: str, new_sha: str, expected_old_sha: Optional[str],
             *, env: Optional[Dict[str, str]] = None) -> PushResult:
    """Set `remote`'s `ref` to `new_sha` only if it currently equals `expected_old_sha`.

    `expected_old_sha=None` means create-only: refused if the ref already exists, and pushed
    with an empty-expectation lease so that of two racing creators exactly one wins. There is
    no way to ask for an unconditional force: a missing, empty, short or non-hex expectation
    raises UnsafePush. The lease is checked by the remote at update time (git sends the old
    value with the update command), so the swap itself is atomic on the server.
    """
    check_ref(ref)
    check_oid(new_sha, "new_sha")
    if new_sha == ZERO_OID or new_sha == "0" * 64:
        raise UnsafePush("use delete_ref_cas to delete a ref")
    _check_remote(remote)
    if expected_old_sha is not None:
        check_oid(expected_old_sha, "expected_old_sha")
        if expected_old_sha == ZERO_OID or expected_old_sha == "0" * 64:
            raise UnsafePush("expected_old_sha is the null oid; pass None for create-only")
        lease = "--force-with-lease=%s:%s" % (ref, expected_old_sha)
    else:
        try:
            existing = ls_remote(repo, remote, ref, env=env)
        except RuntimeError as exc:
            return PushResult(False, "error", str(exc))
        if ref in existing:
            return PushResult(False, "exists", "ref already exists", existing[ref])
        lease = "--force-with-lease=%s:" % ref
    r = run_git(repo, ["push", "--porcelain", "--no-follow-tags", "--recurse-submodules=no",
                       lease, remote, "%s:%s" % (new_sha, ref)], env=_capability_env(repo, env))
    return _classify(r, expected_old_sha is None)


def delete_ref_cas(repo: str, remote: str, ref: str, expected_old_sha: str,
                   *, env: Optional[Dict[str, str]] = None) -> PushResult:
    """Delete `remote`'s `ref` only if it still holds `expected_old_sha`."""
    check_ref(ref)
    check_oid(expected_old_sha, "expected_old_sha")
    _check_remote(remote)
    r = run_git(repo, ["push", "--porcelain", "--no-follow-tags", "--recurse-submodules=no",
                       "--force-with-lease=%s:%s" % (ref, expected_old_sha), remote, ":" + ref],
                env=_capability_env(repo, env))
    return _classify(r, False)


def update_ref_cas_gh_args(repo: str, ref: str, new_sha: str, old_sha: str,
                           *, git_dir: Optional[str] = None) -> List[str]:
    """Argv for `gh api -X PATCH repos/<repo>/git/refs/<ref>` that cannot force.

    `repo` is the GitHub slug `owner/name`. The REST endpoint takes no expected-old value, so
    the API-side guard is `force=false`: the update succeeds only if `new_sha` is a
    descendant of the ref's CURRENT value. That equals compare-and-swap only when `new_sha`
    was built directly on `old_sha`; if `git_dir` is given we verify locally that `old_sha`
    is an ancestor of `new_sha` and raise UnsafePush when it is not. Returns an argv list
    (no shell), never an unconditional force.
    """
    if not isinstance(repo, str) or not _SLUG_RE.match(repo):
        raise UnsafePush("repo must be an owner/name slug")
    check_ref(ref)
    check_oid(new_sha, "new_sha")
    check_oid(old_sha, "old_sha")
    if new_sha == old_sha:
        raise UnsafePush("new_sha equals old_sha: nothing to update")
    if git_dir is not None:
        r = run_git(git_dir, ["merge-base", "--is-ancestor", old_sha, new_sha])
        if r.returncode != 0:
            raise UnsafePush("old_sha is not an ancestor of new_sha: this would be a non-fast-forward")
    return ["gh", "api", "-X", "PATCH", "repos/%s/git/refs/%s" % (repo, ref[len("refs/"):]),
            "-f", "sha=" + new_sha, "-F", "force=false"]


# --------------------------------------------------------------------------- hook


class HookError(RuntimeError):
    pass


def install_prepush_hook(repo: str, *, replace: bool = False) -> str:
    """Write a `pre-push` hook that rejects pushes not made through `push_cas`/`delete_ref_cas`.

    The wrapper reads a random capability from `<git-dir>/tengoku-safegit-cap` and passes it
    in the environment; the hook compares it with the file. This stops accidental or careless
    raw `git push` (including `git push --force`) in this clone. It is defence in depth, NOT a
    boundary: `--no-verify`, a changed `core.hooksPath`, deleting the hook, or reading the
    capability file defeats it. Server-side rulesets are the boundary. Returns the hook path.
    Refuses to replace a pre-push hook it did not write unless `replace=True`.
    """
    gd = _git_dir(repo, None)
    if not gd:
        raise HookError("not a git repository: %s" % repo)
    r = run_git(repo, ["rev-parse", "--git-path", "hooks"])
    if r.returncode != 0:
        raise HookError("cannot locate hooks directory")
    hooks = r.stdout.strip()
    hooks = hooks if os.path.isabs(hooks) else os.path.join(repo, hooks)
    path = os.path.join(hooks, "pre-push")
    if os.path.exists(path) and not replace:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                ours = HOOK_MARK in fh.read()
        except OSError as exc:
            raise HookError("cannot read existing hook: %s" % exc)
        if not ours:
            raise HookError("a different pre-push hook exists; pass replace=True to overwrite it")
    cap_path = os.path.join(gd, CAP_FILE)
    try:
        os.makedirs(hooks, exist_ok=True)
        fd = os.open(cap_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(secrets.token_hex(16) + "\n")
        script = (
            "#!/bin/sh\n"
            "# %s -- defence in depth against raw pushes, not a security boundary.\n"
            "cap_file=%s\n"
            "if [ -n \"${%s:-}\" ] && [ -r \"$cap_file\" ] && [ \"$%s\" = \"$(cat \"$cap_file\")\" ]; then\n"
            "  exit 0\n"
            "fi\n"
            "echo \"tengoku-warden: push refused: use warden.safegit (compare-and-swap); raw git push is blocked\" >&2\n"
            "exit 1\n"
        ) % (HOOK_MARK, shlex.quote(cap_path), CAP_ENV, CAP_ENV)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(script)
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError as exc:
        raise HookError("cannot install hook: %s" % exc)
    return path


# --------------------------------------------------------------------------- PR validation

TARGET_PREFIX = "<!--tengoku-target:v1 "
_TARGET_ID_RE = re.compile(r"^[A-Za-z0-9._/:#-]{1,200}\Z")
_MARKER_KEYS = {"target", "claim", "actor", "base"}
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,200}\Z")
MAX_TITLE = 256
MAX_BODY = 65536


def make_marker(target: str, **fields: str) -> str:
    """Build a canonical v1 target marker. Raises ValueError if it would not validate."""
    data = {"target": target}
    data.update(fields)
    text = "%s%s-->" % (TARGET_PREFIX, json.dumps(data, sort_keys=True, separators=(",", ":")))
    marker, problems = parse_marker(text)
    if problems or marker is None:
        raise ValueError("; ".join(problems))
    return text


def _no_dupes(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key %r" % k)
        out[k] = v
    return out


def parse_marker(body: str):
    """Return (marker dict or None, problems). Exactly one v1 marker; closed keys; no dead variants."""
    problems: List[str] = []
    count = body.count("tengoku-target")
    if count == 0:
        return None, ["target marker missing"]
    if count > 1:
        return None, ["more than one tengoku-target marker mention"]
    idx = body.find(TARGET_PREFIX)
    if idx < 0:
        return None, ["tengoku-target present but not a v1 marker"]
    end = body.find("-->", idx)
    if end < 0:
        return None, ["target marker is not closed"]
    payload = body[idx + len(TARGET_PREFIX):end]
    if "\n" in payload or "\r" in payload or len(payload) > 1024 or not (
            payload.startswith("{") and payload.endswith("}")):
        return None, ["target marker payload is not a single-line JSON object"]
    try:
        data = json.loads(payload, object_pairs_hook=_no_dupes)
    except ValueError as exc:
        return None, ["target marker JSON invalid: %s" % exc]
    if not isinstance(data, dict):
        return None, ["target marker JSON is not an object"]
    unknown = set(data) - _MARKER_KEYS
    if unknown:
        problems.append("target marker has unknown keys: %s" % ", ".join(sorted(unknown)))
    for k, v in data.items():
        if not isinstance(v, str):
            problems.append("target marker key %r must be a string" % k)
    tgt = data.get("target")
    if not isinstance(tgt, str) or not _TARGET_ID_RE.match(tgt):
        problems.append("target marker needs a 'target' id of 1-200 safe characters")
    if problems:
        return None, problems
    return data, []


@dataclass
class PRCheck:
    ok: bool
    problems: List[str] = field(default_factory=list)
    marker: Optional[Dict[str, str]] = None
    scan: str = "skipped"  # clean | found | unavailable | skipped


class PRRefused(ValueError):
    def __init__(self, check: PRCheck):
        super().__init__("; ".join(check.problems))
        self.check = check


def _default_scanner() -> Optional[Callable[[str], int]]:
    """Adapter over warden.secretscan; None when it is absent or has no recognised entry point."""
    try:
        mod = importlib.import_module("warden.secretscan")
    except Exception:  # noqa: BLE001 - any import failure means 'unavailable'
        return None
    for name in ("scan_text", "scan", "find_secrets", "find"):
        fn = getattr(mod, name, None)
        if callable(fn):
            def run(text: str, _fn=fn) -> int:
                res = _fn(text)
                if res is None or res is False:
                    return 0
                if res is True:
                    return 1
                try:
                    return len(res)
                except TypeError:
                    return 1
            return run
    return None


def _has_control(text: str, allow_ws: bool) -> bool:
    for ch in text:
        o = ord(ch)
        if o == 0 or (o < 32 and not (allow_ws and ch in "\n\r\t")) or o == 127:
            return True
    return False


def validate_pr(title: str, body: str, *, base: str, head: str, allowed_bases: Sequence[str],
                marker_required: bool = True, require_scan: bool = False,
                scanner: Optional[Callable[[str], int]] = None,
                max_title: int = MAX_TITLE, max_body: int = MAX_BODY) -> PRCheck:
    """Check a pull request before it is created. Every doubt is a problem; `ok` means none.

    `scanner(text) -> number of findings` overrides the lazily imported `warden.secretscan`.
    If no scanner is available the result has scan='unavailable'; with `require_scan=True`
    that is also a problem (use it for anything that can publish). Findings are counted, never
    echoed.
    """
    problems: List[str] = []
    if not isinstance(title, str) or not isinstance(body, str):
        return PRCheck(False, ["title and body must be strings"])
    if not title.strip():
        problems.append("title is empty")
    if len(title) > max_title:
        problems.append("title longer than %d characters" % max_title)
    if _has_control(title, allow_ws=False):
        problems.append("title contains control characters or newlines")
    if len(body) > max_body:
        problems.append("body longer than %d characters" % max_body)
    if _has_control(body, allow_ws=True):
        problems.append("body contains control characters")
    if not allowed_bases:
        problems.append("no allowed base branches configured")
    elif base not in allowed_bases:
        problems.append("base branch %r is not allowed" % (base,))
    if not isinstance(head, str) or not _BRANCH_RE.match(head) or head.startswith(("-", "/")) or ".." in head:
        problems.append("head branch name is not acceptable")
    elif head == base:
        problems.append("head and base are the same branch")
    if "tengoku-target" in title:
        problems.append("title must not contain a target marker")
    marker = None
    if marker_required or "tengoku-target" in body:
        marker, mp = parse_marker(body)
        problems.extend(mp)
        if marker is not None and "base" in marker and marker["base"] != base:
            problems.append("marker base %r differs from the PR base %r" % (marker["base"], base))
    scan = "skipped"
    fn = scanner if scanner is not None else _default_scanner()
    if fn is None:
        scan = "unavailable"
        if require_scan:
            problems.append("secret scan unavailable (warden.secretscan not importable)")
    else:
        try:
            n = fn(title + "\n" + body)
        except Exception as exc:  # noqa: BLE001 - a crashing scanner must fail closed
            scan = "unavailable"
            problems.append("secret scan crashed: %s" % type(exc).__name__)
        else:
            if n > 0:
                scan = "found"
                problems.append("secret scan found %d possible secret(s) in title/body" % n)
            else:
                scan = "clean"
    return PRCheck(not problems, problems, marker, scan)


def pr_create_argv(title: str, body: str, *, base: str, head: str, allowed_bases: Sequence[str],
                   marker_required: bool = True, require_scan: bool = False,
                   scanner: Optional[Callable[[str], int]] = None, repo: Optional[str] = None,
                   draft: bool = False) -> List[str]:
    """The `gh pr create` argv (no shell), produced only if `validate_pr` passes; else PRRefused."""
    check = validate_pr(title, body, base=base, head=head, allowed_bases=allowed_bases,
                        marker_required=marker_required, require_scan=require_scan, scanner=scanner)
    if not check.ok:
        raise PRRefused(check)
    argv = ["gh", "pr", "create", "--title", title, "--body", body, "--base", base, "--head", head]
    if repo is not None:
        if not _SLUG_RE.match(repo):
            raise PRRefused(PRCheck(False, ["repo must be an owner/name slug"]))
        argv += ["--repo", repo]
    if draft:
        argv.append("--draft")
    return argv

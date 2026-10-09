"""Helpers for the git-based tests: real git, temp directories, no network, no user config."""
from __future__ import annotations

import os
import subprocess
from typing import Dict, Optional, Sequence, Union

_SAVED: Dict[str, Optional[str]] = {}
_ENV = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0"}


def patch_env() -> None:
    """Make every git child ignore the user's and the system's configuration."""
    for k, v in _ENV.items():
        _SAVED[k] = os.environ.get(k)
        os.environ[k] = v


def restore_env() -> None:
    for k, old in _SAVED.items():
        if old is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = old
    _SAVED.clear()


def git(cwd: str, *args: str, input_bytes: Optional[bytes] = None, check: bool = True) -> str:
    cmd = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false",
           "-c", "protocol.file.allow=always"] + list(args)
    p = subprocess.run(cmd, cwd=cwd, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode != 0:
        raise AssertionError("git %s failed: %s" % (" ".join(args), p.stderr.decode("utf-8", "replace")))
    return p.stdout.decode("utf-8", "replace").strip()


def init_repo(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    git(path, "init", "-q", "-b", "main")
    return path


def init_bare(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    git(path, "init", "-q", "--bare", "-b", "main")
    return path


Content = Union[str, bytes]


def commit(repo: str, files: Optional[Dict[str, Content]] = None, *, delete: Sequence[str] = (),
           msg: str = "c") -> str:
    """Write `files`, remove `delete`, stage everything and commit; returns the new commit id."""
    for rel, data in (files or {}).items():
        full = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        if os.path.lexists(full):
            os.remove(full)
        with open(full, "wb") as fh:
            fh.write(data if isinstance(data, bytes) else data.encode("utf-8"))
    for rel in delete:
        os.remove(os.path.join(repo, rel))
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", msg)
    return git(repo, "rev-parse", "HEAD")

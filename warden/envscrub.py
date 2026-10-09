"""Build a child process environment from an explicit allowlist, never by subtraction.

``build_env(allow, extra, source)`` starts from an empty dict and copies only the
named variables, so a variable nobody thought about (a new cloud key, a CI token,
a management key) cannot reach the child.  Names and values that look like
secrets are refused unless the caller names them in ``secret_ok``; ``HOME`` is
never inherited (the caller passes a throwaway home explicitly); a ``PATH`` with
empty or relative entries is refused.

Credit: Tau Ceti Project, TauCetiWorker (agents.py ``host_agent_argv``, the
research report ``report-worker-claims.md`` item 1.7).  Its host mode copies the
whole parent environment and removes two provider keys, while its own reference
document says the OpenRouter management key is "never passed to an agent"; the
report found that host children still inherit that key, a Kiro key and the GitHub
token.  TauCetiReview (feature F4, "reviewer clean room") shows the right shape for
the reviewer: its own key and a throwaway HOME only, and TauCeti's bubblewrap
build (B4) starts the sandbox under ``env -i`` so PID 1's environment is empty.

What we do differently: an allowlist is the only way in (there is no copy-then-pop
code path at all); the allowlist itself is checked for secret-looking names, so
adding ``GH_TOKEN`` to it by mistake is an error rather than a leak; values are
checked as well as names; and ``report`` prints names and lengths only so the
audit log of what a child received can be published.

Pure logic: nothing here reads the process environment unless the caller leaves
``source`` at its default.  Python 3.9 compatible.
"""
from __future__ import annotations

import math
import os
import re
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, TextIO, Tuple

DEFAULT_ALLOW: Tuple[str, ...] = ("PATH", "LANG", "LC_ALL", "TZ", "TMPDIR", "TERM")
"""Variables a child normally needs.  HOME is deliberately absent: pass ``home=``."""

_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class EnvRefused(ValueError):
    """The requested environment was refused (fail closed); the message names the variable, never its value."""


# ----------------------------------------------------------------------------------------------
# secret detection
# ----------------------------------------------------------------------------------------------

_SECRET_TOKENS = frozenset(
    {
        "TOKEN", "TOKENS", "SECRET", "SECRETS", "PASSWORD", "PASSWD", "PASSPHRASE", "CREDENTIAL", "CREDENTIALS",
        "AUTH", "AUTHORIZATION", "APIKEY", "COOKIE", "COOKIES", "BEARER", "OAUTH", "JWT", "PAT", "DSN",
    }
)
_SECRET_PAIRS = frozenset({("API", "KEY"), ("PRIVATE", "KEY"), ("ACCESS", "KEY"), ("SIGNING", "KEY")})


def _name_tokens(name: str) -> List[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return [t for t in re.split(r"[^A-Za-z0-9]+", spaced.upper()) if t]


def looks_secret_name(name: str) -> bool:
    """True when a variable name suggests a credential (TOKEN, SECRET, ..._KEY, SSH_AUTH_SOCK, ...).

    Token based, so ``GIT_AUTHOR_NAME`` and ``KEYBOARD`` are not flagged but ``GH_TOKEN``, ``OPENAI_API_KEY``,
    ``LAKE_CACHE_KEY`` and ``BRIDGE_TOKEN`` are.  Errs on the side of flagging.
    """
    tokens = _name_tokens(str(name))
    if not tokens:
        return False
    if any(t in _SECRET_TOKENS for t in tokens):
        return True
    if tokens[-1] == "KEY":
        return True
    return any((a, b) in _SECRET_PAIRS for a, b in zip(tokens, tokens[1:]))


_VALUE_PATTERNS = tuple(
    re.compile(p)
    for p in (
        r"sk-ant-[A-Za-z0-9_\-]{16,}",
        r"sk-[A-Za-z0-9_\-]{20,}",
        r"gh[pousr]_[A-Za-z0-9]{20,}",
        r"github_pat_[A-Za-z0-9_]{20,}",
        r"xox[abprs]-[A-Za-z0-9\-]{10,}",
        r"AKIA[0-9A-Z]{16}",
        r"ASIA[0-9A-Z]{16}",
        r"AIza[0-9A-Za-z_\-]{30,}",
        r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]{20,}",
        r"://[^/\s:@]+:[^/\s@]+@",
    )
)
_ENTROPY_CANDIDATE = re.compile(r"^[A-Za-z0-9+/_=\-]{32,}$")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(s))
    return -sum((c / n) * math.log(c / n, 2) for c in counts.values())


def _secretscan_says_secret(value: str) -> bool:
    """Ask warden.secretscan (written by another module) if it is importable; any problem means 'no opinion'."""
    try:
        import importlib

        mod = importlib.import_module("warden.secretscan")
        scan = getattr(mod, "scan", None)
        if scan is None:
            return False
        return bool(scan(value))
    except Exception:  # noqa: BLE001 - optional collaborator; local patterns stay authoritative
        return False


def looks_secret_value(value: str) -> bool:
    """True when a value matches a known credential shape or is a long random-looking token.

    Local patterns always apply; ``warden.secretscan`` is consulted additionally when it can be imported.
    """
    if not isinstance(value, str) or not value:
        return False
    for pat in _VALUE_PATTERNS:
        if pat.search(value):
            return True
    if (
        not value.startswith(("/", "./", "../", "~"))  # a filesystem path is not a token, however random its directory names
        and _ENTROPY_CANDIDATE.match(value)
        and re.search(r"[A-Za-z]", value)
        and re.search(r"[0-9]", value)
        and not re.fullmatch(r"[0-9a-fA-F]+", value)
        and _entropy(value) >= 4.2
    ):
        return True
    return _secretscan_says_secret(value)


# ----------------------------------------------------------------------------------------------
# PATH checks
# ----------------------------------------------------------------------------------------------


def path_issues(path_value: str) -> List[str]:
    """Problems in a PATH string that do not need the filesystem: empty entries and relative entries (both mean 'cwd')."""
    issues: List[str] = []
    if path_value == "":
        return ["PATH is empty"]
    for i, entry in enumerate(path_value.split(os.pathsep)):
        if entry == "":
            issues.append("entry %d is empty (means the current directory)" % i)
        elif not os.path.isabs(entry):
            issues.append("entry %d is relative: %r" % (i, entry))
    return issues


def writable_path_dirs(path_value: str, access: Callable[[str, int], bool] = os.access) -> List[str]:
    """PATH entries the current identity can write to (a planted binary there would be run by a later step)."""
    out: List[str] = []
    for entry in path_value.split(os.pathsep):
        if entry and os.path.isdir(entry) and access(entry, os.W_OK):
            out.append(entry)
    return out


# ----------------------------------------------------------------------------------------------
# building and reporting
# ----------------------------------------------------------------------------------------------


def _check_name(name: Any) -> str:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise EnvRefused("invalid environment variable name: %r" % (name,))
    return name


def _check_value(name: str, value: Any, secret_ok: frozenset) -> str:
    if not isinstance(value, str):
        raise EnvRefused("value of %s is not a string" % name)
    if "\x00" in value:
        raise EnvRefused("value of %s contains a NUL byte" % name)
    if name not in secret_ok and looks_secret_value(value):
        raise EnvRefused("value of %s looks like a secret; name it in secret_ok if the child must have it" % name)
    return value


def build_env(
    allow: Iterable[str],
    extra: Optional[Mapping[str, str]] = None,
    source: Mapping[str, str] = os.environ,
    *,
    secret_ok: Iterable[str] = (),
    home: Optional[str] = None,
) -> Dict[str, str]:
    """Return a new environment containing only ``allow`` (copied from ``source``) plus ``extra``.

    * ``allow`` is an iterable of exact variable names (a bare string is rejected: it would iterate characters).
    * ``extra`` overrides and adds; its names and values are refused when secret-looking unless in ``secret_ok``.
    * Allowlisted names that look secret are refused as well, unless in ``secret_ok`` (so a stray ``GH_TOKEN`` in the
      allowlist is an error, and a deliberate ``CLAUDE_CODE_OAUTH_TOKEN`` has to be said out loud).
    * ``HOME`` cannot be allowlisted or put in ``extra``; pass ``home=`` (an absolute path) instead.
    * A ``PATH`` with empty or relative entries is refused.

    Raises ``EnvRefused``; the message never contains a value.
    """
    if isinstance(allow, (str, bytes)):
        raise EnvRefused("allow must be a collection of names, not a string")
    ok = frozenset(secret_ok)
    out: Dict[str, str] = {}
    for name in allow:
        _check_name(name)
        if name == "HOME":
            raise EnvRefused("HOME is never inherited; pass home= with a throwaway directory")
        if looks_secret_name(name) and name not in ok:
            raise EnvRefused("%s is in the allowlist and looks like a credential; name it in secret_ok if intended" % name)
        if name in source:
            out[name] = _check_value(name, source[name], ok)
    for name, value in (extra or {}).items():
        _check_name(name)
        if name == "HOME":
            raise EnvRefused("HOME cannot be set through extra; pass home=")
        if looks_secret_name(name) and name not in ok:
            raise EnvRefused("extra variable %s looks like a credential; name it in secret_ok if intended" % name)
        out[name] = _check_value(name, value, ok)
    if home is not None:
        if not isinstance(home, str) or not os.path.isabs(home) or "\x00" in home:
            raise EnvRefused("home must be an absolute path")
        out["HOME"] = home
    if "PATH" in out:
        problems = path_issues(out["PATH"])
        if problems:
            raise EnvRefused("PATH refused: " + "; ".join(problems))
    return out


def secret_names_in(env: Mapping[str, str], secret_ok: Iterable[str] = ()) -> List[str]:
    """Sorted names in ``env`` whose name or value looks secret and that are not in ``secret_ok``."""
    ok = frozenset(secret_ok)
    return sorted(n for n, v in env.items() if n not in ok and (looks_secret_name(n) or looks_secret_value(v)))


def report(env: Mapping[str, str], secret_ok: Iterable[str] = (), stream: Optional[TextIO] = None) -> str:
    """Names only, values redacted: one line per variable with its length and a flag when it looks secret.

    Returns the text and also writes it to ``stream`` when given.  Safe to publish in an audit log.
    """
    ok = frozenset(secret_ok)
    lines = []
    for name in sorted(env):
        value = env[name]
        flags = []
        if looks_secret_name(name) or looks_secret_value(value):
            flags.append("secret-ok" if name in ok else "SECRET-LOOKING")
        lines.append("%s=<redacted %d chars>%s" % (name, len(value), (" [" + ",".join(flags) + "]") if flags else ""))
    text = "\n".join(lines) + ("\n" if lines else "")
    if stream is not None:
        stream.write(text)
    return text

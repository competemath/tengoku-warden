"""Secret scanner for text an agent produced: answers, diffs, commit messages, PR bodies, logs and artifacts.

Finds provider tokens, private key blocks, JWTs, bearer and API-key header lines, credential URLs and high-entropy values
assigned to key-like names, reports where (never the whole secret), and can replace each with `[REDACTED:<kind>]`.

Credit: Tau Ceti Project, TauCetiWorker `review_diagnostics.py` and `sanitize_failure` (PR #144, #164, #217): a redactor for
`sk-`, `gh?_`, `github_pat_`, `xoxb-`, bearer tokens, `*_KEY=` assignments, credential URLs and home paths, which their
code states "is deliberately not a publication boundary". Their research report records the gap this module fills: no secret
scan of what agents publish (diffs, commit messages, PR bodies), raw logs kept verbatim, and 57 TauCetiData records that once
leaked `raw_stderr` and session ids (issue #105 / PR #107).

What we do differently: the scanner is meant to run at the publication boundary and on every pushed diff (added lines only,
attributed to file and line), not only on failure text; zero-width and control characters inside a token are looked through
(and removed with it on redaction); a bare 40-hex git commit id is not a finding unless a key-like name sits in front of it;
an inline `pragma: allowlist secret` is honoured, as in the Tengoku repositories. It is a heuristic filter: encoded
(base64, hex, split across lines) secrets and secrets without a recognisable shape are not found.
"""

from __future__ import annotations

import argparse
import math
import os
import re
import sys
import unicodedata
from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Iterator, List, Optional, Sequence, Tuple

__all__ = ["Finding", "main", "redact", "scan", "scan_diff", "scan_paths", "shannon_entropy"]

MAX_FILE_BYTES = 20 * 1024 * 1024
_ALLOW = re.compile(r"pragma:\s*allowlist[ _-]*secret", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    """One suspected secret. `start`/`end` are offsets into the scanned text (for scan_diff: into the added line).

    `preview` is at most the first 4 characters and an ellipsis; the secret itself is never kept.
    """

    kind: str
    start: int
    end: int
    preview: str
    line: int = 1
    source: str = ""


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


# ----------------------------------------------------------------------------------------------------------------------
# Rules. Each: (kind, rank, compiled regex, group). rank breaks ties (lower wins); group is the span reported (0 = whole).

_B = r"(?<![A-Za-z0-9_\-])"  # token must not continue an identifier on the left
_PLACEHOLDER = re.compile(r"(?i)\A(?:[\$\{<%\*\[]|x{4,}|your[_-]|example|changeme|placeholder|redacted|dummy|pass(?:word)?\Z|secret\Z|token\Z|none\Z|null\Z|true\Z|false\Z)")
_VALUE = r"[A-Za-z0-9+/=_.\-~]{16,}"

_RULES: List[Tuple[str, int, "re.Pattern[str]", int]] = []


def _rule(kind: str, rank: int, pattern: str, group: int = 0, flags: int = 0) -> None:
    _RULES.append((kind, rank, re.compile(pattern, flags), group))


_rule("anthropic_oauth_token", 1, _B + r"sk-ant-o(?:at|rt)\d{2}-[A-Za-z0-9_\-]{20,}")
_rule("anthropic_api_key", 1, _B + r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{20,}")
_rule("anthropic_key", 2, _B + r"sk-ant-[A-Za-z0-9_\-]{30,}")
_rule("openai_key", 3, _B + r"sk-(?:proj-|svcacct-|admin-)[A-Za-z0-9_\-]{20,}")
_rule("openai_key", 3, _B + r"sk-[A-Za-z0-9]{32,}")
_rule("github_token", 1, _B + r"gh[pousr]_[A-Za-z0-9]{30,255}")
_rule("github_token", 1, _B + r"github_pat_[A-Za-z0-9_]{22,255}")
_rule("slack_token", 1, _B + r"xox[abprs]-[A-Za-z0-9\-]{10,}")
_rule("slack_token", 1, _B + r"xapp-\d-[A-Za-z0-9\-]{10,}")
_rule("slack_webhook", 1, r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{16,}")
_rule("aws_access_key_id", 1, r"(?<![A-Z0-9])(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}(?![A-Z0-9])")
_rule("aws_secret_key", 2, r"(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", 1)
_rule("google_api_key", 1, _B + r"AIza[0-9A-Za-z_\-]{35}")
_rule("stripe_live_key", 1, _B + r"(?:sk|rk)_live_[0-9A-Za-z]{16,}")
_rule("stripe_webhook_secret", 1, _B + r"whsec_[A-Za-z0-9]{24,}")
_rule("huggingface_token", 1, _B + r"hf_[A-Za-z0-9]{34,}")
_rule("npm_token", 1, _B + r"npm_[A-Za-z0-9]{36}")
_rule("private_key", 1,
      r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)")
_rule("jwt", 2, _B + r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")
_rule("bearer_token", 4, r"(?i)\bbearer[ \t]+([A-Za-z0-9._~+/=\-]{20,})", 1)
_rule("credential_url", 3, r"\b[A-Za-z][A-Za-z0-9+.\-]*://[^\s:/@\"'<>]+:([^\s@/\"'<>]+)@", 1)
_rule("auth_header", 5,
      r"(?i)(?<![A-Za-z0-9_\-])(?:x-api-key|x-auth-token|api-key|authorization|proxy-authorization)[\"']?[ \t]*[:=][ \t]*[\"']?"
      r"(?:(?:bearer|basic|token)[ \t]+)?([^\s\"',;]{12,})", 1)
_rule("key_assignment", 9,
      r"(?i)(?<![A-Za-z0-9])(?:[A-Za-z0-9]{1,30}[_\-.]){0,6}(?:key|token|secret|password|passwd|apikey|credentials?)[\"']?[ \t]*[:=][ \t]*[\"']?"
      r"(" + _VALUE + r")", 1)

_GENERIC_KINDS = {"key_assignment", "auth_header", "bearer_token"}


def _plausible_secret(value: str) -> bool:
    if _PLACEHOLDER.match(value):
        return False
    has_digit = any(c.isdigit() for c in value)
    mixed = any(c.isupper() for c in value) and any(c.islower() for c in value)
    if value[0] in "/.~":  # a path, not a secret
        return False
    ent = shannon_entropy(value)
    return (ent >= 3.5 and has_digit) or (ent >= 4.2 and mixed)


# ----------------------------------------------------------------------------------------------------------------------


def _look_through(text: str) -> Tuple[str, List[int]]:
    """Drop invisible and control characters (they can split a token); return the new text and original offsets."""
    out: List[str] = []
    idx: List[int] = []
    for i, ch in enumerate(text):
        cat = unicodedata.category(ch)
        if cat in ("Cf", "Cs", "Co") or (cat == "Cc" and ch not in "\n\t\r"):
            continue
        out.append(ch)
        idx.append(i)
    return "".join(out), idx


def _line_bounds(text: str, pos: int) -> Tuple[int, int]:
    a = text.rfind("\n", 0, pos) + 1
    b = text.find("\n", pos)
    return a, len(text) if b < 0 else b


def _scan_raw(text: str) -> List[Tuple[str, int, int]]:
    cands: List[Tuple[int, int, int, str]] = []  # (start, rank, end, kind)
    for kind, rank, rx, group in _RULES:
        for m in rx.finditer(text):
            s, e = m.span(group)
            if s < 0:
                continue
            if kind in _GENERIC_KINDS and not _plausible_secret(text[s:e]):
                continue
            if kind == "credential_url" and _PLACEHOLDER.match(text[s:e]):
                continue
            cands.append((s, rank, e, kind))
    cands.sort(key=lambda c: (c[0], c[1], -(c[2] - c[0])))
    kept: List[Tuple[str, int, int]] = []
    last_end = -1
    for s, _rank, e, kind in cands:
        if s < last_end:
            continue
        a, b = _line_bounds(text, s)
        if _ALLOW.search(text[a:b]):
            continue
        kept.append((kind, s, e))
        last_end = e
    return kept


def _preview(text: str, s: int) -> str:
    return text[s:s + 4] + "\u2026"


def scan(text: str, source: str = "") -> List[Finding]:
    """Find suspected secrets in `text`. Offsets refer to `text` as given; `line` is 1-based."""
    if not isinstance(text, str):
        raise TypeError("text must be str")
    clean, idx = _look_through(text)
    found: List[Finding] = []
    for kind, s, e in _scan_raw(clean):
        os_, oe = idx[s], idx[e - 1] + 1
        found.append(Finding(kind, os_, oe, _preview(clean, s), text.count("\n", 0, os_) + 1, source))
    return found


def redact(text: str) -> str:
    """Replace every finding with `[REDACTED:<kind>]` (a key name in front of the value is kept)."""
    out: List[str] = []
    pos = 0
    for f in scan(text):
        out.append(text[pos:f.start])
        out.append("[REDACTED:%s]" % f.kind)
        pos = f.end
    out.append(text[pos:])
    return "".join(out)


_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _diff_path(line: str) -> str:
    p = line[4:].split("\t")[0].strip()
    if len(p) > 1 and p[0] == p[-1] == '"':
        p = p[1:-1]
    return p[2:] if p[:2] in ("a/", "b/") else p


def scan_diff(unified_diff_text: str) -> List[Finding]:
    """Scan ONLY the added lines of a unified diff. Findings carry the file (`source`) and new-file line number.

    Consecutive added lines are scanned together, so a private key block spanning lines is found. `start`/`end` are offsets
    inside the (first) line carrying the finding.
    """
    findings: List[Finding] = []
    path = ""
    old_left = new_left = 0
    new_no = 0
    run: List[Tuple[int, str]] = []

    def flush() -> None:
        if not run:
            return
        text = "\n".join(t for _n, t in run)
        starts: List[int] = []
        off = 0
        for _n, t in run:
            starts.append(off)
            off += len(t) + 1
        for f in scan(text, path):
            k = max(i for i, st in enumerate(starts) if st <= f.start)
            findings.append(Finding(f.kind, f.start - starts[k], f.end - starts[k], f.preview, run[k][0], path))
        run.clear()

    for raw in unified_diff_text.split("\n"):
        if old_left > 0 or new_left > 0:
            tag = raw[:1]
            if tag == "+":
                run.append((new_no, raw[1:]))
                new_no += 1
                new_left -= 1
                continue
            if tag == "\\":  # "\ No newline at end of file"
                continue
            flush()
            if tag == "-":
                old_left -= 1
                continue
            if tag == " " or raw == "":
                old_left -= 1
                new_left -= 1
                new_no += 1
                continue
            old_left = new_left = 0  # malformed hunk: leave it and read this line as a header
        flush()
        if raw.startswith("+++ "):
            path = _diff_path(raw)
        elif raw.startswith("diff --git "):
            path = ""
        else:
            m = _HUNK.match(raw)
            if m:
                old_left = int(m.group(2)) if m.group(2) is not None else 1
                new_left = int(m.group(4)) if m.group(4) is not None else 1
                new_no = int(m.group(3))
    flush()
    return findings


def _walk(paths: Iterable[str]) -> Iterator[str]:
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d != ".git")
                for name in sorted(files):
                    yield os.path.join(root, name)
        else:
            yield p


def scan_paths(paths: Iterable[str]) -> List[Finding]:
    """Scan files (directories are walked, `.git` skipped). A file over the size cap is itself a finding (fail closed)."""
    found: List[Finding] = []
    for p in _walk(paths):
        size = os.path.getsize(p)
        if size > MAX_FILE_BYTES:
            found.append(Finding("unscanned_too_large", 0, 0, "", 1, p))
            continue
        with open(p, "rb") as fh:
            data = fh.read()
        found.extend(scan(data.decode("utf-8", errors="replace"), p))
    return found


# ----------------------------------------------------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    """`warden secretscan [--diff] [--redact] FILE...` (argv is what follows the command). Exit 0 clean, 1 findings, 2 bad input."""
    ap = argparse.ArgumentParser(prog="warden secretscan", description="Scan files or unified diffs for secrets.")
    ap.add_argument("--diff", action="store_true", help="inputs are unified diffs; scan added lines only")
    ap.add_argument("--redact", action="store_true", help="write the redacted text to stdout (report goes to stderr)")
    ap.add_argument("files", nargs="+", metavar="FILE", help="file or directory to scan, or - for stdin")
    try:
        args = ap.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return 2 if exc.code else 0
    report = sys.stderr if args.redact else sys.stdout
    total = 0
    names: List[str] = []
    for given in args.files:
        names.extend([given] if given == "-" else _walk([given]))
    for name in names:
        try:
            if name == "-":
                text = sys.stdin.read()
            else:
                if os.path.getsize(name) > MAX_FILE_BYTES:
                    print("%s: file too large to scan" % name, file=report)
                    total += 1
                    continue
                with open(name, "rb") as fh:
                    text = fh.read().decode("utf-8", errors="replace")
        except OSError as exc:
            print("secretscan: cannot read %s: %s" % (name, exc.strerror or exc), file=sys.stderr)
            return 2
        finds = scan_diff(text) if args.diff else scan(text, name)
        for f in finds:
            where = f.source or name
            print("%s:%d: %s %s" % (where, f.line, f.kind, f.preview), file=report)
        total += len(finds)
        if args.redact:
            sys.stdout.write(redact(text))
    return 1 if total else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

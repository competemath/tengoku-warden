"""Output hygiene for text an agent produced that will be PUBLISHED (GitHub comments, PR bodies, chat sinks).

`sanitize_text` removes what could act on the reader or on our own parsers: control, zero-width and bidi characters, HTML
comments (including unterminated ones), reserved marker strings, secrets, and live `@name` / `#123` references.
`public_diagnostic` turns a failure into a fixed phrase, never into text a subprocess or an agent wrote.

Credit: Tau Ceti Project, TauCetiReview `sanitize()` and the public-record code (finding F6), and TauCetiWorker
`review_diagnostics.py` (PR #144, #217): public "Review stuck" issues get only fixed phrases chosen by category, and
`sanitize_failure` redacts tokens, credential URLs and home paths while stating it "is deliberately not a publication
boundary".

What we do differently: order. Tau Ceti strips HTML comments before control characters, so `<!` + a control character +
`--tauceti-meta:v1 {...}-->` survives and becomes a live marker when the control character is removed afterwards. Here
invisible characters go first, then comments (terminated, unterminated and `--!>`), then marker strings, repeated until
nothing changes; secrets are redacted with `warden.secretscan` (diffs, commit messages and PR bodies included) before `@`
and `#` are defused. HONEST LIMIT: this is a filter, not a proof. It does not remove Markdown links or images that point at
attacker URLs, does not detect secrets in encodings it cannot see, and is no substitute for not giving the agent the secret.
"""

from __future__ import annotations

import re
from typing import Optional

from .untrusted import strip_invisible

__all__ = ["DIAGNOSTICS", "public_diagnostic", "redact", "sanitize_text"]

ZWSP = "​"
_COMMENT = re.compile(r"<!--.*?(?:--!?>|\Z)", re.DOTALL)
_DECL = re.compile(r"<!(?=[\[A-Za-z\-])")
_MARKER_VERDICT = re.compile(r"tengoku[\s_\-]*verdict[\s_\-]*[0-9a-z]*", re.IGNORECASE)
_MARKER_META = re.compile(r"tengoku[a-z0-9_\-]*\s*:\s*v\d+", re.IGNORECASE)
_MENTION = re.compile(r"@(?=[A-Za-z0-9])")
_ISSUE = re.compile(r"#(?=\d)")
_GH_REF = re.compile(r"\b(GH-)(?=\d)", re.IGNORECASE)
_MARKER_TEXT = "[marker removed]"
_TRUNC = "…[truncated]"


def redact(text: str) -> str:
    """Replace anything `warden.secretscan` flags with `[REDACTED:<kind>]`."""
    from . import secretscan  # lazy: keeps this module importable on its own

    return secretscan.redact(text)


def _strip_active(text: str) -> str:
    prev: Optional[str] = None
    while prev != text:
        prev = text
        text = strip_invisible(text)
        text = _COMMENT.sub("", text)
        text = _MARKER_VERDICT.sub(_MARKER_TEXT, text)
        text = _MARKER_META.sub(_MARKER_TEXT, text)
    return text


def sanitize_text(s: str, max_len: int, *, defuse_mentions: bool = True, defuse_issue_links: bool = True,
                  redact_secrets: bool = True) -> str:
    """Make agent text safe to publish. Order: invisible characters, HTML comments, markers, secrets, `@`/`#`, length cap.

    The result is at most `max_len` characters (a cut ends with a visible `[truncated]`). Non-text input raises TypeError.
    """
    if not isinstance(s, str):
        raise TypeError("sanitize_text needs str")
    if max_len < 1:
        raise ValueError("max_len must be positive")
    text = _strip_active(s)
    if redact_secrets:
        text = redact(text)
        text = _strip_active(text)
    text = _DECL.sub("&lt;!", text)  # <!DOCTYPE, <![CDATA[ and friends
    if defuse_mentions:
        text = _MENTION.sub("@" + ZWSP, text)
    if defuse_issue_links:
        text = _ISSUE.sub("#" + ZWSP, text)
        text = _GH_REF.sub(lambda m: m.group(1) + ZWSP, text)
    if len(text) > max_len:
        keep = max_len - len(_TRUNC)
        text = (text[:keep] + _TRUNC) if keep > 0 else text[:max_len]
    return text


# ----------------------------------------------------------------------------------------------------------------------

DIAGNOSTICS = {
    "timeout": "The run exceeded its time limit and was stopped.",
    "no_marker": "The reviewer's reply did not contain the expected end marker.",
    "bad_json": "The reviewer's reply was not valid structured output.",
    "bad_verdict": "The reviewer's reply did not carry an allowed verdict.",
    "bad_finding": "The reviewer's reply contained a malformed finding.",
    "trailing_text": "The reviewer's reply contained text after the structured output.",
    "too_large": "The reviewer's reply was larger than the allowed size.",
    "nonzero_exit": "The agent process exited with an error.",
    "provider_down": "The model provider was unavailable.",
    "rate_limited": "The model provider rate-limited the request.",
    "denied": "A tool or path request was denied by policy.",
    "secret_detected": "A possible secret was found in output and withheld.",
    "injection_detected": "Instructions embedded in the reviewed content were detected and ignored.",
    "diff_truncated": "The change was too large to review in full.",
    "cancelled": "The run was cancelled.",
    "internal_error": "An internal error occurred; details are in the private log.",
}
_UNKNOWN = "The run failed for a reason that is not recorded in the public table."
_DETAILS = {
    "first_attempt": "It will be retried once.",
    "after_retry": "The retry also failed; the review is in an error state, which blocks.",
    "partial_view": "Only part of the content was available.",
}


def public_diagnostic(category: str, detail: Optional[str] = None) -> str:
    """A fixed public phrase for a failure category. Subprocess output, exception text and agent text never appear in it.

    `detail` is only a key into a small table (`first_attempt`, `after_retry`, `partial_view`); anything else is ignored.
    """
    base = DIAGNOSTICS.get(category) if isinstance(category, str) else None
    out = base or _UNKNOWN
    extra = _DETAILS.get(detail) if isinstance(detail, str) else None
    return out + (" " + extra if extra else "")

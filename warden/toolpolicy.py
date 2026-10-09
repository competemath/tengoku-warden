"""Tool allowlists for agent CLIs, enforced at the SET level, plus checks that keep them enforced.

A ``ToolPolicy`` names the built-in tools and MCP tool patterns one kind of agent may have.  ``claude_args`` turns it into
the argv fragment that restricts the Claude CLI to exactly that set; ``check_claude_argv`` / ``check_codex_argv`` /
``check_unknown`` inspect a finished argv and list ``Violation`` objects; ``audit_trace_claude`` reads a run's
``--output-format stream-json`` lines and reports every tool the agent actually used, so the policy is a per-run gate
instead of a one-off analysis; ``scan_source_for_spawn_flags`` is a CI regression scan of a bridge's source for spawn
sites that pass permission-bypass or deny-list flags without a restricted tool set.

Credit: Tau Ceti Project, TauCetiReview PR #123 (f854a7e, 2026-08-21, "reviewer tool restriction") and its regression test
``tests/test_reviewer_no_shell.py``.  Their Claude reviewer was launched with ``--allowedTools`` only, from the first commit
(2026-06-03), so Bash was reachable for about 79 days: a trace of 20 runs on 2026-08-20 showed 295 Bash calls in 427 traced
calls (278 succeeded).  The fix passes ``--tools Read Grep Glob``.  TauCetiWorker has no tool allowlist at all (report
``report-worker-claims.md``, "Looks like security but is not enforced" items 7 and 13) and pins permissive flags in golden
tests; its host agents run with permissions bypassed in a checkout that can carry its own CLAUDE.md and hooks.

What we do differently: the rule is generic (every flag combination is judged against a named policy, not one hard-coded
list); a deny-list alone, ``--tools default`` and ``--allowedTools`` without ``--tools`` are all violations by name; the
stream-json auditor makes the 295-call analysis a permanent gate (tool set announced at start, every call, every path
checked against the workspace, shell and web use flagged); and a source scanner checks the code that builds the argv, so
a bridge cannot quietly regress.

Assumptions about the CLIs (verified against ``claude --help`` of Claude Code 2.1.218 on 2026-10-09; see also each checker):
* Claude: ``--tools <tools...>`` sets the available BUILT-IN tools ("" = none, ``default`` = all); ``--allowedTools`` /
  ``--disallowedTools`` are permission rules and do not remove tools from the set; ``--tools``, ``--allowedTools``,
  ``--disallowedTools``, ``--add-dir`` and ``--mcp-config`` are variadic (a following positional prompt is swallowed, so
  ``claude_args`` emits ``--tools=A,B`` by default); ``--strict-mcp-config`` makes ``--mcp-config`` the only MCP source;
  the stream-json ``system``/``init`` event lists the tools the session has (assumed from observed output, tolerated if
  absent).  MCP tool names look like ``mcp__<server>__<tool>`` (assumed from Claude Code's documented naming).
* Codex: NOT installed here; ``check_codex_argv`` encodes the flags as publicly documented (``-s/--sandbox``,
  ``--dangerously-bypass-approvals-and-sandbox``, ``--full-auto``).  Verify with ``codex --help`` before relying on it.
* ``--max-turns`` is accepted by the CLI but absent from its ``--help`` text, so no rule depends on it.

Pure logic apart from ``os.path.realpath`` (symlink resolution) and the thin file functions/CLI.  Python 3.9 compatible.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

# ----------------------------------------------------------------------------------------------
# tool taxonomy
# ----------------------------------------------------------------------------------------------

SHELL_TOOLS = frozenset({"Bash", "BashOutput", "KillShell", "KillBash"})
WEB_TOOLS = frozenset({"WebFetch", "WebSearch"})
WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})
AGENT_TOOLS = frozenset({"Task", "Agent"})
HIGH_RISK_TOOLS = SHELL_TOOLS | WEB_TOOLS | WRITE_TOOLS | AGENT_TOOLS
READ_TOOLS = frozenset({"Read", "Grep", "Glob", "LS", "NotebookRead"})

_TOOL_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class Violation:
    """One finding.  ``rule`` is a stable kebab-case id; ``severity`` is ``error`` (blocks) or ``warn`` (attempt, not an escape)."""

    rule: str
    message: str
    detail: str = ""
    severity: str = "error"

    def __str__(self) -> str:
        return "[%s] %s%s" % (self.rule, self.message, (" (" + self.detail + ")") if self.detail else "")

    def to_dict(self) -> Dict[str, str]:
        return {"rule": self.rule, "message": self.message, "detail": self.detail, "severity": self.severity}


@dataclass(frozen=True)
class ToolPolicy:
    """What one kind of agent may use.

    ``builtin_tools``: built-in tool names (``Read`` ...).  ``mcp_patterns``: MCP tool patterns; ``mcp__srv`` means every
    tool of server ``srv``, ``mcp__srv__*`` and ``mcp__srv__tool`` work too (fnmatch).  ``allow_shell`` must be True for a
    policy that lists Bash.  ``allow_skip_permissions`` lets the launcher pass ``--dangerously-skip-permissions`` but only
    together with a restricted ``--tools`` set.  ``allow_unknown_cli`` lets ``check_unknown`` pass an unrecognised CLI.
    ``require_limits`` additionally demands ``--max-budget-usd``.
    """

    name: str
    builtin_tools: Tuple[str, ...] = ()
    mcp_patterns: Tuple[str, ...] = ()
    allow_shell: bool = False
    allow_skip_permissions: bool = False
    allow_unknown_cli: bool = False
    require_limits: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "builtin_tools", tuple(self.builtin_tools))
        object.__setattr__(self, "mcp_patterns", tuple(self.mcp_patterns))
        problems = validate_policy(self)
        if problems:
            raise ValueError("invalid ToolPolicy %r: %s" % (self.name, "; ".join(problems)))


def validate_policy(policy: "ToolPolicy") -> List[str]:
    """Reasons a policy is itself unsafe or malformed (empty list = fine)."""
    problems: List[str] = []
    if not policy.name:
        problems.append("name is empty")
    for t in policy.builtin_tools:
        if not isinstance(t, str) or not _TOOL_NAME_RE.match(t) or t.startswith("mcp__"):
            problems.append("bad built-in tool name %r" % (t,))
        elif t.lower() == "default":
            problems.append("'default' is not a tool set")
        elif t in SHELL_TOOLS and not policy.allow_shell:
            problems.append("%s listed but allow_shell is False" % t)
    if policy.allow_shell and not (set(policy.builtin_tools) & SHELL_TOOLS):
        problems.append("allow_shell is True but no shell tool is listed")
    for p in policy.mcp_patterns:
        if not isinstance(p, str) or not p.startswith("mcp__") or len(p) <= len("mcp__") or any(c in p for c in " ,()"):
            problems.append("bad MCP pattern %r (must start with mcp__<server>)" % (p,))
        elif p.startswith("mcp__*"):
            problems.append("MCP pattern %r would match every server" % (p,))
    return problems


REVIEWER = ToolPolicy("reviewer", builtin_tools=("Read", "Grep", "Glob"))
MCP_ONLY = ToolPolicy("mcp-only", builtin_tools=(), mcp_patterns=("mcp__tengoku",))
TRANSLATOR = ToolPolicy("translator", builtin_tools=(), mcp_patterns=("mcp__tengoku",))

PRESETS: Dict[str, ToolPolicy] = {"reviewer": REVIEWER, "mcp-only": MCP_ONLY, "translator": TRANSLATOR}


def translator_policy(mcp_patterns: Sequence[str] = ("mcp__tengoku",), *, allow_shell: bool = False) -> ToolPolicy:
    """The translator preset with its MCP server(s); Bash exists only when ``allow_shell=True`` is passed explicitly."""
    return ToolPolicy(
        "translator-shell" if allow_shell else "translator",
        builtin_tools=("Bash",) if allow_shell else (),
        mcp_patterns=tuple(mcp_patterns),
        allow_shell=allow_shell,
    )


def mcp_matches(tool: str, patterns: Iterable[str]) -> bool:
    """Does ``tool`` (``mcp__server__tool``) fall under any pattern (``mcp__server``, ``mcp__server__*``, exact)?"""
    if not tool.startswith("mcp__"):
        return False
    for p in patterns:
        if tool == p or tool.startswith(p + "__") or fnmatch.fnmatchcase(tool, p):
            return True
    return False


def _base_name(entry: str) -> str:
    """``Bash(git *)`` -> ``Bash``."""
    idx = entry.find("(")
    return entry if idx < 0 else entry[:idx]


def classify_tool(entry: str, policy: ToolPolicy) -> Optional[Violation]:
    """None when ``entry`` (a tool name or permission rule like ``Bash(git *)``) is allowed by ``policy``, else why not."""
    base = _base_name(entry.strip())
    if not base:
        return Violation("tool-not-in-policy", "empty tool entry", entry)
    if base.startswith("mcp__"):
        if mcp_matches(base, policy.mcp_patterns):
            return None
        return Violation("tool-not-in-policy", "MCP tool outside the policy's MCP patterns", base)
    if base in SHELL_TOOLS:
        if not policy.allow_shell:
            return Violation("shell-tool", "shell tool present but the policy does not allow a shell", base)
        if base not in policy.builtin_tools:
            return Violation("tool-not-in-policy", "tool not in the policy", base)
        return None
    if base in HIGH_RISK_TOOLS:
        if base not in policy.builtin_tools:
            return Violation("risky-tool", "high-risk tool (web, write, edit or sub-agent) not allowed by the policy", base)
        return None
    if base not in policy.builtin_tools:
        return Violation("tool-not-in-policy", "tool not in the policy", base)
    return None


# ----------------------------------------------------------------------------------------------
# argv construction and parsing
# ----------------------------------------------------------------------------------------------


def claude_args(
    policy: ToolPolicy,
    *,
    mcp_config: Optional[str] = None,
    settings: Optional[str] = None,
    max_budget_usd: Optional[float] = None,
    joined: bool = True,
) -> List[str]:
    """The argv fragment that restricts the Claude CLI to ``policy``.

    ``--tools`` (set level), ``--allowedTools`` (the MCP patterns, plus rules for allowed built-ins), ``--strict-mcp-config``,
    and optionally ``--mcp-config``, ``--settings`` (both should be files inside the run dir) and ``--max-budget-usd``.
    ``joined=True`` emits ``--tools=A,B`` so a positional prompt after the fragment is not swallowed by the variadic flag.
    """
    args: List[str] = []
    tools = ",".join(policy.builtin_tools)
    args += ["--tools=" + tools] if joined else ["--tools", tools]
    allowed = list(policy.builtin_tools) + list(policy.mcp_patterns)
    if allowed:
        allowed_csv = ",".join(allowed)
        args += ["--allowedTools=" + allowed_csv] if joined else ["--allowedTools", allowed_csv]
    args.append("--strict-mcp-config")
    if mcp_config:
        args += ["--mcp-config=" + mcp_config] if joined else ["--mcp-config", mcp_config]
    if settings:
        args += ["--settings=" + settings] if joined else ["--settings", settings]
    if max_budget_usd is not None:
        args += ["--max-budget-usd=%s" % max_budget_usd] if joined else ["--max-budget-usd", str(max_budget_usd)]
    return args


def split_tool_list(values: Iterable[str]) -> List[str]:
    """Split CLI tool values on commas and whitespace outside parentheses (``Bash(git *),Read`` -> two entries)."""
    out: List[str] = []
    for value in values:
        cur: List[str] = []
        depth = 0
        for ch in value:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth = max(0, depth - 1)
            if depth == 0 and (ch == "," or ch.isspace()):
                if cur:
                    out.append("".join(cur))
                    cur = []
            else:
                cur.append(ch)
        if cur:
            out.append("".join(cur))
    return out


_VARIADIC = {
    "--tools": "tools",
    "--allowedTools": "allowed",
    "--allowed-tools": "allowed",
    "--disallowedTools": "disallowed",
    "--disallowed-tools": "disallowed",
    "--add-dir": "add_dir",
    "--mcp-config": "mcp_config",
}
_SINGLE = {
    "--permission-mode": "permission_mode",
    "--settings": "settings",
    "--max-budget-usd": "budget",
    "--model": None,
    "--output-format": None,
    "--input-format": None,
    "--system-prompt": None,
    "--append-system-prompt": None,
    "--setting-sources": None,
    "--agent": None,
    "--agents": None,
    "--session-id": None,
    "--fallback-model": None,
    "--effort": None,
    "--max-turns": None,
}
_SKIP_FLAGS = ("--dangerously-skip-permissions", "--allow-dangerously-skip-permissions")


@dataclass
class ParsedClaude:
    tools: Optional[List[str]] = None  # None = no --tools flag at all
    tools_flag_count: int = 0
    tools_missing_value: bool = False
    allowed: List[str] = field(default_factory=list)
    disallowed: List[str] = field(default_factory=list)
    skip_permissions: List[str] = field(default_factory=list)
    permission_mode: Optional[str] = None
    strict_mcp: bool = False
    settings: List[str] = field(default_factory=list)
    mcp_config: List[str] = field(default_factory=list)
    add_dir: List[str] = field(default_factory=list)
    budget: Optional[str] = None


def parse_claude_argv(argv: Sequence[str]) -> ParsedClaude:
    """Parse the flags we care about the way the CLI's variadic options consume values (conservatively)."""
    p = ParsedClaude()
    toks = [str(a) for a in argv]
    i = 0
    n = len(toks)
    while i < n:
        tok = toks[i]
        i += 1
        if tok == "--":
            break
        if not tok.startswith("-") or tok == "-":
            continue
        name, eq, inline = tok.partition("=") if tok.startswith("--") else (tok, "", "")
        if name in _SKIP_FLAGS:
            p.skip_permissions.append(name)
            continue
        if name == "--strict-mcp-config":
            p.strict_mcp = True
            continue
        if name in _VARIADIC:
            values: List[str] = [inline] if eq else []
            if not eq:
                while i < n and (not toks[i].startswith("-") or toks[i] == "-"):
                    values.append(toks[i])
                    i += 1
            key = _VARIADIC[name]
            if key == "tools":
                p.tools_flag_count += 1
                p.tools = (p.tools or []) + split_tool_list(values)
                if not values:
                    p.tools_missing_value = True
            elif key == "allowed":
                p.allowed += split_tool_list(values)
            elif key == "disallowed":
                p.disallowed += split_tool_list(values)
            elif key == "add_dir":
                p.add_dir += values
            elif key == "mcp_config":
                p.mcp_config += values
            continue
        if name in _SINGLE:
            if eq:
                value: Optional[str] = inline
            elif i < n and not (toks[i].startswith("--")):
                value = toks[i]
                i += 1
            else:
                value = None
            key = _SINGLE[name]
            if key == "permission_mode":
                p.permission_mode = value
            elif key == "settings" and value is not None:
                p.settings.append(value)
            elif key == "budget":
                p.budget = value
    return p


def _inside(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def check_claude_argv(argv: Sequence[str], policy: ToolPolicy, run_dir: Optional[str] = None) -> List[Violation]:
    """Judge a Claude CLI argv against ``policy``; every returned Violation is an error.

    Rules (ids): ``no-tools-set`` (no ``--tools``: a deny-list alone leaves new built-ins reachable), ``tools-default``,
    ``tools-missing-value``, ``tools-repeated`` (ambiguous), ``allowed-without-tools`` (the Tau Ceti #123 bug),
    ``shell-tool`` / ``risky-tool`` / ``tool-not-in-policy`` (for entries in ``--tools`` and ``--allowedTools``),
    ``skip-permissions`` (bypass flag or ``--permission-mode bypassPermissions`` without ``allow_skip_permissions``),
    ``skip-permissions-unrestricted`` (allowed, but without a restricted ``--tools``), ``missing-strict-mcp``,
    ``settings-inline`` / ``settings-unverifiable`` / ``settings-outside-run-dir``, ``mcp-config-outside-run-dir``,
    ``missing-budget-cap`` (only when ``policy.require_limits``).

    Deviation from a literal reading of "when MCP is used": ``--strict-mcp-config`` is required ALWAYS, because without
    it the MCP servers of the user's and the checked-out repository's configuration become tools that ``--tools`` (built-ins
    only) does not remove.
    """
    p = parse_claude_argv(argv)
    out: List[Violation] = []

    if p.tools is None:
        detail = "only a deny-list (--disallowedTools) is present" if p.disallowed else ""
        out.append(Violation("no-tools-set", "no --tools set: a deny-list or permission rule does not restrict which built-in tools exist", detail))
    else:
        if p.tools_missing_value:
            out.append(Violation("tools-missing-value", "--tools given without a value"))
        if p.tools_flag_count > 1:
            out.append(Violation("tools-repeated", "--tools given %d times; the CLI's merge behaviour is not relied on" % p.tools_flag_count))
        for entry in p.tools:
            if entry.lower() == "default":
                out.append(Violation("tools-default", "--tools default enables every built-in tool"))
                continue
            v = classify_tool(entry, policy)
            if v is not None:
                out.append(v)
    if p.allowed and p.tools is None:
        out.append(Violation("allowed-without-tools", "--allowedTools without --tools only pre-approves tools; it does not limit them", ",".join(p.allowed)))
    for entry in p.allowed:
        v = classify_tool(entry, policy)
        if v is not None:
            out.append(v)

    skip_flags = list(p.skip_permissions)
    if p.permission_mode == "bypassPermissions":
        skip_flags.append("--permission-mode=bypassPermissions")
    if skip_flags:
        if not policy.allow_skip_permissions:
            out.append(Violation("skip-permissions", "permission bypass requested but the policy does not allow it", ",".join(skip_flags)))
        elif p.tools is None or any(t.lower() == "default" for t in p.tools):
            out.append(Violation("skip-permissions-unrestricted", "permission bypass without a restricted --tools set", ",".join(skip_flags)))

    if not p.strict_mcp:
        out.append(Violation("missing-strict-mcp", "--strict-mcp-config missing: ambient MCP servers would add tools"))

    for s in p.settings:
        if s.lstrip().startswith("{"):
            out.append(Violation("settings-inline", "inline --settings JSON is not auditable; write a file in the run dir"))
        elif run_dir is None:
            out.append(Violation("settings-unverifiable", "--settings given but no run_dir to check it against", s))
        elif not _inside(os.path.realpath(os.path.join(run_dir, s)), os.path.realpath(run_dir)):
            out.append(Violation("settings-outside-run-dir", "--settings points outside the run dir", s))
    for c in p.mcp_config:
        if c.lstrip().startswith("{"):
            continue  # inline server definitions are written by the launcher itself
        if run_dir is None or not _inside(os.path.realpath(os.path.join(run_dir, c)), os.path.realpath(run_dir)):
            out.append(Violation("mcp-config-outside-run-dir", "--mcp-config file is not provably inside the run dir", c))

    if policy.require_limits and p.budget is None:
        out.append(Violation("missing-budget-cap", "policy requires --max-budget-usd"))
    return out


# ----------------------------------------------------------------------------------------------
# Codex and unknown CLIs
# ----------------------------------------------------------------------------------------------

_CODEX_BYPASS = ("--dangerously-bypass-approvals-and-sandbox", "--yolo")


def check_codex_argv(argv: Sequence[str], *, allow_workspace_write: bool = False) -> List[Violation]:
    """Judge a Codex CLI argv: the sandbox must be ``read-only`` (or ``workspace-write`` if explicitly allowed).

    Assumes (unverified here, codex is not installed): ``-s``/``--sandbox <mode>``, ``--sandbox=<mode>`` and
    ``-c sandbox_mode=<mode>`` choose the sandbox; ``--dangerously-bypass-approvals-and-sandbox`` (alias ``--yolo``) and
    ``--full-auto`` remove protection.  A missing sandbox flag is a violation because the default comes from user config.
    """
    toks = [str(a) for a in argv]
    out: List[Violation] = []
    modes: List[str] = []
    i = 0
    while i < len(toks):
        tok = toks[i]
        i += 1
        if tok == "--":
            break
        name, eq, inline = tok.partition("=") if tok.startswith("--") else (tok, "", "")
        if tok in _CODEX_BYPASS or name in _CODEX_BYPASS:
            out.append(Violation("codex-bypass", "approvals and sandbox bypass flag present", tok))
        elif name == "--full-auto":
            out.append(Violation("codex-full-auto", "--full-auto grants workspace writes without approvals", tok))
        elif name in ("-s", "--sandbox"):
            if eq:
                modes.append(inline)
            elif i < len(toks):
                modes.append(toks[i])
                i += 1
            else:
                modes.append("")
        elif tok.startswith("-s") and len(tok) > 2 and not tok.startswith("--"):
            modes.append(tok[2:])
        elif name in ("-c", "--config"):
            kv = inline if eq else (toks[i] if i < len(toks) else "")
            if not eq:
                i += 1
            m = re.match(r"^\s*sandbox_mode\s*=\s*[\"']?([A-Za-z\-]+)[\"']?\s*$", kv)
            if m:
                modes.append(m.group(1))
    if not modes:
        out.append(Violation("codex-sandbox-missing", "no explicit sandbox mode; the default comes from user configuration"))
    for mode in modes:
        if mode == "read-only":
            continue
        if mode == "danger-full-access":
            out.append(Violation("codex-danger-full-access", "sandbox is danger-full-access", mode))
        elif mode == "workspace-write" and allow_workspace_write:
            continue
        else:
            out.append(Violation("codex-sandbox-not-read-only", "sandbox must be read-only", mode))
    return out


def identify_cli(argv: Sequence[str]) -> str:
    """'claude', 'codex' or 'unknown', from the first few non-option, non-assignment tokens (wrappers like env/sudo/node are skipped)."""
    seen = 0
    for tok in argv:
        tok = str(tok)
        if tok.startswith("-") or ("=" in tok and "/" not in tok.split("=", 1)[0]):
            continue
        seen += 1
        low = tok.replace("\\", "/").lower()
        base = os.path.basename(low)
        for ext in (".js", ".mjs", ".cjs", ".exe"):
            if base.endswith(ext):
                base = base[: -len(ext)]
        if base == "claude" or "@anthropic-ai/claude-code" in low:
            return "claude"
        if base == "codex" or "@openai/codex" in low:
            return "codex"
        if seen >= 6:
            break
    return "unknown"


def check_unknown(argv: Sequence[str], policy: Optional[ToolPolicy] = None) -> List[Violation]:
    """Refuse an unrecognised CLI (we cannot judge its flags) unless the policy says ``allow_unknown_cli``."""
    if identify_cli(argv) != "unknown":
        return []
    if policy is not None and policy.allow_unknown_cli:
        return []
    head = os.path.basename(str(argv[0])) if argv else ""
    return [Violation("unknown-cli", "unrecognised agent CLI; its tool and sandbox flags cannot be checked", head)]


def check_argv(argv: Sequence[str], policy: ToolPolicy, run_dir: Optional[str] = None) -> List[Violation]:
    """Dispatch on the CLI: claude -> check_claude_argv, codex -> check_codex_argv, else check_unknown."""
    cli = identify_cli(argv)
    if cli == "claude":
        return check_claude_argv(argv, policy, run_dir)
    if cli == "codex":
        return check_codex_argv(argv)
    return check_unknown(argv, policy)


def assert_argv_builder_enforced(builder, policy: ToolPolicy, cases: Iterable[Any], run_dir: Optional[str] = None) -> None:
    """For a project's unit tests: ``builder(case)`` must return an argv that passes ``check_argv`` for every case.

    Raises AssertionError listing each failing case and its violations.
    """
    failures: List[str] = []
    n = 0
    for case in cases:
        n += 1
        argv = builder(case)
        violations = check_argv(argv, policy, run_dir)
        if violations:
            failures.append("case %r: %s" % (case, "; ".join(str(v) for v in violations)))
    if n == 0:
        raise AssertionError("assert_argv_builder_enforced needs at least one case")
    if failures:
        raise AssertionError("argv builder does not enforce policy %r:\n%s" % (policy.name, "\n".join(failures)))


# ----------------------------------------------------------------------------------------------
# stream-json trace audit
# ----------------------------------------------------------------------------------------------


@dataclass
class TraceReport:
    calls_by_tool: Dict[str, int] = field(default_factory=dict)
    total_calls: int = 0
    denied: int = 0
    failed: int = 0
    unparsed_lines: int = 0
    events: int = 0
    init_tools: Optional[List[str]] = None
    violations: List[Violation] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.events > 0 and not any(v.severity == "error" for v in self.violations)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "calls_by_tool": dict(sorted(self.calls_by_tool.items())),
            "total_calls": self.total_calls,
            "denied": self.denied,
            "failed": self.failed,
            "unparsed_lines": self.unparsed_lines,
            "events": self.events,
            "init_tools": self.init_tools,
            "violations": [v.to_dict() for v in self.violations],
        }


_DENIED_RE = re.compile(r"permission|denied|not allowed|isn't allowed|not available|haven't granted|no such tool|requires approval", re.I)
_PATH_KEYS = ("file_path", "path", "notebook_path")
_GLOB_CHARS = "*?[{"


def _iter_blocks(obj: Any, depth: int = 0) -> Iterator[Dict[str, Any]]:
    if depth > 12:
        return
    if isinstance(obj, dict):
        if obj.get("type") in ("tool_use", "tool_result", "server_tool_use"):
            yield obj
            return
        for v in obj.values():
            if isinstance(v, (dict, list)):
                for b in _iter_blocks(v, depth + 1):
                    yield b
    elif isinstance(obj, list):
        for v in obj:
            for b in _iter_blocks(v, depth + 1):
                yield b


def _result_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for c in content:
            if isinstance(c, dict) and isinstance(c.get("text"), str):
                parts.append(c["text"])
            elif isinstance(c, str):
                parts.append(c)
        return " ".join(parts)
    return ""


def _static_prefix(pattern: str) -> str:
    parts = pattern.split("/")
    keep: List[str] = []
    for part in parts:
        if any(c in part for c in _GLOB_CHARS):
            break
        keep.append(part)
    prefix = "/".join(keep)
    return prefix if prefix or not pattern.startswith("/") else "/"


def resolve_in_workspace(path: str, workspace_dirs: Sequence[str], cwd: Optional[str] = None) -> Tuple[bool, str]:
    """(inside, resolved): is ``path`` (relative to ``cwd`` or the first workspace dir; ``~`` expanded; symlinks resolved)
    within one of ``workspace_dirs``?  Empty ``workspace_dirs`` -> never inside (fail closed)."""
    roots = [os.path.realpath(w) for w in workspace_dirs]
    base = cwd or (workspace_dirs[0] if workspace_dirs else os.getcwd())
    expanded = os.path.expanduser(path)
    resolved = os.path.realpath(os.path.join(base, expanded))
    return any(_inside(resolved, r) for r in roots), resolved


def _short(text: str, limit: int = 60) -> str:
    words = []
    try:
        from warden import envscrub

        for w in text.split():
            words.append("<redacted>" if envscrub.looks_secret_value(w) else w)
    except Exception:  # noqa: BLE001
        words = text.split()
    s = " ".join(words)
    return s if len(s) <= limit else s[:limit] + "..."


def audit_trace_claude(
    lines: Iterable[Any],
    policy: ToolPolicy,
    workspace_dirs: Sequence[str],
    cwd: Optional[str] = None,
) -> TraceReport:
    """Audit Claude ``--output-format stream-json`` lines (str, bytes or already-parsed dicts) against ``policy``.

    Reports: calls per tool; denied and failed counts (from ``tool_result`` blocks with ``is_error``); violations:
    a tool outside the policy was invoked or announced in the init event (``tool-not-in-policy``, ``shell-tool``,
    ``risky-tool``; shell and WebFetch/WebSearch have their own ids when disallowed), a shell command present
    (``shell-command``), a Read/Grep/Glob/LS path resolving outside ``workspace_dirs`` (``path-outside-workspace``),
    permission bypass in the init event, and an empty trace (``empty-trace``: no evidence is a failure).
    A call whose result shows it was denied is a ``warn`` (attempt), anything else an ``error``.
    Unknown shapes and non-JSON lines are tolerated and counted in ``unparsed_lines``.
    """
    rep = TraceReport()
    uses: Dict[str, Dict[str, Any]] = {}  # tool_use id -> {name, input}
    results: Dict[str, Tuple[bool, str]] = {}  # tool_use id -> (is_error, text)
    anon = 0
    for raw in lines:
        if isinstance(raw, (bytes, bytearray)):
            raw = bytes(raw).decode("utf-8", "replace")
        if isinstance(raw, dict):
            ev: Any = raw
        else:
            text = str(raw).strip()
            if not text:
                continue
            try:
                ev = json.loads(text)
            except ValueError:
                rep.unparsed_lines += 1
                continue
        if not isinstance(ev, dict):
            rep.unparsed_lines += 1
            continue
        rep.events += 1
        if ev.get("type") == "system" and ev.get("subtype") == "init":
            tools = ev.get("tools")
            if isinstance(tools, list):
                names = [t if isinstance(t, str) else (t.get("name") if isinstance(t, dict) else None) for t in tools]
                rep.init_tools = [n for n in names if isinstance(n, str)]
            mode = ev.get("permissionMode")
            if mode == "bypassPermissions" and not policy.allow_skip_permissions:
                rep.violations.append(Violation("skip-permissions", "session started with permission bypass", "permissionMode"))
        for blk in _iter_blocks(ev):
            if blk.get("type") == "tool_result":
                tid = blk.get("tool_use_id")
                if isinstance(tid, str):
                    results[tid] = (bool(blk.get("is_error")), _result_text(blk.get("content")))
                continue
            name = blk.get("name")
            if not isinstance(name, str):
                continue
            tid = blk.get("id")
            if not isinstance(tid, str):
                anon += 1
                tid = "anon-%d" % anon
            prev = uses.get(tid)
            inp = blk.get("input") if isinstance(blk.get("input"), dict) else {}
            if prev is None or (not prev["input"] and inp):
                uses[tid] = {"name": name, "input": inp}

    if rep.init_tools is not None:
        for t in rep.init_tools:
            v = classify_tool(t, policy)
            if v is not None:
                rep.violations.append(Violation(v.rule, "tool available to the session is outside the policy: " + v.message, t))

    for tid, use in uses.items():
        name, inp = use["name"], use["input"]
        rep.total_calls += 1
        rep.calls_by_tool[name] = rep.calls_by_tool.get(name, 0) + 1
        is_error, text = results.get(tid, (False, ""))
        denied = is_error and bool(_DENIED_RE.search(text))
        if is_error:
            if denied:
                rep.denied += 1
            else:
                rep.failed += 1
        severity = "warn" if denied else "error"

        def add(rule: str, message: str, detail: str = "") -> None:
            rep.violations.append(Violation(rule, message, detail, severity))

        v = classify_tool(name, policy)
        if v is not None:
            add(v.rule, "tool invoked outside the policy: " + v.message, name)
        if name in SHELL_TOOLS:
            cmd = inp.get("command")
            add("shell-command", "a shell command was requested", _short(cmd) if isinstance(cmd, str) else "")
        if name in WEB_TOOLS and v is not None:
            add("web-access", "web tool invoked", name)
        if name in READ_TOOLS:
            for key in _PATH_KEYS + (("pattern",) if name == "Glob" else ()):
                val = inp.get(key)
                if val is None:
                    continue
                if not isinstance(val, str):
                    add("path-outside-workspace", "non-string path argument", "%s.%s" % (name, key))
                    continue
                target = _static_prefix(val) if key == "pattern" else val
                if key == "pattern" and not (os.path.isabs(val) or ".." in val.split("/") or val.startswith("~")):
                    continue  # a relative glob pattern is relative to an already-checked path
                inside, resolved = resolve_in_workspace(target, workspace_dirs, cwd)
                if not inside:
                    add("path-outside-workspace", "%s read a path outside the workspace" % name, resolved)

    if rep.events == 0:
        rep.violations.append(Violation("empty-trace", "no parsable events: nothing to audit counts as a failure"))
    return rep


# ----------------------------------------------------------------------------------------------
# source scanner for spawn sites
# ----------------------------------------------------------------------------------------------

_FLAG_PATTERNS: Tuple[Tuple[str, str, "re.Pattern[str]"], ...] = (
    ("--dangerously-skip-permissions", "cli-flag", re.compile(r"(?<![\w-])--(?:allow-)?dangerously-skip-permissions(?![\w-])")),
    ("--allowedTools", "cli-flag", re.compile(r"(?<![\w-])--allowed(?:Tools|-tools)(?![\w-])")),
    ("--disallowedTools", "cli-flag", re.compile(r"(?<![\w-])--disallowed(?:Tools|-tools)(?![\w-])")),
    ("bypassPermissions", "cli-flag", re.compile(r"bypassPermissions")),
    ("allowedTools:", "sdk-option", re.compile(r"(?<![\w-])allowedTools\s*:")),
    ("disallowedTools:", "sdk-option", re.compile(r"(?<![\w-])disallowedTools\s*:")),
    ("allowDangerouslySkipPermissions", "sdk-option", re.compile(r"allowDangerouslySkipPermissions\s*:\s*true")),
)
_TOOLS_FLAG = re.compile(r"(?<![\w-])--tools(?![\w-])")
_SDK_TOOLS = re.compile(r"(?<![\w.-])tools\s*:\s*[\[\"'`]")
_DEF_RE = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?(?:function\b|def\b|class\b)"
    r"|^\s*(?:public|private|protected|static)\s+(?:async\s+)?\w+\s*\("
    r"|^\s*(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>"
    r"|^\s*(?!(?:if|for|while|switch|catch|else|return|with)\b)(?:async\s+)?\w+\s*\([^)]*\)\s*\{\s*$"
)


@dataclass(frozen=True)
class SpawnFinding:
    path: str
    line: int
    flag: str
    kind: str  # cli-flag | sdk-option
    in_comment: bool
    has_tools_set: bool  # a --tools set (or SDK tools option) appears in the same argument-building region
    tools_in_group: bool  # ... and in the same bracket group (stricter, informational)
    region: Tuple[int, int]
    snippet: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path, "line": self.line, "flag": self.flag, "kind": self.kind, "in_comment": self.in_comment,
            "has_tools_set": self.has_tools_set, "tools_in_group": self.tools_in_group, "region": list(self.region),
            "snippet": self.snippet,
        }


@dataclass
class SpawnScan:
    path: str
    findings: List[SpawnFinding] = field(default_factory=list)
    tools_flag_lines: List[int] = field(default_factory=list)
    error: str = ""


def _lex(text: str, py: bool) -> Tuple[List[Tuple[int, int]], List[Tuple[int, str]]]:
    """Heuristic lexer: returns (comment spans, code-level bracket events).  Strings are skipped for brackets.

    Best effort: JS regex literals containing quotes can confuse it; the scanner reports what it can see.
    """
    comments: List[Tuple[int, int]] = []
    brackets: List[Tuple[int, str]] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        two = text[i : i + 2]
        if (py and ch == "#") or (not py and two == "//"):
            j = text.find("\n", i)
            j = n if j < 0 else j
            comments.append((i, j))
            i = j
        elif not py and two == "/*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            comments.append((i, j))
            i = j
        elif ch in "\"'`":
            if py and text[i : i + 3] in ('"""', "'''"):
                q = text[i : i + 3]
                j = text.find(q, i + 3)
                i = n if j < 0 else j + 3
                continue
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == ch or (ch != "`" and text[j] == "\n"):
                    break
                j += 1
            i = j + 1
        else:
            if ch in "([{)]}":
                brackets.append((i, ch))
            i += 1
    return comments, brackets


def _enclosing_group(brackets: List[Tuple[int, str]], pos: int) -> Optional[Tuple[int, int]]:
    stack: List[int] = []
    pairs: Dict[int, int] = {}
    for p, ch in brackets:
        if ch in "([{":
            stack.append(p)
        elif stack:
            pairs[stack.pop()] = p
    best: Optional[Tuple[int, int]] = None
    for start, end in pairs.items():
        if start < pos < end and (best is None or start > best[0]):
            best = (start, end)
    return best


def analyze_spawn_source(text: str, path: str = "<source>") -> SpawnScan:
    """Pure core of ``scan_source_for_spawn_flags``."""
    py = path.endswith(".py")
    scan = SpawnScan(path=path)
    lines = text.split("\n")
    offsets = [0]
    for ln in lines:
        offsets.append(offsets[-1] + len(ln) + 1)
    comments, brackets = _lex(text, py)

    def in_comment(pos: int) -> bool:
        return any(s <= pos < e for s, e in comments)

    def line_of(pos: int) -> int:
        lo, hi = 0, len(lines)
        while lo < hi:
            mid = (lo + hi) // 2
            if offsets[mid + 1] <= pos:
                lo = mid + 1
            else:
                hi = mid
        return lo  # 0-based

    def indent(s: str) -> int:
        return len(s) - len(s.lstrip())

    def region_of(idx: int) -> Tuple[int, int]:
        cur_indent = indent(lines[idx])
        start = 0
        for j in range(idx, -1, -1):
            if _DEF_RE.match(lines[j]) and indent(lines[j]) <= cur_indent:
                start = j
                break
        d_indent = indent(lines[start])
        end = len(lines) - 1
        for j in range(start + 1, len(lines)):
            if _DEF_RE.match(lines[j]) and indent(lines[j]) <= d_indent:
                end = j - 1
                break
        return start, end

    tools_positions = [m.start() for m in _TOOLS_FLAG.finditer(text) if not in_comment(m.start())]
    tools_positions += [m.start() for m in _SDK_TOOLS.finditer(text) if not in_comment(m.start())]
    scan.tools_flag_lines = sorted({line_of(p) + 1 for p in tools_positions})

    for flag, kind, pat in _FLAG_PATTERNS:
        for m in pat.finditer(text):
            pos = m.start()
            idx = line_of(pos)
            r0, r1 = region_of(idx)
            lo, hi = offsets[r0], offsets[min(r1 + 1, len(lines))]
            has_tools = any(lo <= p < hi for p in tools_positions)
            group = _enclosing_group(brackets, pos)
            in_group = bool(group) and any(group[0] < p < group[1] for p in tools_positions)
            scan.findings.append(
                SpawnFinding(path, idx + 1, flag, kind, in_comment(pos), has_tools, in_group, (r0 + 1, r1 + 1), lines[idx].strip()[:160])
            )
    scan.findings.sort(key=lambda f: (f.line, f.flag))
    return scan


def scan_source_for_spawn_flags(path: str) -> SpawnScan:
    """Scan a JS/TS/Python source file for CLI spawn sites: each ``--dangerously-skip-permissions``, ``--allowedTools``,
    ``--disallowedTools`` (and SDK-style ``allowedTools:`` / ``permissionMode: 'bypassPermissions'``), with whether a
    ``--tools`` set appears in the same function-level argument-building region.  Heuristic (no real parser); a read error
    is recorded in ``SpawnScan.error`` and ``spawn_violations`` treats it as a failure.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return SpawnScan(path=path, error="%s: %s" % (type(exc).__name__, exc))
    return analyze_spawn_source(text, path)


def spawn_violations(scan: SpawnScan, policy: Optional[ToolPolicy] = None) -> List[Violation]:
    """CI gate over a ``SpawnScan``.  Commented-out flags are ignored.

    * ``spawn-skip-permissions-unrestricted``: bypass flag with no ``--tools`` set in its region.
    * ``spawn-skip-permissions``: bypass flag, set present, but the policy (default: strict) forbids bypass.
    * ``spawn-allowedtools-without-tools``: ``--allowedTools`` with no ``--tools`` set (the Tau Ceti #123 bug).
    * ``spawn-denylist-only``: ``--disallowedTools`` with no ``--tools`` set.
    * ``spawn-unreadable``: the file could not be read.
    """
    if scan.error:
        return [Violation("spawn-unreadable", "could not read the source file", scan.error)]
    allow_skip = bool(policy and policy.allow_skip_permissions)
    out: List[Violation] = []
    for f in scan.findings:
        if f.in_comment:
            continue
        where = "%s:%d" % (f.path, f.line)
        if f.flag in ("--dangerously-skip-permissions", "bypassPermissions", "allowDangerouslySkipPermissions"):
            if not f.has_tools_set:
                out.append(Violation("spawn-skip-permissions-unrestricted", "permission bypass without a --tools set in the same region", where))
            elif not allow_skip:
                out.append(Violation("spawn-skip-permissions", "permission bypass present; the policy does not allow it", where))
        elif f.flag in ("--allowedTools", "allowedTools:"):
            if not f.has_tools_set:
                out.append(Violation("spawn-allowedtools-without-tools", "--allowedTools without a --tools set in the same region", where))
        elif f.flag in ("--disallowedTools", "disallowedTools:"):
            if not f.has_tools_set:
                out.append(Violation("spawn-denylist-only", "deny-list without a --tools set in the same region", where))
    unique: List[Violation] = []
    for v in out:
        if v not in unique:
            unique.append(v)
    return unique


# ----------------------------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------------------------


def _policy_from_name(name: str, allow_shell: bool = False) -> ToolPolicy:
    if name == "translator" and allow_shell:
        return translator_policy(allow_shell=True)
    try:
        return PRESETS[name]
    except KeyError:
        raise SystemExit("unknown policy %r (choose from %s)" % (name, ", ".join(sorted(PRESETS))))


def main(argv: Optional[Sequence[str]] = None) -> int:
    """``toolpolicy args|check-argv|audit-trace|scan-source``.  Exit 0 ok, 1 violations, 2 bad input."""
    ap = argparse.ArgumentParser(prog="warden toolpolicy", description="Tool allowlist policy: build, check and audit.")
    sub = ap.add_subparsers(dest="cmd")
    a = sub.add_parser("args", help="print the claude argv fragment for a policy")
    a.add_argument("--policy", default="reviewer")
    c = sub.add_parser("check-argv", help="check an argv given after --")
    c.add_argument("--policy", default="reviewer")
    c.add_argument("--run-dir")
    c.add_argument("argv", nargs=argparse.REMAINDER)
    t = sub.add_parser("audit-trace", help="audit a stream-json trace file")
    t.add_argument("trace")
    t.add_argument("--policy", default="reviewer")
    t.add_argument("--workspace", action="append", default=[])
    t.add_argument("--json", dest="json_out")
    s = sub.add_parser("scan-source", help="scan JS/TS/Python sources for risky spawn flags")
    s.add_argument("files", nargs="+")
    s.add_argument("--allow-skip-permissions", action="store_true")
    try:
        ns = ap.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2
    if not ns.cmd:
        ap.print_usage(sys.stderr)
        return 2
    try:
        if ns.cmd == "args":
            print(" ".join(claude_args(_policy_from_name(ns.policy))))
            return 0
        if ns.cmd == "check-argv":
            rest = ns.argv[1:] if ns.argv[:1] == ["--"] else ns.argv
            vs = check_argv(rest, _policy_from_name(ns.policy), ns.run_dir)
            for v in vs:
                print(v)
            return 1 if vs else 0
        if ns.cmd == "audit-trace":
            with open(ns.trace, "r", encoding="utf-8", errors="replace") as fh:
                rep = audit_trace_claude(fh, _policy_from_name(ns.policy), ns.workspace or [os.getcwd()])
            text = json.dumps(rep.to_dict(), indent=2, sort_keys=True)
            if ns.json_out:
                with open(ns.json_out, "w", encoding="utf-8") as out:
                    out.write(text + "\n")
            else:
                print(text)
            return 0 if rep.ok else 1
        if ns.cmd == "scan-source":
            pol = ToolPolicy("scan", allow_skip_permissions=ns.allow_skip_permissions)
            bad = 0
            for f in ns.files:
                for v in spawn_violations(scan_source_for_spawn_flags(f), pol):
                    print(v)
                    bad += 1
            return 1 if bad else 0
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())

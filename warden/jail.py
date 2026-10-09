"""Pure builders for the isolation commands a CI runner executes around an untrusted agent.

Nothing here runs anything: every function returns argv lists or shell text that the workflow (a person reading the audit
log can read it first) executes with ``sudo``.  The pieces: ``bwrap_argv`` (a bubblewrap sandbox), ``uid_egress_rules`` and
``uid_egress_teardown`` (iptables/ip6tables rules keyed on the agent's uid), ``agent_user_script`` (an unprivileged user with
no sudo, a closed runner home, ``hidepid=2`` on /proc and an agent-owned workspace), ``run_as_argv`` (``sudo -u`` with a
cleared environment), ``JailSpec`` to tie them together and ``describe`` for the audit log.

Credit: Tau Ceti Project, TauCeti ``scripts/sandbox-build.sh`` and the build workflows (research report
``report-main-roadmap.md``, feature B4 and findings F-4, F-20, F-21).  Their published behaviour is the model: a tmpfs root with
read-only binds and ``--remount-ro /`` (finding F-21: a fresh tmpfs root is writable, so a planted binary on PATH would run in
later steps), a PATH with no writable directory, ``env -i`` so PID 1's environment cannot leak the launcher's secrets,
namespaces named one by one because ``--unshare-all`` uses the "try" user-namespace form that silently skips, plus
``--disable-userns``, ``--die-with-parent`` and ``--new-session``; and the lesson of GHSA-pxhw-h44j-8pfx (bubblewrap following
a committed symlink at a mount point), which is why the workspace here must be a directory the launcher created.  TauCetiWorker
documents that its agents run with the operator's network and credentials and has only an opt-in container (report
``report-worker-claims.md``, items 1.1, 1.6).

What we do differently: this is code written from those ideas, not copied.  /etc is not bound whole (only the files a
toolchain needs; Tau Ceti lists "/etc readable" as a limit); network is off by default, and when it is on a per-uid iptables
and ip6tables chain rejects everything except named loopback ports, the cloud metadata addresses and IPv6 included (Bubble's
own limits list DNS exfiltration and iptables-only enforcement; the self-test in ``warden.selftest`` checks the result from
inside); the agent runs as a separate unprivileged user so the runner's /proc and home are not readable; every builder
validates its input and raises ``JailSpecError`` instead of emitting a weaker command.

Assumptions (not verifiable here, bwrap/iptables are not run): bubblewrap >= 0.8 for ``--assert-userns-disabled`` (older
versions reject the flag, which fails the launch closed); ``--ro-bind-try`` is the bubblewrap option for optional paths and is
unrelated to the "try" unshare form; ``iptables -w`` waits for the xtables lock.  Python 3.9 compatible.
"""
from __future__ import annotations

import hashlib
import os
import posixpath
import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

DEFAULT_RO_BINDS: Tuple[str, ...] = ("/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32")
DEFAULT_ETC_BINDS: Tuple[str, ...] = (
    "/etc/alternatives", "/etc/ssl", "/etc/ca-certificates", "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
    "/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/etc/hosts", "/etc/localtime",
)
DEFAULT_PATH_DIRS: Tuple[str, ...] = ("/usr/local/bin", "/usr/bin", "/bin")

_FORBIDDEN_EXACT = ("/", "/home", "/root", "/etc", "/boot", "/var", "/tmp", "/run", "/var/run", "/run/user")
_FORBIDDEN_TREES = (
    "/proc", "/sys", "/dev", "/root", "/var/lib/docker", "/run/docker", "/var/run/docker", "/run/containerd", "/run/podman",
    "/run/dbus", "/var/run/dbus", "/run/systemd", "/run/user",
)
_SOCKET_NAMES = ("docker.sock", "containerd.sock", "podman.sock", "docker.pid")
_SENSITIVE_PARTS = ("/.ssh", "/.config/gh", "/.aws", "/.claude", "/.git-credentials", "/.netrc", "/.gnupg", "/.docker")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,30}$")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HOST_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
UID_VAR = "$AGENT_UID"


class JailSpecError(ValueError):
    """The jail description is unsafe or malformed; ``problems`` lists every reason."""

    def __init__(self, problems: Sequence[str]):
        self.problems = list(problems)
        super().__init__("; ".join(self.problems))


@dataclass(frozen=True)
class JailSpec:
    """Everything needed to build one jailed launch.

    ``workspace`` is the only writable path (plus a private tmpfs on /tmp).  ``command`` is the agent argv.  ``env`` is given
    to the child with ``--setenv`` (the sandbox launcher itself runs under ``env -i``); PATH and HOME are set by the jail from
    ``path_dirs`` and a tmpfs home.  ``tool_binds`` are extra read-only paths that must exist (the Claude CLI's install, node).
    ``channel_binds`` are extra WRITABLE paths (for example a directory holding a unix socket to the host's proxy) and are
    listed in the audit text.  ``network=False`` unshares the network namespace; ``network=True`` shares it and requires
    ``uid`` so ``uid_egress_rules`` can fence the agent, unless ``network_unrestricted_ok`` says otherwise.
    """

    workspace: str
    command: Tuple[str, ...]
    env: Mapping[str, str] = field(default_factory=dict)
    path_dirs: Tuple[str, ...] = DEFAULT_PATH_DIRS
    ro_binds: Tuple[str, ...] = DEFAULT_RO_BINDS
    etc_binds: Tuple[str, ...] = DEFAULT_ETC_BINDS
    tool_binds: Tuple[str, ...] = ()
    channel_binds: Tuple[str, ...] = ()
    network: bool = False
    allowed_loopback_ports: Tuple[int, ...] = ()
    uid: Optional[int] = None
    user: Optional[str] = None
    network_unrestricted_ok: bool = False
    hostname: str = "warden"
    bwrap_path: str = "/usr/bin/bwrap"
    secret_ok: Tuple[str, ...] = ()
    assert_userns_disabled: bool = True


# ----------------------------------------------------------------------------------------------
# validation
# ----------------------------------------------------------------------------------------------


def _clean_abs(path: str) -> Optional[str]:
    """Normalised absolute path, or None if it is relative, has '..', NUL, comma or whitespace tricks."""
    if not isinstance(path, str) or not path.startswith("/") or "\x00" in path or "\n" in path:
        return None
    if ".." in path.split("/"):
        return None
    return posixpath.normpath(path)


def _sensitive_bind(c: str) -> bool:
    """A bind source that would hand the agent host state: the root, system trees, a whole home, or a credential directory."""
    if c in _FORBIDDEN_EXACT or _under(c, _FORBIDDEN_TREES) or posixpath.basename(c) in _SOCKET_NAMES:
        return True
    return any(part + "/" in c + "/" for part in _SENSITIVE_PARTS)


def _under(path: str, roots: Iterable[str]) -> bool:
    return any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots)


def jail_problems(spec: JailSpec) -> List[str]:
    """Every reason ``spec`` cannot be turned into a safe command (empty list = fine)."""
    problems: List[str] = []
    ws = _clean_abs(spec.workspace)
    if ws is None or ws == "/":
        problems.append("workspace must be an absolute directory other than / without '..'")
        ws = None
    if not spec.command or not all(isinstance(c, str) and c and "\x00" not in c for c in spec.command):
        problems.append("command must be a non-empty argv of non-empty strings")
    if not _HOST_RE.match(spec.hostname):
        problems.append("hostname is not a plain DNS label")
    if not _clean_abs(spec.bwrap_path):
        problems.append("bwrap_path must be an absolute path")
    if spec.user is not None and not _USER_RE.match(spec.user):
        problems.append("user name %r is not a plain lowercase account name" % (spec.user,))

    ro_clean: List[str] = []
    for label, items in (("ro_binds", spec.ro_binds), ("etc_binds", spec.etc_binds), ("tool_binds", spec.tool_binds)):
        for p in items:
            c = _clean_abs(p)
            if c is None:
                problems.append("%s entry %r is not a clean absolute path" % (label, p))
                continue
            ro_clean.append(c)
            if label == "etc_binds":
                if c == "/etc" or not c.startswith("/etc/"):
                    problems.append("etc_binds must name individual files or directories under /etc, got %s" % c)
            elif _sensitive_bind(c):
                problems.append("%s entry %s exposes a sensitive host path" % (label, c))
    for p in spec.channel_binds:
        c = _clean_abs(p)
        if c is None or _sensitive_bind(c):
            problems.append("channel_binds entry %r is not a safe absolute path" % (p,))
        elif ws is not None and (c == ws):
            problems.append("channel_binds entry duplicates the workspace")
    if ws is not None:
        if _under(ws, list(DEFAULT_RO_BINDS) + ["/proc", "/dev", "/sys", "/tmp", "/etc"] + ro_clean):
            problems.append("workspace %s overlaps a read-only, system or tmpfs path" % ws)

    writable = ([ws] if ws else []) + ["/tmp"] + [c for c in (_clean_abs(p) for p in spec.channel_binds) if c]
    for d in spec.path_dirs:
        c = _clean_abs(d)
        if c is None:
            problems.append("PATH entry %r is not a clean absolute path" % (d,))
        elif _under(c, writable):
            problems.append("PATH entry %s is inside a writable location" % c)
        elif not _under(c, ro_clean):
            problems.append("PATH entry %s is not inside a read-only bind" % c)
    if not spec.path_dirs:
        problems.append("path_dirs is empty")

    try:
        from warden import envscrub
    except ImportError:  # pragma: no cover - sibling module always present in the package
        envscrub = None  # type: ignore[assignment]
    ok = set(spec.secret_ok)
    for name, value in spec.env.items():
        if not isinstance(name, str) or not _ENV_NAME_RE.match(name):
            problems.append("env name %r is invalid" % (name,))
            continue
        if name in ("PATH", "HOME", "TMPDIR"):
            problems.append("env %s is set by the jail; do not pass it" % name)
        if not isinstance(value, str) or "\x00" in value:
            problems.append("env %s has a non-string or NUL value" % name)
            continue
        if envscrub is not None and name not in ok and (envscrub.looks_secret_name(name) or envscrub.looks_secret_value(value)):
            problems.append("env %s looks like a secret; list it in secret_ok to pass it deliberately" % name)

    seen_ports = set()
    for port in spec.allowed_loopback_ports:
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            problems.append("loopback port %r is invalid" % (port,))
        elif port in seen_ports:
            problems.append("loopback port %d listed twice" % port)
        seen_ports.add(port)
    if spec.allowed_loopback_ports and not spec.network:
        problems.append("allowed_loopback_ports needs network=True (a separate network namespace has its own loopback)")
    if spec.network and (spec.uid is None or spec.uid <= 0) and not spec.network_unrestricted_ok:
        problems.append("network=True needs the agent's uid so uid_egress_rules can fence it (or network_unrestricted_ok=True)")
    if spec.uid is not None and (not isinstance(spec.uid, int) or spec.uid <= 0):
        problems.append("uid must be a positive integer")
    return problems


def _raise_if_bad(spec: JailSpec) -> None:
    problems = jail_problems(spec)
    if problems:
        raise JailSpecError(problems)


# ----------------------------------------------------------------------------------------------
# bubblewrap
# ----------------------------------------------------------------------------------------------


def bwrap_argv(spec: JailSpec, *, env_i: bool = True) -> List[str]:
    """The bubblewrap command line (list form, no shell).  Raises ``JailSpecError`` for an unsafe spec.

    Order: namespaces named one by one, ``--disable-userns``, ``--die-with-parent``, ``--new-session``, ``--cap-drop ALL``,
    a tmpfs root with read-only binds, /proc, /dev, a private /tmp and HOME, the workspace as the only bind-writable path,
    ``--remount-ro /``, ``--chdir``, ``--setenv`` for the child, then ``--`` and the agent argv.  With ``env_i`` the whole
    command is prefixed by ``env -i`` so the launcher (PID 1 inside the sandbox) has an empty environment.
    """
    _raise_if_bad(spec)
    ws = _clean_abs(spec.workspace) or spec.workspace
    argv: List[str] = (["env", "-i"] if env_i else []) + [spec.bwrap_path]
    argv += ["--unshare-user", "--unshare-ipc", "--unshare-pid"]
    if not spec.network:
        argv.append("--unshare-net")
    argv += ["--unshare-uts", "--unshare-cgroup", "--disable-userns"]
    if spec.assert_userns_disabled:
        argv.append("--assert-userns-disabled")
    argv += ["--die-with-parent", "--new-session", "--cap-drop", "ALL", "--hostname", spec.hostname]
    argv += ["--tmpfs", "/"]
    for p in spec.ro_binds:
        argv += ["--ro-bind-try", p, p]
    for p in spec.etc_binds:
        argv += ["--ro-bind-try", p, p]
    for p in spec.tool_binds:
        argv += ["--ro-bind", p, p]
    argv += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/tmp/home"]
    argv += ["--bind", ws, ws]
    for p in spec.channel_binds:
        argv += ["--bind", p, p]
    argv += ["--remount-ro", "/", "--chdir", ws]
    child_env: Dict[str, str] = {"PATH": ":".join(spec.path_dirs), "HOME": "/tmp/home", "TMPDIR": "/tmp"}
    child_env.update(spec.env)
    for k in sorted(child_env):
        argv += ["--setenv", k, child_env[k]]
    argv.append("--")
    argv += list(spec.command)
    return argv


# ----------------------------------------------------------------------------------------------
# per-uid egress rules
# ----------------------------------------------------------------------------------------------

METADATA_V4 = ("169.254.169.254/32", "169.254.0.0/16", "168.63.129.16/32", "100.100.100.200/32")
METADATA_V6 = ("fd00:ec2::254/128", "fe80::/10")


def _uid_token(uid: Union[int, str]) -> str:
    if isinstance(uid, bool):
        raise JailSpecError(["uid must be a positive integer"])
    if isinstance(uid, int) and uid > 0:
        return str(uid)
    if uid == UID_VAR:
        return UID_VAR
    raise JailSpecError(["uid must be a positive integer (root's rules would fence the whole host) or %s" % UID_VAR])


def _chain(uid: Union[int, str]) -> str:
    return "WARDEN_" + _uid_token(uid).replace("$", "")


def _ports(ports: Iterable[int]) -> List[int]:
    out = sorted(set(ports))
    for p in out:
        if not isinstance(p, int) or isinstance(p, bool) or not 1 <= p <= 65535:
            raise JailSpecError(["loopback port %r is invalid" % (p,)])
    return out


def uid_egress_rules(uid: Union[int, str], allowed_loopback_ports: Iterable[int] = (), *, allow_ipv6_loopback: bool = False) -> List[str]:
    """Shell lines (to run as root) fencing everything the given uid sends out.

    A dedicated chain per uid, entered from OUTPUT by an owner match inserted at position 1: explicit REJECTs for the cloud
    metadata addresses and link-local ranges, ACCEPT only TCP to 127.0.0.1 on the listed ports (IPv6 loopback only when
    ``allow_ipv6_loopback``), then REJECT for everything else, for both iptables and ip6tables.  Idempotent: re-running
    flushes the chain and does not duplicate the jump.  ``uid`` must be positive (or the literal ``$AGENT_UID``).
    """
    token = _uid_token(uid)
    chain = _chain(uid)
    ports = _ports(allowed_loopback_ports)
    lines: List[str] = []
    for tool, v6 in (("iptables", False), ("ip6tables", True)):
        lines.append("%s -w -N %s 2>/dev/null || %s -w -F %s" % (tool, chain, tool, chain))
        for dst in (METADATA_V6 if v6 else METADATA_V4):
            lines.append("%s -w -A %s -d %s -j REJECT" % (tool, chain, dst))
        if v6:
            if allow_ipv6_loopback:
                for p in ports:
                    lines.append("%s -w -A %s -p tcp -d ::1/128 --dport %d -j ACCEPT" % (tool, chain, p))
        else:
            for p in ports:
                lines.append("%s -w -A %s -p tcp -d 127.0.0.1/32 --dport %d -j ACCEPT" % (tool, chain, p))
        lines.append("%s -w -A %s -j REJECT" % (tool, chain))
        jump = "-m owner --uid-owner %s -j %s" % (token, chain)
        lines.append("%s -w -C OUTPUT %s 2>/dev/null || %s -w -I OUTPUT 1 %s" % (tool, jump, tool, jump))
    return lines


def uid_egress_teardown(uid: Union[int, str]) -> List[str]:
    """Shell lines removing what ``uid_egress_rules`` installed (jump, chain contents, chain); safe to run twice."""
    token = _uid_token(uid)
    chain = _chain(uid)
    lines: List[str] = []
    for tool in ("iptables", "ip6tables"):
        lines.append("while %s -w -D OUTPUT -m owner --uid-owner %s -j %s 2>/dev/null; do :; done" % (tool, token, chain))
        lines.append("%s -w -F %s 2>/dev/null || true" % (tool, chain))
        lines.append("%s -w -X %s 2>/dev/null || true" % (tool, chain))
    return lines


# ----------------------------------------------------------------------------------------------
# agent user
# ----------------------------------------------------------------------------------------------

FORBIDDEN_GROUPS: Tuple[str, ...] = ("sudo", "admin", "wheel", "docker", "adm", "root", "lxd", "disk", "shadow", "systemd-journal")


def agent_user_script(
    user: str,
    workspace: str,
    *,
    runner_user: str = "runner",
    runner_home: str = "/home/runner",
    harden_runner_home: bool = True,
    hidepid: bool = True,
) -> str:
    """Bash text (run as root) that prepares an unprivileged agent identity; it exits non-zero if any guarantee is missing.

    Creates ``user`` (system account, locked password, no login shell, private 0700 home) if absent; refuses a workspace under
    ``runner_home``; closes ``runner_home`` to others (``chmod o-rwx``) so the agent cannot read the runner's files; makes sure the
    agent is in none of the privileged groups and that ``sudo -l -U user`` reports nothing allowed; remounts /proc with
    ``hidepid=2`` (other users' /proc/<pid>/environ become invisible) and verifies it; creates the workspace owned by the agent
    with mode 0700; finally exports ``AGENT_UID`` for ``uid_egress_rules("$AGENT_UID", ...)``.
    """
    if not _USER_RE.match(user or "") or user in ("root", runner_user):
        raise JailSpecError(["agent user %r must be a plain lowercase account that is neither root nor the runner user" % (user,)])
    if not _USER_RE.match(runner_user or ""):
        raise JailSpecError(["runner_user %r is not a plain account name" % (runner_user,)])
    ws = _clean_abs(workspace)
    rh = _clean_abs(runner_home)
    if ws is None or ws == "/" or rh is None or rh == "/":
        raise JailSpecError(["workspace and runner_home must be clean absolute paths other than /"])
    if _under(ws, [rh]) or _under(rh, [ws]):
        raise JailSpecError(["workspace %s must not be inside (or contain) the runner home %s, which is closed to the agent" % (ws, rh)])
    if _under(ws, ["/proc", "/sys", "/dev", "/etc", "/usr", "/bin", "/lib", "/boot", "/root"]):
        raise JailSpecError(["workspace %s is under a system directory" % ws])
    q = shlex.quote
    groups = " ".join(FORBIDDEN_GROUPS)
    lines = [
        "#!/usr/bin/env bash",
        "# Generated by warden.jail.agent_user_script; run as root. Fails closed: any unmet guarantee exits non-zero.",
        "set -euo pipefail",
        "umask 022",
        "AGENT_USER=%s" % q(user),
        "AGENT_WS=%s" % q(ws),
        "RUNNER_HOME=%s" % q(rh),
        "fail() { echo \"warden-jail: $*\" >&2; exit 1; }",
        '[ "$(id -u)" = "0" ] || fail "must run as root"',
        'if ! id -u "$AGENT_USER" >/dev/null 2>&1; then',
        '  useradd --system --user-group --create-home --home-dir "/home/$AGENT_USER" --shell /usr/sbin/nologin "$AGENT_USER"',
        "fi",
        'passwd -l "$AGENT_USER" >/dev/null 2>&1 || true',
        'chmod 0700 "/home/$AGENT_USER"',
        'AGENT_UID="$(id -u "$AGENT_USER")"',
        '[ "$AGENT_UID" != "0" ] || fail "agent resolved to uid 0"',
    ]
    if harden_runner_home:
        lines.append('chmod o-rwx "$RUNNER_HOME"')
    lines += [
        "for g in %s; do" % groups,
        '  if getent group "$g" >/dev/null 2>&1; then',
        '    gpasswd -d "$AGENT_USER" "$g" >/dev/null 2>&1 || true',
        '    if id -nG "$AGENT_USER" | tr " " "\\n" | grep -qx "$g"; then fail "agent is still in group $g"; fi',
        "  fi",
        "done",
        'rm -f "/etc/sudoers.d/90-warden-$AGENT_USER"',
        'SUDO_OUT="$(sudo -n -l -U "$AGENT_USER" 2>&1 || true)"',
        'case "$SUDO_OUT" in',
        '  *"not allowed to run sudo"*) ;;',
        '  *) fail "agent may use sudo: $SUDO_OUT" ;;',
        "esac",
    ]
    if hidepid:
        lines += [
            "if ! grep -qE '^proc /proc proc .*hidepid=(2|invisible)' /proc/mounts; then",
            "  mount -o remount,hidepid=2 /proc || fail \"could not remount /proc with hidepid=2\"",
            "fi",
            "grep -qE '^proc /proc proc .*hidepid=(2|invisible)' /proc/mounts || fail \"/proc is not mounted with hidepid=2\"",
        ]
    lines += [
        'install -d -o "$AGENT_USER" -g "$AGENT_USER" -m 0700 "$AGENT_WS"',
        'chown -R -h "$AGENT_USER:$AGENT_USER" "$AGENT_WS"',
        'echo "warden-jail: agent $AGENT_USER uid=$AGENT_UID workspace=$AGENT_WS ready"',
        "export AGENT_UID",
    ]
    return "\n".join(lines) + "\n"


def setup_script(spec: JailSpec, *, runner_user: str = "runner", runner_home: str = "/home/runner") -> str:
    """User preparation followed by the egress rules for ``spec`` (needs ``spec.user``); returns bash text."""
    if not spec.user:
        raise JailSpecError(["setup_script needs spec.user"])
    _raise_if_bad(spec)
    body = agent_user_script(spec.user, spec.workspace, runner_user=runner_user, runner_home=runner_home)
    if spec.network:
        body += "\n".join(uid_egress_rules(UID_VAR, spec.allowed_loopback_ports)) + "\n"
    return body


def run_as_argv(user: str, argv: Sequence[str], env: Optional[Mapping[str, str]] = None) -> List[str]:
    """``sudo -n -u user env -i K=V ... argv``: the command runs as ``user`` with exactly ``env`` as its environment."""
    if not _USER_RE.match(user or "") or user == "root":
        raise JailSpecError(["run_as user %r must be a plain lowercase non-root account" % (user,)])
    if not argv or not all(isinstance(a, str) and "\x00" not in a for a in argv):
        raise JailSpecError(["argv must be a non-empty list of strings without NUL"])
    if argv[0].startswith("-") or "=" in argv[0]:
        raise JailSpecError(["argv[0] %r would be parsed by env(1) as an option or assignment" % (argv[0],)])
    pairs: List[str] = []
    for k, v in (env or {}).items():
        if not isinstance(k, str) or not _ENV_NAME_RE.match(k) or not isinstance(v, str) or "\x00" in v:
            raise JailSpecError(["environment variable %r is invalid" % (k,)])
        pairs.append("%s=%s" % (k, v))
    return ["sudo", "-n", "-u", user, "env", "-i"] + sorted(pairs) + list(argv)


def run_as_command(user: str, argv: Sequence[str], env: Optional[Mapping[str, str]] = None) -> str:
    """``run_as_argv`` rendered as one shell-quoted command line (shlex), for log lines and ``run:`` steps."""
    return " ".join(shlex.quote(a) for a in run_as_argv(user, argv, env))


def launch_argv(spec: JailSpec) -> List[str]:
    """The full launch: bubblewrap, run as ``spec.user`` (with an empty environment) when a user is set."""
    if spec.user:
        return run_as_argv(spec.user, bwrap_argv(spec, env_i=False), env={})
    return bwrap_argv(spec)


def describe(spec: JailSpec) -> str:
    """Audit-log text: what the jail grants, with env NAMES only and a digest of the exact launch argv."""
    problems = jail_problems(spec)
    lines = [
        "jail: %s" % ("INVALID" if problems else "valid"),
        "  workspace (only writable path): %s" % spec.workspace,
        "  user: %s uid: %s" % (spec.user or "(current user)", spec.uid if spec.uid is not None else "(unset)"),
        "  network: %s" % ("shared namespace, fenced by uid rules" if spec.network and spec.uid else
                           ("shared namespace, UNFENCED" if spec.network else "none (own namespace)")),
        "  loopback ports allowed: %s" % (", ".join(str(p) for p in sorted(spec.allowed_loopback_ports)) or "none"),
        "  read-only binds: %s" % ", ".join(list(spec.ro_binds) + list(spec.tool_binds)),
        "  /etc files: %s" % (", ".join(spec.etc_binds) or "none"),
        "  extra writable binds: %s" % (", ".join(spec.channel_binds) or "none"),
        "  PATH: %s" % ":".join(spec.path_dirs),
        "  env names: %s" % (", ".join(sorted(spec.env)) or "(none besides PATH, HOME, TMPDIR)"),
        "  secret-ok env: %s" % (", ".join(sorted(spec.secret_ok)) or "none"),
        "  command: %s (+%d args)" % (spec.command[0] if spec.command else "(empty)", max(0, len(spec.command) - 1)),
    ]
    for p in problems:
        lines.append("  PROBLEM: %s" % p)
    if not problems:
        digest = hashlib.sha256("\0".join(launch_argv(spec)).encode("utf-8")).hexdigest()
        lines.append("  launch argv sha256: %s" % digest)
    return "\n".join(lines) + "\n"

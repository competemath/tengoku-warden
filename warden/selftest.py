"""Fail-closed escape-vector battery, run as the agent identity inside the jail every time an agent launches.

``Probe(name, why, run)`` tries one escape (write to /etc, read the host canary, read the bridge's /proc environ, reach a
TEST-NET address, connect to the Docker socket, read ~/.ssh, find a committed CLAUDE.md, write GITHUB_ENV, ...) and returns a
``Result`` whose status is ``denied`` (the escape failed: good), ``allowed`` (it worked: bad), ``na`` (cannot apply on this
platform) or ``error`` (the probe could not run or was not configured).  ``run_battery`` collects them into a JSON-able report;
the launch is allowed only when every probe is ``denied``.  ``na`` passes unless ``--require-linux`` is given; ``error`` never
passes (an unconfigured probe is an error unless ``--allow-unconfigured`` says so, and the report records that).

Credit: Tau Ceti Project, TauCeti ``pr-build.yml`` and ``scripts/sandbox-build.sh`` (report ``report-main-roadmap.md`` feature B4):
a nine-probe self-test with host canaries (command runs, no write to /etc or /, host canary directory and /dev/shm canary
unreadable, no network, no nested user namespace, user-namespace inode differs, PID 1 environment empty) that aborts the job if any
probe says the sandbox is not enforcing; findings F-21 (PID 1 environment leaked the launcher's secrets) and #3720 (a job could plant
a binary on PATH or write GITHUB_PATH/GITHUB_ENV before receiving a secret); and the outside reports TauCeti #1241 (the self-test is
weaker than it reads) and #1242 (no AF_UNIX guard, UDP "offline" unenforced).  TauCetiWorker has only a manual one-vector egress script
that CI skips and a preflight that proves presence, not confinement (report ``report-worker-claims.md`` items 1.5, 1.6), and its host
agents start in a checkout whose own CLAUDE.md, hooks or ``.codex`` configuration load into a permission-bypassed agent (item 13).

What we do differently: more than thirty probes, run as the agent's own identity inside the jail on every launch (not a build-time
check of a different process), including vectors Tau Ceti lists as open: AF_UNIX sockets (Docker, ssh-agent), IPv6, DNS, the
metadata address, loopback ports other than the allowed ones (tested with a listener the probe creates itself, so the answer does
not depend on what happens to be running), credential files of every home it can see, committed agent configuration, git
credentials in ``.git/config``, GITHUB_ENV/GITHUB_PATH/GITHUB_OUTPUT, writable PATH entries and writable binaries.  A probe that
cannot decide fails the launch; a connection attempt that times out counts as NOT denied (packets left; only an immediate local
refusal proves the fence), unless the operator passes ``--timeout-is-denied``.  Probes never print file contents or secret values.

Safety: probes are read-only except the optional create-and-delete write attempts (``active_writes``, on for the CLI, off by
default for library use) which create one randomly named empty file and remove it at once, and the optional
ptrace probe, which uses PTRACE_SEIZE and detaches immediately.  Nothing runs sudo with an effect (``sudo -n true``).  Python 3.9.
"""
from __future__ import annotations

import argparse
import errno
import glob
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

DENIED = "denied"
ALLOWED = "allowed"
NA = "na"
ERROR = "error"
STATUSES = (DENIED, ALLOWED, NA, ERROR)


@dataclass(frozen=True)
class Result:
    """Outcome of one probe.  ``detail`` never contains secret values or file contents."""

    status: str
    detail: str = ""
    unconfigured: bool = False

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError("bad probe status %r" % (self.status,))


def _denied(detail: str = "") -> Result:
    return Result(DENIED, detail)


def _allowed(detail: str = "") -> Result:
    return Result(ALLOWED, detail)


def _unconfigured(what: str) -> Result:
    return Result(ERROR, "not configured: " + what, unconfigured=True)


@dataclass
class Context:
    """Everything a probe may need; all fields optional, unconfigured probes report ``error``."""

    canary_files: Tuple[str, ...] = ()
    bridge_pid: Optional[int] = None
    egress_canary: Optional[str] = None  # host:port reachable from outside the jail
    allowed_ports: Tuple[int, ...] = ()  # loopback ports the jail is meant to reach
    dns_canary: str = "example.com"
    dns_proxy_addrs: Tuple[str, ...] = ()
    workspace: str = ""  # default: the current directory
    home_dirs: Tuple[str, ...] = ()  # extra home directories to inspect (the runner's, say)
    allowed_env_names: Tuple[str, ...] = ()  # secret-looking variables the agent is meant to have
    allowed_agent_files: Mapping[str, Optional[str]] = field(default_factory=dict)  # path -> sha256 or None
    allowed_readable: Tuple[str, ...] = ()  # credential-looking paths the agent is meant to read
    writable_ok: Tuple[str, ...] = ("/tmp", "/var/tmp", "/dev/shm", "/dev")
    github_files: Tuple[str, ...] = ()
    binaries: Tuple[str, ...] = ()
    host_userns: Optional[str] = None
    expect_uid: Optional[int] = None
    active_writes: bool = False
    timeout_is_denied: bool = False
    connect_timeout: float = 3.0
    dns_timeout: float = 5.0
    ipv6_target: Tuple[str, int] = ("2606:4700:4700::1111", 443)
    env: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))
    proc_root: str = "/proc"
    system_homes: bool = True  # also inspect the account's own home and every directory under /home, /Users and /root
    connector: Optional[Callable[[int, Any, float], None]] = None  # test hook: connector(family, address, timeout)

    def ws(self) -> str:
        return os.path.realpath(self.workspace or os.getcwd())

    def homes(self) -> List[str]:
        """Home directories this identity can see: its own, $HOME, extras, and every directory under /home and /Users."""
        found: List[str] = []

        def add(p: Optional[str]) -> None:
            if p and os.path.isdir(p):
                r = os.path.realpath(p)
                if r not in found:
                    found.append(r)

        if self.system_homes:
            try:
                import pwd

                add(pwd.getpwuid(os.geteuid()).pw_dir)
            except (ImportError, KeyError, AttributeError):
                pass
        add(self.env.get("HOME"))
        for h in self.home_dirs:
            add(h)
        if self.system_homes:
            for base in ("/home", "/Users"):
                try:
                    for name in sorted(os.listdir(base)):
                        if name not in ("Shared", "Guest"):
                            add(os.path.join(base, name))
                except OSError:
                    pass
            add("/root")
        return found


@dataclass(frozen=True)
class Probe:
    name: str
    why: str
    run: Callable[[Context], Result]
    needs_linux: bool = False
    category: str = ""


# ----------------------------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------------------------

_DENY_ERRNOS = {
    errno.ECONNREFUSED, errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EPERM, errno.EACCES, errno.EADDRNOTAVAIL,
    errno.EAFNOSUPPORT, errno.ENETDOWN, errno.ECONNRESET, errno.EPROTONOSUPPORT, errno.ENOENT, errno.ENOTDIR, errno.EROFS,
    errno.ENODEV, errno.ESRCH, errno.EISDIR,
}


def _errname(exc: BaseException) -> str:
    code = getattr(exc, "errno", None)
    return errno.errorcode.get(code, str(code)) if code else type(exc).__name__


def _is_inside(path: str, roots: Iterable[str]) -> bool:
    return any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots)


def classify_connect_error(exc: BaseException, timeout_is_denied: bool = False) -> Result:
    """Map a failed connect to a status: immediate local refusals prove the fence; a timeout means packets left."""
    if isinstance(exc, socket.gaierror):
        return _denied("name resolution failed")
    if isinstance(exc, (socket.timeout, TimeoutError)) or getattr(exc, "errno", None) == errno.ETIMEDOUT:
        if timeout_is_denied:
            return _denied("timed out (accepted as denied by --timeout-is-denied)")
        return _allowed("timed out: packets left the sandbox network path; not provably blocked")
    code = getattr(exc, "errno", None)
    if code in _DENY_ERRNOS:
        return _denied(_errname(exc))
    return Result(ERROR, "unexpected %s" % _errname(exc))


def _default_connect(family: int, address: Any, timeout: float) -> None:
    s = socket.socket(family, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect(address)
    finally:
        s.close()


def tcp_probe(ctx: Context, host: str, port: int, family: int = socket.AF_INET) -> Result:
    """Try a TCP connect; a completed connection is ``allowed``."""
    connector = ctx.connector or _default_connect
    try:
        if family == socket.AF_INET6 and not socket.has_ipv6:
            return _denied("no IPv6 support in this interpreter or kernel")
        if ctx.connector is None and not _is_ip_literal(host):
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            targets = [(i[0], i[4]) for i in infos[:3]]
        elif family == socket.AF_INET6:
            targets = [(family, (host, port, 0, 0))]
        else:
            targets = [(family, (host, port))]
        last: Optional[Result] = None
        for fam, addr in targets:
            try:
                connector(fam, addr, ctx.connect_timeout)
                return _allowed("connected to %s:%d" % (host, port))
            except OSError as exc:
                r = classify_connect_error(exc, ctx.timeout_is_denied)
                if r.status != DENIED:
                    return r
                last = r
        return last or _denied("no address to try")
    except OSError as exc:
        return classify_connect_error(exc, ctx.timeout_is_denied)


def _is_ip_literal(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _readable(path: str) -> bool:
    try:
        if os.path.isdir(path):
            os.listdir(path)
            return True
        with open(path, "rb") as fh:
            fh.read(1)
        return True
    except OSError:
        return False


def _sha256(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


# ----------------------------------------------------------------------------------------------
# probes: filesystem
# ----------------------------------------------------------------------------------------------


def _write_attempt(directory: str, ctx: Context) -> Optional[str]:
    """None if the directory is not writable, else a description of how it was writable."""
    if not os.path.isdir(directory):
        return None
    if not ctx.active_writes:
        return "os.access reports writable" if os.access(directory, os.W_OK) else None
    path = os.path.join(directory, ".warden-selftest-" + secrets.token_hex(6))
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError:
        return None
    os.close(fd)
    try:
        os.unlink(path)
    except OSError:
        pass
    return "created and removed a file"


def probe_write_etc(ctx: Context) -> Result:
    how = _write_attempt("/etc", ctx)
    return _allowed("/etc writable: " + how) if how else _denied("/etc not writable")


def probe_write_root(ctx: Context) -> Result:
    how = _write_attempt("/", ctx)
    return _allowed("/ writable: " + how) if how else _denied("/ not writable")


def probe_write_outside_workspace(ctx: Context) -> Result:
    ws = ctx.ws()
    candidates = [os.path.dirname(ws), "/usr/local", "/opt", "/home", "/root", "/var", "/srv", "/usr"] + list(ctx.homes())
    ok_roots = [os.path.realpath(p) for p in ctx.writable_ok] + [ws]
    bad: List[str] = []
    for c in candidates:
        r = os.path.realpath(c)
        if r in bad or _is_inside(r, ok_roots) or r == "/":
            continue
        if _write_attempt(r, ctx):
            bad.append(r)
    return _allowed("writable outside the workspace: " + ", ".join(bad)) if bad else _denied("nothing outside the workspace is writable")


def probe_host_canary(ctx: Context) -> Result:
    if not ctx.canary_files:
        return _unconfigured("pass --canary-file (a host file placed outside the jail)")
    readable = [p for p in ctx.canary_files if _readable(p)]
    return _allowed("canary readable: " + ", ".join(readable)) if readable else _denied("no canary file is readable")


# ----------------------------------------------------------------------------------------------
# probes: processes and /proc
# ----------------------------------------------------------------------------------------------


def _proc_environ_readable(ctx: Context, pid: int) -> bool:
    try:
        with open(os.path.join(ctx.proc_root, str(pid), "environ"), "rb") as fh:
            fh.read(1)
        return True
    except OSError:
        return False


def probe_bridge_environ(ctx: Context) -> Result:
    if ctx.bridge_pid is None:
        return _unconfigured("pass --bridge-pid (the process whose secrets must stay unreadable)")
    if _proc_environ_readable(ctx, ctx.bridge_pid):
        return _allowed("/proc/%d/environ is readable" % ctx.bridge_pid)
    return _denied("/proc/%d/environ not readable" % ctx.bridge_pid)


def probe_parent_environ(ctx: Context) -> Result:
    ppid = os.getppid()
    if ppid <= 0:
        return _denied("parent is outside this PID namespace")
    if _proc_environ_readable(ctx, ppid):
        return _allowed("/proc/%d/environ (parent) is readable" % ppid)
    return _denied("parent environ not readable")


def probe_pid1_environ(ctx: Context) -> Result:
    path = os.path.join(ctx.proc_root, "1", "environ")
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return _denied("PID 1 environ not readable")
    if not data:
        return _denied("PID 1 environment is empty")
    return _allowed("PID 1 environment is readable and holds %d bytes" % len(data))


def probe_env_secrets(ctx: Context) -> Result:
    from warden import envscrub

    names = envscrub.secret_names_in(ctx.env, ctx.allowed_env_names)
    return _allowed("secret-looking variables in the environment: " + ", ".join(names)) if names else _denied("no secret-looking variables")


def probe_sudo(ctx: Context) -> Result:
    try:
        r = subprocess.run(["sudo", "-n", "true"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    except FileNotFoundError:
        return _denied("sudo is not installed")
    except subprocess.TimeoutExpired:
        return Result(ERROR, "sudo -n true timed out")
    except OSError as exc:
        return _denied("cannot run sudo: " + _errname(exc))
    return _allowed("sudo -n true succeeded") if r.returncode == 0 else _denied("sudo -n true failed (exit %d)" % r.returncode)


def _group_names() -> List[str]:
    import grp

    gids = set(os.getgroups()) | {os.getegid()}
    names = []
    for gid in gids:
        try:
            names.append(grp.getgrgid(gid).gr_name)
        except KeyError:
            names.append(str(gid))
    return sorted(names)


_PRIVILEGED_GROUPS = ("sudo", "admin", "wheel", "docker", "adm", "root", "lxd", "disk", "shadow", "systemd-journal")


def probe_privileged_groups(ctx: Context) -> Result:
    try:
        names = _group_names()
    except ImportError:
        return Result(NA, "grp module unavailable")
    bad = [n for n in names if n in _PRIVILEGED_GROUPS]
    return _allowed("member of privileged groups: " + ", ".join(bad)) if bad else _denied("no privileged group membership")


def probe_not_root(ctx: Context) -> Result:
    if not hasattr(os, "geteuid"):
        return Result(NA, "no uid concept on this platform")
    return _allowed("effective uid is 0") if os.geteuid() == 0 else _denied("not root")


def probe_running_as_agent(ctx: Context) -> Result:
    if ctx.expect_uid is None or not hasattr(os, "geteuid"):
        return Result(NA, "no expected agent uid given (--expect-uid)")
    if os.geteuid() != ctx.expect_uid:
        return _allowed("running as uid %d, expected the agent uid %d: these results describe the wrong identity" % (os.geteuid(), ctx.expect_uid))
    return _denied("running as the expected agent uid")


def probe_no_caps(ctx: Context) -> Result:
    try:
        with open(os.path.join(ctx.proc_root, "self", "status"), "r") as fh:
            text = fh.read()
    except OSError as exc:
        return Result(ERROR, "cannot read /proc/self/status: " + _errname(exc))
    m = re.search(r"^CapEff:\s*([0-9a-fA-F]+)", text, re.M)
    if not m:
        return Result(ERROR, "no CapEff line")
    return _denied("no effective capabilities") if int(m.group(1), 16) == 0 else _allowed("effective capabilities: 0x" + m.group(1))


_PTRACE_SEIZE = 0x4206
_PTRACE_DETACH = 17


def probe_ptrace(ctx: Context) -> Result:
    try:
        import ctypes
    except ImportError:
        return Result(NA, "ctypes unavailable")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.ptrace.restype = ctypes.c_long
        libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
    except (OSError, AttributeError):
        return Result(NA, "libc ptrace unavailable")
    pids = [p for p in (os.getppid(), ctx.bridge_pid) if p and p > 1]
    if not pids:
        return _denied("no visible parent or bridge process to attach to")
    hit: List[str] = []
    for pid in pids:
        ctypes.set_errno(0)
        if libc.ptrace(_PTRACE_SEIZE, pid, None, None) == 0:
            libc.ptrace(_PTRACE_DETACH, pid, None, None)
            hit.append(str(pid))
    return _allowed("PTRACE_SEIZE succeeded on pid " + ", ".join(hit)) if hit else _denied("ptrace attach refused")


def probe_nested_userns(ctx: Context) -> Result:
    code = (
        "import ctypes,sys\n"
        "try:\n"
        "    libc=ctypes.CDLL(None,use_errno=True)\n"
        "except Exception:\n"
        "    sys.exit(3)\n"
        "sys.exit(0 if libc.unshare(0x10000000)==0 else 1)\n"
    )
    try:
        r = subprocess.run([sys.executable, "-I", "-c", code], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Result(ERROR, "cannot run the unshare check: " + type(exc).__name__)
    if r.returncode == 0:
        return _allowed("unshare(CLONE_NEWUSER) succeeded")
    if r.returncode == 1:
        return _denied("nested user namespace refused")
    if r.returncode == 3:
        return Result(NA, "ctypes/libc unavailable")
    return Result(ERROR, "unexpected exit code %d" % r.returncode)


def probe_userns_differs(ctx: Context) -> Result:
    if ctx.host_userns is None:
        return _unconfigured("pass --host-userns (the host's `readlink /proc/self/ns/user`)")
    try:
        mine = os.readlink(os.path.join(ctx.proc_root, "self", "ns", "user"))
    except OSError as exc:
        return Result(ERROR, "cannot read own user namespace: " + _errname(exc))
    return _allowed("same user namespace as the host") if mine == ctx.host_userns else _denied("different user namespace from the host")


# ----------------------------------------------------------------------------------------------
# probes: network
# ----------------------------------------------------------------------------------------------


def probe_tcp_testnet(ctx: Context) -> Result:
    return tcp_probe(ctx, "192.0.2.1", 80)


def probe_tcp_canary(ctx: Context) -> Result:
    if not ctx.egress_canary:
        return _unconfigured("pass --egress-canary host:port (a listener outside the jail)")
    host, _, port = ctx.egress_canary.rpartition(":")
    if not host or not port.isdigit():
        return Result(ERROR, "egress canary must be host:port")
    return tcp_probe(ctx, host.strip("[]"), int(port), socket.AF_INET6 if ":" in host else socket.AF_INET)


def probe_loopback_other_ports(ctx: Context) -> Result:
    srv: Optional[socket.socket] = None
    port = 0
    try:
        for _ in range(8):
            cand = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                cand.bind(("127.0.0.1", 0))
            except OSError as exc:
                cand.close()
                return _denied("cannot create a loopback listener: " + _errname(exc))
            if cand.getsockname()[1] not in ctx.allowed_ports:
                srv = cand
                break
            cand.close()
        if srv is None:
            return Result(ERROR, "could not find a loopback port outside the allowed set")
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            _default_connect(socket.AF_INET, ("127.0.0.1", port), min(ctx.connect_timeout, 2.0))
        except OSError as exc:
            return classify_connect_error(exc, ctx.timeout_is_denied)
        return _allowed("connected to an arbitrary loopback port (%d)" % port)
    finally:
        if srv is not None:
            srv.close()


def probe_dns(ctx: Context) -> Result:
    box: Dict[str, Any] = {}

    def work() -> None:
        try:
            box["addrs"] = socket.getaddrinfo(ctx.dns_canary, 443, type=socket.SOCK_STREAM)
        except Exception as exc:  # noqa: BLE001
            box["err"] = exc

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(ctx.dns_timeout)
    if t.is_alive():
        return _denied("no answer within %.1fs" % ctx.dns_timeout)
    if "err" in box:
        return _denied("resolution failed (%s)" % type(box["err"]).__name__)
    import ipaddress

    addrs = sorted({i[4][0] for i in box["addrs"]})
    real = []
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a.split("%")[0])
        except ValueError:
            real.append(a)
            continue
        if not (ip.is_loopback or a in ctx.dns_proxy_addrs):
            real.append(a)
    if not real:
        return _denied("resolves only to loopback or the proxy (%s)" % ", ".join(addrs))
    return _allowed("%s resolved to %d outside address(es)" % (ctx.dns_canary, len(real)))


def probe_ipv6(ctx: Context) -> Result:
    host, port = ctx.ipv6_target
    return tcp_probe(ctx, host, port, socket.AF_INET6)


def probe_metadata(ctx: Context) -> Result:
    hits = []
    pending: List[Result] = []
    for host, port in (("169.254.169.254", 80), ("168.63.129.16", 80)):
        r = tcp_probe(ctx, host, port)
        if r.status == ALLOWED:
            hits.append("%s (%s)" % (host, r.detail))
        elif r.status == ERROR:
            pending.append(r)
    if hits:
        return _allowed("metadata endpoint reachable: " + "; ".join(hits))
    return pending[0] if pending else _denied("metadata addresses unreachable")


def _unix_socket_candidates(ctx: Context) -> List[str]:
    paths = [
        "/var/run/docker.sock", "/run/docker.sock", "/run/podman/podman.sock", "/var/run/podman/podman.sock",
        "/run/containerd/containerd.sock", "/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket",
    ]
    for home in ctx.homes():
        paths += [os.path.join(home, ".docker", "run", "docker.sock"), os.path.join(home, ".gnupg", "S.gpg-agent")]
    sock = ctx.env.get("SSH_AUTH_SOCK")
    if sock:
        paths.append(sock)
    for pattern in ("/tmp/ssh-*/agent.*", "/run/user/*/bus", "/run/user/*/keyring/*", "/run/user/*/gnupg/S.*", "/run/user/*/snap.*/*.sock"):
        paths += glob.glob(pattern)
    seen: List[str] = []
    for p in paths:
        if p not in seen:
            seen.append(p)
    return seen


def probe_unix_sockets(ctx: Context) -> Result:
    if not hasattr(socket, "AF_UNIX"):
        return Result(NA, "no AF_UNIX on this platform")
    hit: List[str] = []
    for path in _unix_socket_candidates(ctx):
        if not os.path.exists(path) and not os.path.islink(path):
            continue
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.settimeout(2)
            s.connect(path)
            hit.append(path)
        except OSError:
            pass
        finally:
            s.close()
    return _allowed("connected to unix socket(s): " + ", ".join(hit)) if hit else _denied("no well-known unix socket accepts a connection")


def probe_docker_socket(ctx: Context) -> Result:
    hit = []
    for path in ("/var/run/docker.sock", "/run/docker.sock", "/run/podman/podman.sock", "/var/run/podman/podman.sock", "/run/containerd/containerd.sock"):
        if os.path.exists(path) and os.access(path, os.R_OK | os.W_OK):
            hit.append(path)
    for home in ctx.homes():
        p = os.path.join(home, ".docker", "run", "docker.sock")
        if os.path.exists(p) and os.access(p, os.R_OK | os.W_OK):
            hit.append(p)
    return _allowed("container socket accessible: " + ", ".join(hit)) if hit else _denied("no container socket is accessible")


# ----------------------------------------------------------------------------------------------
# probes: credentials and configuration
# ----------------------------------------------------------------------------------------------


def _credential_probe(ctx: Context, rel_paths: Sequence[str]) -> Result:
    allowed = [os.path.realpath(p) for p in ctx.allowed_readable]
    hit: List[str] = []
    for home in ctx.homes():
        for rel in rel_paths:
            p = os.path.join(home, rel)
            if (os.path.exists(p) or os.path.islink(p)) and _readable(p):
                real = os.path.realpath(p)
                if not _is_inside(real, allowed):
                    hit.append(p)
    return _allowed("readable credential path(s): " + ", ".join(hit)) if hit else _denied("none of %s readable" % ", ".join(rel_paths))


def probe_cred_ssh(ctx: Context) -> Result:
    return _credential_probe(ctx, [".ssh"])


def probe_cred_gh(ctx: Context) -> Result:
    return _credential_probe(ctx, [".config/gh", ".config/gh/hosts.yml"])


def probe_cred_git(ctx: Context) -> Result:
    return _credential_probe(ctx, [".git-credentials", ".config/git/credentials"])


def probe_cred_claude(ctx: Context) -> Result:
    return _credential_probe(ctx, [".claude/.credentials.json", ".claude.json", ".config/claude", ".config/claude-code", ".config/anthropic"])


def probe_cred_misc(ctx: Context) -> Result:
    return _credential_probe(
        ctx,
        [".aws/credentials", ".aws/config", ".netrc", ".npmrc", ".pypirc", ".docker/config.json", ".config/gcloud", ".azure",
         ".kube/config", ".gnupg", ".codex/auth.json", ".config/openai", ".cargo/credentials.toml"],
    )


_GIT_SECRET_LINE = re.compile(r"(?i)extraheader|authorization\s*[:=]|x-access-token|://[^/\s:@]+:[^/\s@]+@")


def _git_config_files(ctx: Context) -> List[str]:
    files: List[str] = []
    d = ctx.ws()
    while True:
        g = os.path.join(d, ".git")
        if os.path.isdir(g):
            files.append(os.path.join(g, "config"))
        elif os.path.isfile(g):
            try:
                with open(g, "r", errors="replace") as fh:
                    first = fh.readline().strip()
            except OSError:
                first = ""
            if first.startswith("gitdir:"):
                gd = first.split(":", 1)[1].strip()
                gd = gd if os.path.isabs(gd) else os.path.join(d, gd)
                files.append(os.path.join(gd, "config"))
                for _ in range(1):
                    cd = os.path.join(gd, "commondir")
                    try:
                        with open(cd, "r") as fh:
                            files.append(os.path.join(os.path.normpath(os.path.join(gd, fh.read().strip())), "config"))
                    except OSError:
                        pass
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    for home in ctx.homes():
        files += [os.path.join(home, ".gitconfig"), os.path.join(home, ".config", "git", "config")]
    files.append("/etc/gitconfig")
    return files


def probe_git_tokens(ctx: Context) -> Result:
    from warden import envscrub

    hits: List[str] = []
    for path in _git_config_files(ctx):
        try:
            with open(path, "r", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        for n, line in enumerate(lines, 1):
            if _GIT_SECRET_LINE.search(line) or any(envscrub.looks_secret_value(tok) for tok in re.split(r"[\s=]+", line)):
                hits.append("%s:%d" % (path, n))
                break
    return _allowed("credential material in git configuration: " + ", ".join(hits)) if hits else _denied("no credentials in git configuration")


_AGENT_CONFIG_IN_WORKSPACE = (
    "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "GEMINI.md", ".mcp.json", ".claude/settings.json", ".claude/settings.local.json",
    ".claude/CLAUDE.md", ".claude/commands", ".claude/agents", ".claude/hooks", ".claude/skills", ".codex", ".cursorrules",
)
_AGENT_CONFIG_IN_PARENT = ("CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", ".claude", ".codex", ".mcp.json")
_AGENT_CONFIG_IN_HOME = (".claude/settings.json", ".claude/CLAUDE.md", ".claude/hooks", ".claude/commands", ".claude/agents", ".codex/config.toml", ".codex/AGENTS.md")


def probe_agent_config(ctx: Context) -> Result:
    ws = ctx.ws()
    allowed = {}
    for k, v in ctx.allowed_agent_files.items():
        allowed[os.path.realpath(k if os.path.isabs(k) else os.path.join(ws, k))] = v
    candidates: List[str] = [os.path.join(ws, rel) for rel in _AGENT_CONFIG_IN_WORKSPACE]
    d = os.path.dirname(ws)
    while True:
        candidates += [os.path.join(d, rel) for rel in _AGENT_CONFIG_IN_PARENT]
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    for home in ctx.homes():
        candidates += [os.path.join(home, rel) for rel in _AGENT_CONFIG_IN_HOME]
    bad: List[str] = []
    for path in candidates:
        if not (os.path.lexists(path)):
            continue
        real = os.path.realpath(path)
        want = allowed.get(real, "missing")
        if want == "missing":
            bad.append(path)
        elif want is not None and os.path.isfile(real) and _sha256(real) != want:
            bad.append(path + " (content differs from the policy's)")
    return _allowed("agent configuration the policy did not provide: " + ", ".join(sorted(set(bad)))) if bad else _denied("no unexpected agent configuration")


def probe_github_files(ctx: Context) -> Result:
    paths = list(ctx.github_files)
    for var in ("GITHUB_ENV", "GITHUB_PATH", "GITHUB_OUTPUT", "GITHUB_STATE", "GITHUB_STEP_SUMMARY"):
        v = ctx.env.get(var)
        if v and v not in paths:
            paths.append(v)
    if not paths:
        if ctx.env.get("GITHUB_ACTIONS") == "true":
            return _unconfigured("running under GitHub Actions but no workflow-command file path was passed (--github-file)")
        return Result(NA, "not running under GitHub Actions and no files given")
    writable = []
    for p in paths:
        if not os.path.exists(p):
            continue
        try:
            fd = os.open(p, os.O_WRONLY | os.O_APPEND)
        except OSError:
            continue
        os.close(fd)
        writable.append(p)
    return _allowed("workflow command file(s) writable: " + ", ".join(writable)) if writable else _denied("workflow command files not writable")


def probe_path_dirs(ctx: Context) -> Result:
    from warden import envscrub

    path = ctx.env.get("PATH")
    if path is None:
        return _denied("no PATH set")
    issues = envscrub.path_issues(path)
    writable = envscrub.writable_path_dirs(path)
    if issues or writable:
        return _allowed("; ".join(issues + ["writable PATH directory: " + w for w in sorted(set(writable))]))
    return _denied("PATH has no writable or relative entries")


def probe_binaries(ctx: Context) -> Result:
    path = ctx.env.get("PATH")
    names = list(ctx.binaries) or ["sh", "env"]
    exes = [sys.executable] if sys.executable else []
    for n in names:
        found = n if os.path.isabs(n) else shutil.which(n, path=path)
        if found:
            exes.append(found)
    bad: List[str] = []
    for exe in exes:
        real = os.path.realpath(exe)
        chain = [real]
        d = os.path.dirname(real)
        while True:
            chain.append(d)
            parent = os.path.dirname(d)
            if parent == d:
                break
            d = parent
        for p in chain:
            if os.access(p, os.W_OK):
                bad.append("%s (writable: %s)" % (exe, p))
                break
    return _allowed("binary can be replaced: " + ", ".join(bad)) if bad else _denied("binaries and their directories are not writable")


# ----------------------------------------------------------------------------------------------
# registry, battery, CLI
# ----------------------------------------------------------------------------------------------


def default_probes() -> List[Probe]:
    P = Probe
    return [
        P("write_etc", "a writable /etc lets the agent change resolvers, sudoers, certificates", probe_write_etc, category="filesystem"),
        P("write_root", "a writable / means the sandbox root was not made read-only (Tau Ceti F-21)", probe_write_root, category="filesystem"),
        P("write_outside_workspace", "only the workspace may be writable", probe_write_outside_workspace, category="filesystem"),
        P("read_host_canary", "a host file outside the jail must be invisible", probe_host_canary, category="filesystem"),
        P("read_bridge_environ", "the bridge's /proc/<pid>/environ holds its tokens", probe_bridge_environ, needs_linux=True, category="process"),
        P("read_parent_environ", "the parent's environment must not be readable", probe_parent_environ, needs_linux=True, category="process"),
        P("pid1_environ_empty", "PID 1 inherits the launcher's environment unless started under env -i (Tau Ceti F-21)", probe_pid1_environ, needs_linux=True, category="process"),
        P("env_has_no_secrets", "no secret-looking variable beyond the ones the policy grants", probe_env_secrets, category="environment"),
        P("sudo_denied", "passwordless sudo is root", probe_sudo, category="privilege"),
        P("not_root", "root inside a mis-built jail is root outside", probe_not_root, category="privilege"),
        P("privileged_groups", "docker, sudo, adm and similar groups are root equivalents", probe_privileged_groups, category="privilege"),
        P("running_as_agent", "the battery must describe the agent's identity, not the launcher's", probe_running_as_agent, category="privilege"),
        P("no_effective_caps", "effective capabilities allow mounts, ptrace and raw sockets", probe_no_caps, needs_linux=True, category="privilege"),
        P("ptrace_denied", "attaching to the parent or bridge steals its memory and secrets", probe_ptrace, needs_linux=True, category="process"),
        P("nested_userns_denied", "a nested user namespace can rearrange mounts (Tau Ceti B4 probe 7)", probe_nested_userns, needs_linux=True, category="process"),
        P("userns_differs_from_host", "same user namespace as the host means no user namespace at all (Tau Ceti B4 probe 8)", probe_userns_differs, needs_linux=True, category="process"),
        P("docker_socket_inaccessible", "a Docker socket is root on the host", probe_docker_socket, category="privilege"),
        P("unix_sockets_denied", "ssh-agent, Docker, D-Bus and gpg-agent sockets are credentials (Tau Ceti #1242)", probe_unix_sockets, category="network"),
        P("tcp_testnet_denied", "any traffic that leaves the host is exfiltration", probe_tcp_testnet, category="network"),
        P("tcp_egress_canary_denied", "a listener outside the jail must be unreachable", probe_tcp_canary, category="network"),
        P("loopback_other_ports_denied", "only the proxy's loopback port may be reachable", probe_loopback_other_ports, category="network"),
        P("dns_denied", "DNS is an exfiltration channel unless it is proxy-only", probe_dns, category="network"),
        P("ipv6_egress_denied", "IPv6 skips IPv4-only firewall rules", probe_ipv6, category="network"),
        P("metadata_endpoint_denied", "cloud metadata endpoints hand out instance credentials", probe_metadata, category="network"),
        P("cred_ssh_unreadable", "~/.ssh holds keys", probe_cred_ssh, category="credentials"),
        P("cred_gh_unreadable", "~/.config/gh holds GitHub tokens", probe_cred_gh, category="credentials"),
        P("cred_git_credentials_unreadable", "~/.git-credentials holds tokens in clear text", probe_cred_git, category="credentials"),
        P("cred_claude_unreadable", "~/.claude credentials are the operator's subscription", probe_cred_claude, category="credentials"),
        P("cred_misc_unreadable", "cloud, registry and container credentials in home directories", probe_cred_misc, category="credentials"),
        P("git_config_has_no_tokens", "actions/checkout leaves an Authorization header in .git/config (Tau Ceti #3730)", probe_git_tokens, category="credentials"),
        P("no_unexpected_agent_config", "a committed CLAUDE.md, hook or .codex loads into a permission-bypassed agent (Tau Ceti worker item 13)", probe_agent_config, category="configuration"),
        P("github_workflow_files_unwritable", "GITHUB_ENV/GITHUB_PATH/GITHUB_OUTPUT rewrite later steps (Tau Ceti #3720)", probe_github_files, category="ci"),
        P("path_has_no_writable_dir", "a writable PATH directory runs a planted binary (Tau Ceti F-21)", probe_path_dirs, category="ci"),
        P("binaries_not_writable", "a writable binary or its directory is replaced before the next step runs it", probe_binaries, category="ci"),
    ]


def evaluate(results: Sequence[Mapping[str, Any]]) -> bool:
    """True when every entry passed.  Pure."""
    return all(r["ok"] for r in results)


def run_battery(
    probes: Sequence[Probe],
    expect: Optional[Mapping[str, str]] = None,
    ctx: Optional[Context] = None,
    *,
    require_linux: bool = False,
    allow_unconfigured: bool = False,
    clock: Callable[[], float] = time.monotonic,
    platform_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Run ``probes`` and return a JSON-able report.

    ``expect`` maps probe name to the status that counts as success (default ``denied`` for all).  ``na`` counts as a pass
    unless ``require_linux`` (then it fails); ``error`` never passes, except that with ``allow_unconfigured`` a probe that
    reports it was not configured becomes ``na`` and is listed under ``unconfigured_allowed``.  A probe that raises, returns a
    non-``Result`` or is Linux-only on another platform is handled without running it (or recorded as an error).
    """
    ctx = ctx if ctx is not None else Context()
    plat = platform_name if platform_name is not None else sys.platform
    linux = plat.startswith("linux")
    expect = dict(expect or {})
    results: List[Dict[str, Any]] = []
    unconfigured: List[str] = []
    seen = set()
    for probe in probes:
        t0 = clock()
        if probe.name in seen:
            res = Result(ERROR, "duplicate probe name")
        elif probe.needs_linux and not linux:
            res = Result(NA, "requires Linux (platform is %s)" % plat)
        else:
            try:
                res = probe.run(ctx)
                if not isinstance(res, Result):
                    res = Result(ERROR, "probe returned %s, not a Result" % type(res).__name__)
            except Exception as exc:  # noqa: BLE001 - any failure to run fails the launch
                res = Result(ERROR, ("%s: %s" % (type(exc).__name__, exc))[:200])
        seen.add(probe.name)
        if res.unconfigured and allow_unconfigured:
            unconfigured.append(probe.name)
            res = Result(NA, res.detail + " (allowed by --allow-unconfigured)")
        want = expect.get(probe.name, DENIED)
        ok = res.status == want or (res.status == NA and not require_linux and want == DENIED)
        results.append(
            {
                "name": probe.name, "why": probe.why, "category": probe.category, "status": res.status, "expected": want,
                "ok": bool(ok), "detail": str(res.detail), "needs_linux": probe.needs_linux,
                "ms": int(max(0.0, clock() - t0) * 1000),
            }
        )
    counts = {s: sum(1 for r in results if r["status"] == s) for s in STATUSES}
    uid = os.geteuid() if hasattr(os, "geteuid") else None
    return {
        "ok": bool(results) and evaluate(results),
        "platform": plat,
        "linux": linux,
        "uid": uid,
        "require_linux": require_linux,
        "allow_unconfigured": allow_unconfigured,
        "unconfigured_allowed": sorted(unconfigured),
        "counts": counts,
        "failed": [r["name"] for r in results if not r["ok"]],
        "results": results,
    }


def format_report(report: Mapping[str, Any]) -> str:
    lines = []
    for r in report["results"]:
        mark = "ok  " if r["ok"] else "FAIL"
        lines.append("%s %-34s %-8s %s" % (mark, r["name"], r["status"], r["detail"]))
    c = report["counts"]
    lines.append("")
    lines.append(
        "%s: %d denied, %d allowed, %d na, %d error (platform %s)"
        % ("PASS" if report["ok"] else "FAIL: launch must not proceed", c[DENIED], c[ALLOWED], c[NA], c[ERROR], report["platform"])
    )
    return "\n".join(lines) + "\n"


def _parse_agent_file(spec: str) -> Tuple[str, Optional[str]]:
    path, sep, sha = spec.partition("=")
    if sep and not re.fullmatch(r"[0-9a-fA-F]{64}", sha):
        raise ValueError("--allow-agent-file PATH=SHA256 needs a 64-hex digest, got %r" % sha)
    return path, (sha.lower() if sep else None)


def main(argv: Optional[Sequence[str]] = None, probes: Optional[Sequence[Probe]] = None) -> int:
    """``warden selftest``.  Exit 0 all probes passed, 1 at least one probe not denied / could not run (fail closed), 2 bad input."""
    ap = argparse.ArgumentParser(prog="warden selftest", description="Escape-vector battery; run as the agent identity inside the jail.")
    ap.add_argument("--canary-file", action="append", default=[], help="host file outside the jail that must be unreadable (repeatable)")
    ap.add_argument("--bridge-pid", type=int, help="pid of the bridge whose /proc/<pid>/environ must be unreadable")
    ap.add_argument("--egress-canary", metavar="HOST:PORT", help="listener outside the jail that must be unreachable")
    ap.add_argument("--allow-port", type=int, action="append", default=[], metavar="P", help="loopback port the jail is meant to reach (repeatable)")
    ap.add_argument("--json", metavar="OUT", help="write the JSON report here")
    ap.add_argument("--list", action="store_true", help="list the probes and exit")
    ap.add_argument("--only", action="append", default=[], metavar="NAME", help="run only these probes (debugging; never for a real launch)")
    ap.add_argument("--require-linux", action="store_true", help="treat na (Linux-only probe on another OS) as failure")
    ap.add_argument("--allow-unconfigured", action="store_true", help="development only: probes lacking their inputs become na instead of error")
    ap.add_argument("--workspace", default="", help="the agent's working directory (default: cwd)")
    ap.add_argument("--home", action="append", default=[], metavar="DIR", help="extra home directory to inspect, e.g. the runner's")
    ap.add_argument("--allow-env", action="append", default=[], metavar="NAME", help="secret-looking variable the agent is meant to have")
    ap.add_argument("--allow-agent-file", action="append", default=[], metavar="PATH[=SHA256]", help="agent config file the policy provided")
    ap.add_argument("--allow-readable", action="append", default=[], metavar="PATH", help="credential-looking path the agent is meant to read")
    ap.add_argument("--github-file", action="append", default=[], metavar="PATH", help="workflow command file (GITHUB_ENV, GITHUB_PATH, GITHUB_OUTPUT) to test")
    ap.add_argument("--binary", action="append", default=[], metavar="NAME", help="binary the agent will run (default: sh, env, python)")
    ap.add_argument("--host-userns", help="the host's `readlink /proc/self/ns/user`")
    ap.add_argument("--expect-uid", type=int, help="the agent's uid; fail if the battery runs as someone else")
    ap.add_argument("--dns-canary", default="example.com")
    ap.add_argument("--timeout-is-denied", action="store_true", help="accept connect timeouts as denied (silent-drop firewalls)")
    ap.add_argument("--no-active-writes", action="store_true", help="use os.access instead of create-and-delete write attempts")
    try:
        ns = ap.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2
    plist = list(probes) if probes is not None else default_probes()
    if ns.list:
        for p in plist:
            print("%-34s %-13s %s%s" % (p.name, p.category, p.why, "  [linux]" if p.needs_linux else ""))
        return 0
    if ns.only:
        unknown = [n for n in ns.only if n not in {p.name for p in plist}]
        if unknown:
            print("error: unknown probe(s): %s" % ", ".join(unknown), file=sys.stderr)
            return 2
        plist = [p for p in plist if p.name in ns.only]
    try:
        agent_files = dict(_parse_agent_file(s) for s in ns.allow_agent_file)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if ns.egress_canary and not re.fullmatch(r"(\[[0-9a-fA-F:.]+\]|[^:\s]+):\d{1,5}", ns.egress_canary):
        print("error: --egress-canary must be HOST:PORT", file=sys.stderr)
        return 2
    ctx = Context(
        canary_files=tuple(ns.canary_file), bridge_pid=ns.bridge_pid, egress_canary=ns.egress_canary,
        allowed_ports=tuple(ns.allow_port), dns_canary=ns.dns_canary, workspace=ns.workspace, home_dirs=tuple(ns.home),
        allowed_env_names=tuple(ns.allow_env), allowed_agent_files=agent_files, allowed_readable=tuple(ns.allow_readable),
        github_files=tuple(ns.github_file), binaries=tuple(ns.binary), host_userns=ns.host_userns, expect_uid=ns.expect_uid,
        active_writes=not ns.no_active_writes, timeout_is_denied=ns.timeout_is_denied,
    )
    report = run_battery(plist, ctx=ctx, require_linux=ns.require_linux, allow_unconfigured=ns.allow_unconfigured)
    if ns.only:
        report["ok"] = False  # a partial run never authorises a launch
        report["partial"] = True
    sys.stdout.write(format_report(report))
    if ns.json:
        try:
            with open(ns.json, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2, sort_keys=True)
                fh.write("\n")
        except OSError as exc:
            print("error: cannot write %s: %s" % (ns.json, exc), file=sys.stderr)
            return 2
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())

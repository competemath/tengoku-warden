"""Egress allowlists: derive one from an audit run, render it for the workflow, and enforce it with a tiny CONNECT proxy.

Three pieces.  ``parse_audit`` turns a StepSecurity harden-runner audit (its network-events table or its suggested
``allowed-endpoints`` list) or a plain ``host:port``-per-line file into a sorted allowlist, refusing endpoints that must never be
allowlisted (cloud metadata, link-local, loopback, private ranges).  ``render_allowed_endpoints`` writes it in the form the
workflow input takes.  ``ConnectProxy`` is a stdlib, loopback-only, CONNECT-only forward proxy that tunnels to a listed
``host:port`` and answers 403 to everything else, logging every decision; the agent's only route to the outside is then
``HTTPS_PROXY=http://127.0.0.1:PORT`` with the uid egress rules from ``warden.jail`` allowing nothing but that loopback port.

Credit: Tau Ceti Project.  TauCetiWorker's Bubble sandbox reaches GitHub only through a scoped host proxy (report
``report-worker-claims.md``, items 1.2 and 1.6) and its own documentation lists the limits of that design: DNS exfiltration,
a /24 over-allowance, enforcement by iptables alone, and a one-vector egress probe that CI never runs.  The idea of building
the allowlist from a recorded audit of a real run rather than from memory is the standard harden-runner workflow; TauCeti's
workflows rely on network-less sandboxes plus trusted-phase downloads pinned by hash (B9).

What we do differently: the allowlist is data that is parsed, validated and diffable (``parse_audit``/``render``), not a list
in a workflow nobody reads again; the proxy matches the exact ``host:port`` (no CIDR over-allowance), resolves the name itself and
refuses to tunnel to private, loopback, link-local or metadata addresses even if an allowed name resolves there (DNS rebinding
and SSRF through an allowed name), connects to the address it checked, has header, idle and total timeouts and a connection
cap, never sees the payload (CONNECT is a blind tunnel), and treats a failing audit log as a reason to refuse.  The agent's own
DNS is closed by the uid rules, so name resolution happens only here.

Pure parsing/rendering functions are separate from the socket code; tests use local sockets only.  Python 3.9 compatible.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import select
import signal
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

# ----------------------------------------------------------------------------------------------
# endpoints
# ----------------------------------------------------------------------------------------------

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST_RE = re.compile(r"^(?:%s)(?:\.%s)*$" % (_LABEL, _LABEL))
_ALWAYS_BLOCKED_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("169.254.0.0/16", "fe80::/10", "168.63.129.16/32", "100.100.100.200/32", "fd00:ec2::254/128", "0.0.0.0/8")
)


class EndpointError(ValueError):
    """An endpoint string is malformed or not allowed to be allowlisted."""


def _norm_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _is_always_blocked(ip: "ipaddress._BaseAddress") -> bool:
    return any(ip in net for net in _ALWAYS_BLOCKED_NETS if net.version == ip.version)


def _is_nonpublic(ip: "ipaddress._BaseAddress") -> bool:
    return bool(
        ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified
        or _is_always_blocked(ip)
    )


def parse_endpoint(entry: str, default_port: Optional[int] = None) -> Tuple[str, int]:
    """``host:port`` -> (normalised host, port).  Accepts DNS names, ``*.suffix`` wildcards (at least two labels after the
    star), IPv4 and ``[IPv6]`` literals.  Raises ``EndpointError``; never guesses a port unless ``default_port`` is given.
    """
    if not isinstance(entry, str):
        raise EndpointError("endpoint is not a string")
    text = entry.strip()
    if not text or any(c in text for c in " \t\r\n\x00/@\\"):
        raise EndpointError("malformed endpoint %r" % entry)
    if text.startswith("["):
        m = re.match(r"^\[([0-9a-fA-F:.]+)\](?::(\d{1,5}))?$", text)
        if not m:
            raise EndpointError("malformed IPv6 endpoint %r" % entry)
        host, port_s = m.group(1), m.group(2)
        try:
            host = str(ipaddress.IPv6Address(host))
        except ValueError:
            raise EndpointError("malformed IPv6 address in %r" % entry)
    else:
        host, sep, port_s = text.rpartition(":")
        if not sep:
            host, port_s = text, None
        elif ":" in host:
            raise EndpointError("IPv6 endpoints must be written [addr]:port, got %r" % entry)
    if port_s is None:
        if default_port is None:
            raise EndpointError("endpoint %r has no port" % entry)
        port = int(default_port)
    else:
        if not port_s.isdigit():
            raise EndpointError("bad port in %r" % entry)
        port = int(port_s)
    if not 1 <= port <= 65535:
        raise EndpointError("port out of range in %r" % entry)
    host = _norm_host(host)
    if not host:
        raise EndpointError("empty host in %r" % entry)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        return str(ip), port
    wildcard = host.startswith("*.")
    name = host[2:] if wildcard else host
    if len(name) > 253 or not _HOST_RE.match(name):
        raise EndpointError("invalid host name in %r" % entry)
    if wildcard and name.count(".") < 1:
        raise EndpointError("wildcard %r is too broad" % entry)
    return host, port


def endpoint_rejection(host: str) -> Optional[str]:
    """Why a host must never be allowlisted (metadata/link-local/loopback/private literal, localhost), else None."""
    h = host[2:] if host.startswith("*.") else host
    if h == "localhost" or h.endswith(".localhost") or h.endswith(".internal") or h.endswith(".local"):
        return "local name"
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return None
    if _is_always_blocked(ip):
        return "metadata or link-local address"
    if _is_nonpublic(ip):
        return "private, loopback or reserved address"
    return None


@dataclass
class AuditResult:
    allow: List[str] = field(default_factory=list)
    rejected: List[Tuple[str, str]] = field(default_factory=list)  # (entry, reason)


_TOKEN_RE = re.compile(r"(?<![\w.\-*])((?:\*\.)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z0-9-]*[A-Za-z0-9]|\[[0-9A-Fa-f:.]+\]):(\d{1,5})(?!\d)")
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _table_endpoint(cells: List[str]) -> Optional[str]:
    port = next((c for c in cells if c.isdigit() and 1 <= int(c) <= 65535), None)
    if port is None:
        return None
    host = None
    for c in cells:
        cl = c.strip("`* ").lower().rstrip(".")
        if cl and "." in cl and not cl.isdigit() and not _IP_RE.match(cl) and _HOST_RE.match(cl.replace("*.", "", 1)):
            host = cl
            break
    if host is None:
        host = next((c for c in cells if _IP_RE.match(c)), None)
    return "%s:%s" % (host, port) if host else None


def parse_audit_detailed(text: str, default_port: Optional[int] = None) -> AuditResult:
    """Parse audit text into an allowlist plus the entries that were refused and why.

    Understood: one ``host:port`` per line (optionally with ``-``, quotes or commas around it, ``#`` comments), tokens of
    that shape anywhere in a line (the suggested ``allowed-endpoints`` block), and markdown/pipe table rows holding a domain (or
    IP) cell and a port cell.  Lines that match nothing are ignored.  Unverified against live harden-runner output; the format
    is parsed tolerantly and every refusal is reported rather than dropped.
    """
    seen: Set[str] = set()
    res = AuditResult()

    def consider(raw: str) -> None:
        try:
            host, port = parse_endpoint(raw, default_port)
        except EndpointError as exc:
            res.rejected.append((raw, str(exc)))
            return
        why = endpoint_rejection(host)
        shown = "[%s]:%d" % (host, port) if ":" in host else "%s:%d" % (host, port)
        if why:
            res.rejected.append((shown, why))
        elif shown not in seen:
            seen.add(shown)
            res.allow.append(shown)

    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "|" in s:
            cells = [c.strip() for c in s.strip("|").split("|")]
            cand = _table_endpoint(cells)
            if cand:
                consider(cand)
            continue
        plain = s.lstrip("-* \t").strip("\"',")
        if default_port is not None and re.fullmatch(r"(?:\*\.)?[A-Za-z0-9.-]+\.[A-Za-z0-9-]+", plain):
            consider(plain)
            continue
        if re.fullmatch(r"[^\s]+", plain) and ":" in plain and not plain.endswith(":"):
            try:
                parse_endpoint(plain, default_port)
            except EndpointError:
                pass
            else:
                consider(plain)
                continue
        for m in _TOKEN_RE.finditer(s):
            consider("%s:%s" % (m.group(1), m.group(2)))
    res.allow.sort()
    return res


def parse_audit(text: str, default_port: Optional[int] = None) -> List[str]:
    """Sorted, de-duplicated ``host:port`` allowlist from harden-runner audit output or a plain list (see ``parse_audit_detailed``)."""
    return parse_audit_detailed(text, default_port).allow


def render_allowed_endpoints(endpoints: Iterable[str], *, indent: int = 0) -> str:
    """The workflow input as a YAML block: ``allowed-endpoints: >`` then one sorted ``host:port`` per line, plus a trailing newline.

    Every entry is validated and must not be a forbidden address; ``EndpointError`` otherwise.  ``indent`` is the column of the key.
    """
    items: Set[str] = set()
    for e in endpoints:
        host, port = parse_endpoint(e)
        why = endpoint_rejection(host)
        if why:
            raise EndpointError("%s:%d must not be allowlisted (%s)" % (host, port, why))
        items.add("[%s]:%d" % (host, port) if ":" in host else "%s:%d" % (host, port))
    if not items:
        raise EndpointError("refusing to render an empty allowlist (harden-runner would block everything or nothing)")
    pad = " " * indent
    lines = [pad + "allowed-endpoints: >"] + [pad + "  " + i for i in sorted(items)]
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------------------------------
# CONNECT proxy
# ----------------------------------------------------------------------------------------------

LogFn = Callable[[Dict[str, Any]], None]
_DENY = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
_BAD = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
_BUSY = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
_BADGW = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
_OK = b"HTTP/1.1 200 Connection Established\r\n\r\n"
_MAX_HEADER = 8192


class ConnectProxy:
    """Loopback-only forward proxy that tunnels CONNECT requests to allowlisted ``host:port`` pairs and 403s the rest.

    ``allow``: iterable of ``host:port`` (see ``parse_endpoint``).  ``log(event_dict)`` is called for every decision and tunnel
    close; if it raises, the request is refused (no audit trail, no access).  ``allow_private=True`` lets allowlisted names
    resolve to loopback/private addresses (tests, internal registries) but metadata and link-local addresses stay blocked.
    ``resolver(host, port) -> list of ip strings`` can be injected for tests.  Usable as a context manager.
    """

    def __init__(
        self,
        allow: Iterable[str],
        log: Optional[LogFn] = None,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        idle_timeout: float = 30.0,
        total_timeout: float = 300.0,
        connect_timeout: float = 10.0,
        header_timeout: float = 10.0,
        max_conns: int = 64,
        allow_private: bool = False,
        resolver: Optional[Callable[[str, int], List[str]]] = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        try:
            ip = ipaddress.ip_address("127.0.0.1" if host == "localhost" else host)
        except ValueError:
            raise ValueError("listen host must be a loopback IP literal or 'localhost'")
        if not ip.is_loopback:
            raise ValueError("the proxy only listens on loopback; refusing %s" % host)
        self._listen_host = str(ip)
        self._listen_port = int(port)
        self._exact: Set[Tuple[str, int]] = set()
        self._wild: List[Tuple[str, int]] = []
        for entry in allow:
            h, p = parse_endpoint(entry)
            why = endpoint_rejection(h)
            if why and not (allow_private and why != "metadata or link-local address"):
                raise EndpointError("%s:%d cannot be allowlisted (%s)" % (h, p, why))
            if h.startswith("*."):
                self._wild.append((h[2:], p))
            else:
                self._exact.add((h, p))
        if not self._exact and not self._wild:
            raise ValueError("empty allowlist: the proxy would deny everything; refusing to start")
        self._log = log
        self._idle = float(idle_timeout)
        self._total = float(total_timeout)
        self._connect_timeout = float(connect_timeout)
        self._header_timeout = float(header_timeout)
        self._allow_private = allow_private
        self._resolver = resolver or self._default_resolve
        self._clock = clock
        self._slots = threading.BoundedSemaphore(max(1, int(max_conns)))
        self._reject_slots = threading.BoundedSemaphore(16)
        self._stop = threading.Event()
        self._listener: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._workers: List[threading.Thread] = []
        self._lock = threading.Lock()
        self.address: Tuple[str, int] = (self._listen_host, self._listen_port)

    # -- policy ------------------------------------------------------------------------------

    def decide(self, host: str, port: int) -> Tuple[bool, str]:
        """(allowed, reason) for a CONNECT target, before any resolution."""
        h = _norm_host(host)
        if (h, port) in self._exact:
            return True, "listed"
        try:
            ipaddress.ip_address(h)
            is_ip = True
        except ValueError:
            is_ip = False
        if not is_ip:
            for suffix, p in self._wild:
                if p == port and h.endswith("." + suffix):
                    return True, "wildcard"
        return False, "not allowlisted"

    @staticmethod
    def _default_resolve(host: str, port: int) -> List[str]:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        out: List[str] = []
        for fam, _t, _p, _c, sa in infos:
            addr = sa[0]
            if addr not in out:
                out.append(addr)
        return out

    def _check_addresses(self, host: str, port: int) -> Tuple[List[str], str]:
        try:
            ipaddress.ip_address(host)
            addrs = [host]
        except ValueError:
            try:
                addrs = self._resolver(host, port)
            except (OSError, UnicodeError):
                return [], "name did not resolve"
        if not addrs:
            return [], "name did not resolve"
        for a in addrs:
            try:
                ip = ipaddress.ip_address(a.split("%")[0])
            except ValueError:
                return [], "unparsable address"
            if _is_always_blocked(ip):
                return [], "resolved to a metadata or link-local address"
            if _is_nonpublic(ip) and not self._allow_private:
                return [], "resolved to a non-public address"
        return addrs, "ok"

    # -- lifecycle ---------------------------------------------------------------------------

    def start(self) -> "ConnectProxy":
        if self._listener is not None:
            raise RuntimeError("already started")
        fam = socket.AF_INET6 if ":" in self._listen_host else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self._listen_host, self._listen_port))
            s.listen(64)
            s.settimeout(0.05)
        except OSError:
            s.close()
            raise
        self._listener = s
        self.address = s.getsockname()[:2]
        self._thread = threading.Thread(target=self._serve, name="warden-egress-accept", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        if t is not None:
            t.join(5)
        if self._listener is not None:
            try:
                self._listener.close()
            finally:
                self._listener = None
        with self._lock:
            workers = list(self._workers)
        for w in workers:
            w.join(5)

    def __enter__(self) -> "ConnectProxy":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    def wait(self) -> None:
        """Block until ``request_stop`` is called (from a signal handler or another thread)."""
        while not self._stop.wait(0.5):
            pass

    def serve_forever(self) -> None:
        self.start()
        try:
            self.wait()
        finally:
            self.stop()

    def request_stop(self) -> None:
        self._stop.set()

    def _emit(self, event: Dict[str, Any]) -> bool:
        if self._log is None:
            return True
        try:
            self._log(event)
            return True
        except Exception:  # noqa: BLE001 - a broken audit log must refuse, not crash the accept loop
            return False

    def _serve(self) -> None:
        listener = self._listener
        assert listener is not None
        while not self._stop.is_set():
            try:
                conn, addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._slots.acquire(blocking=False):
                self._reject_busy(conn, addr[0])
                continue
            w = threading.Thread(target=self._worker, args=(conn, addr), daemon=True)
            with self._lock:
                self._workers = [x for x in self._workers if x.is_alive()] + [w]
            w.start()

    @staticmethod
    def _send_and_close(sock: socket.socket, data: bytes) -> None:
        """Send a final response, half-close, then briefly drain the request so the peer sees the response and not a reset."""
        try:
            sock.settimeout(2)
            sock.sendall(data)
            sock.shutdown(socket.SHUT_WR)
            sock.settimeout(0.1)
            drained = 0
            while drained < 65536:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                drained += len(chunk)
        except OSError:
            pass
        finally:
            sock.close()

    def _reject_busy(self, conn: socket.socket, client: str) -> None:
        self._emit({"event": "decision", "decision": "deny", "reason": "busy", "client": client})
        if self._reject_slots.acquire(blocking=False):
            def run() -> None:
                try:
                    self._send_and_close(conn, _BUSY)
                finally:
                    self._reject_slots.release()

            threading.Thread(target=run, daemon=True).start()
        else:
            conn.close()

    def _worker(self, conn: socket.socket, addr: Any) -> None:
        try:
            self._handle(conn, addr)
        except Exception:  # noqa: BLE001 - never let a handler bug leave a tunnel open
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
            self._slots.release()

    # -- one connection ----------------------------------------------------------------------

    def _read_head(self, conn: socket.socket) -> Optional[Tuple[bytes, bytes]]:
        conn.settimeout(self._header_timeout)
        buf = b""
        deadline = self._clock() + self._header_timeout
        while b"\r\n\r\n" not in buf:
            if len(buf) > _MAX_HEADER or self._clock() > deadline or self._stop.is_set():
                return None
            try:
                chunk = conn.recv(2048)
            except (socket.timeout, OSError):
                return None
            if not chunk:
                return None
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        return head, rest

    def _handle(self, conn: socket.socket, addr: Any) -> None:
        client = addr[0] if addr else ""
        got = self._read_head(conn)
        if got is None:
            self._emit({"event": "decision", "decision": "deny", "reason": "bad or slow request head", "client": client})
            self._send_and_close(conn, _BAD)
            return
        head, rest = got
        first = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = first.split(" ")
        if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
            self._emit({"event": "decision", "decision": "deny", "reason": "malformed request line", "client": client})
            self._send_and_close(conn, _BAD)
            return
        method, target = parts[0], parts[1]
        if method.upper() != "CONNECT":
            self._emit({"event": "decision", "decision": "deny", "reason": "only CONNECT is supported", "method": method[:16], "client": client})
            self._send_and_close(conn, _DENY)
            return
        try:
            host, port = parse_endpoint(target)
        except EndpointError:
            self._emit({"event": "decision", "decision": "deny", "reason": "bad CONNECT target", "client": client})
            self._send_and_close(conn, _BAD)
            return
        allowed, reason = self.decide(host, port)
        addrs: List[str] = []
        if allowed:
            addrs, why = self._check_addresses(host, port)
            if not addrs:
                allowed, reason = False, why
        event = {"event": "decision", "decision": "allow" if allowed else "deny", "host": host, "port": port, "reason": reason, "client": client}
        if not self._emit(event):
            self._send_and_close(conn, _DENY)
            return
        if not allowed:
            self._send_and_close(conn, _DENY)
            return
        upstream = self._dial(addrs, port)
        if upstream is None:
            self._emit({"event": "closed", "host": host, "port": port, "reason": "upstream connect failed", "bytes_up": 0, "bytes_down": 0})
            self._send_and_close(conn, _BADGW)
            return
        try:
            conn.settimeout(self._idle)
            conn.sendall(_OK)
            up, down, why_closed = self._relay(conn, upstream, rest)
        finally:
            upstream.close()
        self._emit({"event": "closed", "host": host, "port": port, "reason": why_closed, "bytes_up": up, "bytes_down": down})

    def _dial(self, addrs: Sequence[str], port: int) -> Optional[socket.socket]:
        for a in addrs:
            ip = a.split("%")[0]
            fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
            s = socket.socket(fam, socket.SOCK_STREAM)
            try:
                s.settimeout(self._connect_timeout)
                s.connect((ip, port))
                s.settimeout(self._idle)
                return s
            except OSError:
                s.close()
        return None

    def _relay(self, client: socket.socket, upstream: socket.socket, pending: bytes) -> Tuple[int, int, str]:
        up = down = 0
        start = last = self._clock()
        if pending:
            upstream.sendall(pending)
            up += len(pending)
        open_socks = {client: upstream, upstream: client}
        reason = "eof"
        while open_socks:
            now = self._clock()
            if self._stop.is_set():
                reason = "stopped"
                break
            if now - start > self._total:
                reason = "total timeout"
                break
            if now - last > self._idle:
                reason = "idle timeout"
                break
            try:
                ready, _, _ = select.select(list(open_socks), [], [], 0.1)
            except (OSError, ValueError):
                reason = "error"
                break
            for s in ready:
                other = open_socks.get(s)
                if other is None:
                    continue
                try:
                    data = s.recv(65536)
                except (socket.timeout, OSError):
                    reason = "error"
                    open_socks.clear()
                    break
                last = self._clock()
                if not data:
                    del open_socks[s]
                    try:
                        other.shutdown(socket.SHUT_WR)
                    except OSError:
                        open_socks.pop(other, None)
                    continue
                try:
                    other.sendall(data)
                except OSError:
                    reason = "error"
                    open_socks.clear()
                    break
                if s is client:
                    up += len(data)
                else:
                    down += len(data)
        return up, down, reason


# ----------------------------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    """``warden egress-proxy --listen 127.0.0.1:PORT --allow host:port ...``.  Exit 0 ok, 1 refused to run, 2 bad input."""
    ap = argparse.ArgumentParser(prog="warden egress-proxy", description="Loopback CONNECT proxy that permits only listed host:port pairs.")
    ap.add_argument("--listen", default="127.0.0.1:0", help="HOST:PORT on loopback (default 127.0.0.1:0)")
    ap.add_argument("--allow", action="append", default=[], metavar="HOST:PORT")
    ap.add_argument("--allow-file", action="append", default=[], help="file with one host:port per line")
    ap.add_argument("--from-audit", action="append", default=[], help="harden-runner audit output to derive the allowlist from")
    ap.add_argument("--log", default="-", help="JSON-lines decision log file ('-' = stderr)")
    ap.add_argument("--idle-timeout", type=float, default=30.0)
    ap.add_argument("--total-timeout", type=float, default=300.0)
    ap.add_argument("--max-conns", type=int, default=64)
    ap.add_argument("--allow-private", action="store_true", help="let allowlisted names resolve to private addresses (never metadata)")
    ap.add_argument("--render", action="store_true", help="print the workflow allowed-endpoints block and exit")
    try:
        ns = ap.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2
    entries: List[str] = list(ns.allow)
    try:
        for path in ns.allow_file:
            with open(path, "r", encoding="utf-8") as fh:
                entries += parse_audit(fh.read())
        for path in ns.from_audit:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                res = parse_audit_detailed(fh.read())
            for entry, why in res.rejected:
                print("refused from audit: %s (%s)" % (entry, why), file=sys.stderr)
            entries += res.allow
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    try:
        if ns.render:
            sys.stdout.write(render_allowed_endpoints(entries))
            return 0
        host, _, port_s = ns.listen.rpartition(":")
        if not port_s.isdigit():
            print("error: --listen must be HOST:PORT", file=sys.stderr)
            return 2
        log_fh = sys.stderr if ns.log == "-" else open(ns.log, "a", encoding="utf-8")
    except (EndpointError, OSError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    def log(event: Dict[str, Any]) -> None:
        log_fh.write(json.dumps(event, sort_keys=True) + "\n")
        log_fh.flush()

    try:
        proxy = ConnectProxy(
            entries, log, host=host or "127.0.0.1", port=int(port_s), idle_timeout=ns.idle_timeout,
            total_timeout=ns.total_timeout, max_conns=ns.max_conns, allow_private=ns.allow_private,
        )
    except (ValueError, EndpointError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        if log_fh is not sys.stderr:
            log_fh.close()
        return 1
    signal.signal(signal.SIGINT, lambda *_: proxy.request_stop())
    signal.signal(signal.SIGTERM, lambda *_: proxy.request_stop())
    try:
        proxy.start()
        print("listening on %s:%d" % (proxy.address[0], proxy.address[1]), file=sys.stderr)
        proxy.wait()
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    finally:
        proxy.stop()
        if log_fh is not sys.stderr:
            log_fh.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

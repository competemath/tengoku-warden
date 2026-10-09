"""A scoped, credential-injecting reverse proxy: the agent's real token never enters the agent's process.

What it does: `ScopedProxy` listens on loopback and forwards ONLY requests that match an explicit `Rule` (method, path
regex, one pinned upstream host, a body cap) to that host, adding the real credential from `token_provider()` on the way. The
agent is configured with the proxy's address and a per-run capability value; it never holds the token. Everything that does
not match a rule is refused with 403 and an audit entry. Presets build the rules for one repository's read-only API, one pull
request's comments, git smart-HTTP for one repository (and, scoped to exactly one branch, pushes), and the Anthropic messages
API.

Credit: the Tau Ceti Project's TauCetiWorker runs agents behind Bubble's scoped GitHub proxy, which holds the real token and lets a
container push to exactly one extra repository (research report 2026-10-09, features 1.1 and 1.2; TauCetiWorker PR #5, issue #1
"prompts are guidance, not an enforcement boundary"). The same report lists what that leaves open: the mode is opt-in (the default
since PR #98 on 2026-07-21 runs the agent on the host with the operator's token), GraphQL reads are account-wide, allowlisted GraphQL
mutations exist, the per-container proxy token is world-readable (mode 644) inside the container, and only GitHub is covered. The
bors fork's controller also never follows a redirect with a credential (bors-ng fork PR #5, 2026-10-06), which we adopt.

What we do differently: deny by default with an audit entry for every decision; GraphQL is refused unless a rule names it (and a
too-broad path regex cannot let it through by accident); client-supplied `Authorization`, `x-api-key`, `Cookie` and every other
header outside a small allowlist are dropped; the capability the agent presents is a random value that is not the real
credential and is compared in constant time; the upstream scheme, host and port come from the rule, never from the request; no
redirect is ever followed (refused by default); request bodies are size-capped before they are read, and a rule can inspect the
body (so a push is allowed only if every ref update names the one allowed branch, and the Anthropic preset can pin the model and
`max_tokens`, a spend control Tau Ceti lacks); audit entries never contain header values.

Honest limits: this is a reverse proxy, not a CONNECT proxy and not an egress firewall. It does no TLS interception, so an agent
that can reach the internet directly can ignore it: pair it with network confinement (the jail module) so the proxy is the ONLY
route out. DNS resolution of the upstream host is the caller's resolver's. A malicious upstream could echo the token in a
response body; we do not scan responses. The capability travels in clear over loopback; anything else on the machine that can
read the agent's environment or connect to the port can use it, so bind it to a per-run port/namespace. Git over HTTP clients
must send the capability header (`git -c http.extraHeader=...`) and must use Content-Length bodies for pushes (raise
`http.postBuffer`) or the chunked decoder is used. The `anthropic_messages` preset is for API-key mode: OAuth subscription tokens
(Claude Code logins) are bound to the official client flow and refresh logic, and may not work, or may violate their terms, when
injected by a raw proxy.
"""

from __future__ import annotations

import base64
import hmac
import http.client
import json
import re
import secrets
import ssl
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

CAPABILITY_HEADER = "X-Warden-Capability"
_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")
_HOST = re.compile(r"^(?=.{1,253}\Z)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\Z")
_LOOPBACK = ("127.0.0.1", "::1", "localhost")
_TOKEN = re.compile(r"^[\x21-\x7e]{1,4096}\Z")
_BAD_TARGET = re.compile(r"(?:^|/)\.\.?(?:/|$)|//|\\|%2e|%2f|%5c|%00|%25|[\x00-\x20\x7f-\xff#]", re.IGNORECASE)
DEFAULT_QUERY = r"[A-Za-z0-9_.,=&%:+\-]{0,512}"
# Client headers that may reach the upstream. Authorization, x-api-key, Cookie, Host, Proxy-*, Forwarded-* and everything
# else are dropped.
DEFAULT_PASS_HEADERS = ("accept", "content-type", "user-agent", "if-none-match", "if-modified-since", "x-github-api-version", "git-protocol", "content-encoding")
_HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "trailers", "transfer-encoding", "upgrade", "set-cookie", "set-cookie2"}


class TooLarge(Exception):
    pass


@dataclass(frozen=True)
class Rule:
    """One allowed request shape. `method` may list several: "GET|HEAD". `path_regex` must match the whole path."""

    method: str
    path_regex: str
    upstream_host: str
    max_body: int = 0
    rule_id: str = ""
    path_template: str = ""  # what the audit log records instead of the real path
    query_regex: str = DEFAULT_QUERY
    upstream_port: Optional[int] = None
    credential: str = "default"  # which token provider to use
    inject: str = "bearer"  # bearer | x-api-key | basic-x-access-token
    graphql: bool = False  # must be True for a rule to be allowed to match a GraphQL path
    pass_headers: Tuple[str, ...] = ()  # extra client headers (lowercase) this rule forwards
    body_check: Optional[Callable[[bytes], Optional[str]]] = field(default=None, compare=False)
    _path_re: Any = field(default=None, init=False, repr=False, compare=False)
    _query_re: Any = field(default=None, init=False, repr=False, compare=False)
    _methods: Tuple[str, ...] = field(default=(), init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        methods = tuple(m.strip() for m in self.method.split("|"))
        if not methods or any(m not in _METHODS for m in methods):
            raise ValueError("method must be one or more of %s joined by |" % "/".join(_METHODS))
        if not isinstance(self.upstream_host, str) or not _HOST.match(self.upstream_host):
            raise ValueError("upstream_host must be a bare lower-case host name")
        if isinstance(self.max_body, bool) or not isinstance(self.max_body, int) or self.max_body < 0:
            raise ValueError("max_body must be a non-negative integer")
        if self.upstream_port is not None and (isinstance(self.upstream_port, bool) or not isinstance(self.upstream_port, int) or not 0 < self.upstream_port < 65536):
            raise ValueError("upstream_port out of range")
        if self.inject not in ("bearer", "x-api-key", "basic-x-access-token"):
            raise ValueError("unknown inject style")
        if not self.path_regex.startswith("/"):
            raise ValueError("path_regex must start with /")
        object.__setattr__(self, "_methods", methods)
        object.__setattr__(self, "_path_re", re.compile(self.path_regex))
        object.__setattr__(self, "_query_re", re.compile(self.query_regex))
        if not self.rule_id:
            object.__setattr__(self, "rule_id", "rule:%s:%s" % (self.method, self.path_regex[:40]))
        if not self.path_template:
            object.__setattr__(self, "path_template", self.rule_id)


def split_target(target: str) -> Tuple[str, str]:
    """(path, query) from the request-target, or ValueError. Absolute-form targets and odd characters are refused."""
    if not isinstance(target, str) or not target.startswith("/") or target.startswith("//"):
        raise ValueError("request target must be origin-form")
    path, _, query = target.partition("?")
    if _BAD_TARGET.search(path) or re.search(r"[\x00-\x20\x7f-\xff#]|%0[0adAD]", query):
        raise ValueError("request target has forbidden characters")
    return path, query


def match_rule(rules: Sequence[Rule], method: str, target: str) -> Tuple[Optional[Rule], str]:
    """Pure decision: (rule, "ok") or (None, reason). The first matching rule wins."""
    try:
        path, query = split_target(target)
    except ValueError:
        return None, "bad_target"
    reason = "no_rule"
    for rule in rules:
        if method not in rule._methods or not rule._path_re.fullmatch(path):
            continue
        if not rule._query_re.fullmatch(query):
            reason = "query_not_allowed"
            continue
        if "graphql" in path.lower() and not rule.graphql:
            return None, "graphql_denied"
        return rule, "ok"
    if "graphql" in path.lower():
        return None, "graphql_denied"
    return None, reason


def _shape(target: str) -> str:
    """A coarse, secret-free description of an unmatched path for the audit log."""
    path = target.split("?", 1)[0]
    segs = [s for s in path.split("/") if s]
    if not segs or not re.fullmatch(r"[A-Za-z0-9_-]{1,30}", segs[0]):
        return "/*"
    return ("/" + "/".join([segs[0]] + ["*"] * (len(segs) - 1)))[:80]


def _read_chunked(rfile: Any, limit: int) -> bytes:
    out = bytearray()
    while True:
        line = rfile.readline(70)
        if not line.endswith(b"\n"):
            raise ValueError("bad chunk header")
        size_txt = line.split(b";", 1)[0].strip()
        if not re.fullmatch(rb"[0-9a-fA-F]{1,8}", size_txt):
            raise ValueError("bad chunk size")
        size = int(size_txt, 16)
        if size == 0:
            while True:  # trailers, discarded
                t = rfile.readline(8192)
                if t in (b"\r\n", b"\n", b""):
                    return bytes(out)
        if len(out) + size > limit:
            raise TooLarge()
        chunk = rfile.read(size)
        if len(chunk) != size or rfile.read(2) != b"\r\n":
            raise ValueError("truncated chunk")
        out += chunk


TokenProvider = Union[Callable[[], str], Mapping[str, Callable[[], str]]]


class ScopedProxy:
    """Deny-by-default credential-injecting reverse proxy bound to loopback.

    `token_provider` is a zero-argument callable returning the real credential (called on every forwarded request, so
    rotation works), or a mapping from `Rule.credential` names to such callables. `audit_log(entry)` receives one dict per
    decision (phase "decision") and one per forwarded result (phase "result"); if it raises, the request is NOT forwarded.
    `upstream_scheme="http"` exists for tests and is refused unless every rule's host is loopback.
    """

    def __init__(
        self,
        rules: Sequence[Rule],
        token_provider: TokenProvider,
        audit_log: Callable[[Dict[str, Any]], None],
        listen: Tuple[str, int] = ("127.0.0.1", 0),
        capability: Optional[str] = None,
        *,
        upstream_scheme: str = "https",
        redirect_policy: str = "refuse",
        max_response: int = 64 * 1024 * 1024,
        upstream_timeout: float = 60.0,
        client_timeout: float = 30.0,
        accept_capability_in_auth: bool = False,
    ) -> None:
        rules = list(rules)
        if not rules or not all(isinstance(r, Rule) for r in rules):
            raise ValueError("rules must be a non-empty list of Rule")
        if listen[0] not in _LOOPBACK:
            raise ValueError("the proxy only listens on loopback")
        if upstream_scheme not in ("https", "http"):
            raise ValueError("upstream_scheme must be https or http")
        if upstream_scheme == "http" and any(r.upstream_host not in _LOOPBACK for r in rules):
            raise ValueError("plain-http upstreams are for tests and only allowed for loopback hosts")
        if redirect_policy not in ("refuse", "return"):
            raise ValueError("redirect_policy must be refuse or return")
        if not callable(audit_log):
            raise ValueError("audit_log must be callable")
        providers: Dict[str, Callable[[], str]]
        if callable(token_provider):
            providers = {"*": token_provider}
        elif isinstance(token_provider, Mapping) and all(callable(v) for v in token_provider.values()):
            providers = dict(token_provider)
        else:
            raise ValueError("token_provider must be a callable or a mapping of callables")
        cap = capability if capability is not None else secrets.token_urlsafe(32)
        if not isinstance(cap, str) or len(cap) < 16 or not _TOKEN.match(cap):
            raise ValueError("capability must be 16+ printable characters")
        self.rules = rules
        self._providers = providers
        self._audit = audit_log
        self._listen = listen
        self.capability = cap
        self._scheme = upstream_scheme
        self._redirects = redirect_policy
        self._max_response = max_response
        self._up_timeout = upstream_timeout
        self._client_timeout = client_timeout
        self._cap_in_auth = accept_capability_in_auth
        self._lock = threading.Lock()
        self._counter = 0
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    # -- lifecycle -------------------------------------------------------------------------------------------------

    def start(self) -> Tuple[str, int]:
        if self._server is not None:
            raise RuntimeError("already started")
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "warden-authproxy"
            sys_version = ""
            timeout = proxy._client_timeout

            def log_message(self, *args: Any) -> None:  # the audit log is the record, not stderr
                return

            def _go(self) -> None:
                self.close_connection = True
                try:
                    proxy._serve(self)
                except Exception:  # never leak internals; the request is already refused or finished
                    try:
                        self.send_error(500)
                    except Exception:
                        pass

            do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_TRACE = do_CONNECT = _go

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = True

            def handle_error(self, request: Any, client_address: Any) -> None:  # a reset client is not an event; no traceback on stderr
                return

        if ":" in self._listen[0]:
            import socket

            Server.address_family = socket.AF_INET6
        self._server = Server(self._listen, Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self._thread.start()
        return self.address

    @property
    def address(self) -> Tuple[str, int]:
        if self._server is None:
            raise RuntimeError("not started")
        host, port = self._server.server_address[:2]
        return (str(host), int(port))

    @property
    def base_url(self) -> str:
        host, port = self.address
        return "http://%s:%d" % ("[%s]" % host if ":" in host else host, port)

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = self._thread = None

    def __enter__(self) -> "ScopedProxy":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    # -- request handling -------------------------------------------------------------------------------------------

    def _log(self, entry: Dict[str, Any]) -> bool:
        with self._lock:
            try:
                self._audit(entry)
                return True
            except Exception:
                return False

    def _next_id(self) -> int:
        with self._lock:
            self._counter += 1
            return self._counter

    def _capability_ok(self, headers: Any) -> bool:
        presented = [headers.get(CAPABILITY_HEADER)]
        if self._cap_in_auth:
            presented.append(headers.get("x-api-key"))
            auth = headers.get("Authorization") or ""
            if auth.lower().startswith("bearer "):
                presented.append(auth[7:].strip())
        want = self.capability.encode("ascii")
        ok = False
        for p in presented:
            if isinstance(p, str):
                try:
                    ok = hmac.compare_digest(p.encode("ascii"), want) or ok
                except UnicodeEncodeError:
                    pass
        return ok

    @staticmethod
    def _drain(h: BaseHTTPRequestHandler) -> None:
        """Swallow a small unread request body so closing the socket does not reset the client before it reads our answer."""
        cl = h.headers.get("Content-Length")
        if cl and re.fullmatch(r"\d{1,12}", cl.strip()):
            try:
                h.rfile.read(min(int(cl), 65536))
            except OSError:
                pass

    def _respond(self, h: BaseHTTPRequestHandler, status: int, reason: str) -> None:
        if not getattr(h, "_body_consumed", False):
            self._drain(h)
        body = json.dumps({"error": "denied" if status < 500 else "unavailable", "reason": reason}).encode("ascii")
        h.send_response(status)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(body)))
        h.send_header("Connection", "close")
        h.end_headers()
        if h.command != "HEAD":
            h.wfile.write(body)

    def _deny(self, h: BaseHTTPRequestHandler, rid: int, status: int, reason: str, rule: Optional[Rule] = None, rule_id: str = "-") -> None:
        self._log(
            {
                "phase": "decision",
                "request_id": rid,
                "decision": "deny",
                "reason": reason,
                "status": status,
                "method": h.command[:10],
                "host": rule.upstream_host if rule else "-",
                "rule_id": rule.rule_id if rule else rule_id,
                "path_template": rule.path_template if rule else _shape(h.path),
            }
        )
        self._respond(h, status, reason)

    def _read_body(self, h: BaseHTTPRequestHandler, rule: Rule) -> bytes:
        te, cl = h.headers.get("Transfer-Encoding"), h.headers.get("Content-Length")
        if te is not None and cl is not None:
            raise ValueError("both Transfer-Encoding and Content-Length")
        if te is not None:
            if te.strip().lower() != "chunked":
                raise ValueError("unsupported transfer encoding")
            data = _read_chunked(h.rfile, rule.max_body)
            h._body_consumed = True  # type: ignore[attr-defined]
            return data
        if cl is None:
            return b""
        if not re.fullmatch(r"\d{1,12}", cl.strip()):
            raise ValueError("bad content length")
        n = int(cl)
        if n > rule.max_body:
            raise TooLarge()
        data = h.rfile.read(n)
        if len(data) != n:
            raise ValueError("short body")
        h._body_consumed = True  # type: ignore[attr-defined]
        return data

    def _credential(self, rule: Rule) -> Optional[str]:
        provider = self._providers.get(rule.credential) or self._providers.get("*")
        if provider is None:
            return None
        try:
            tok = provider()
        except Exception:
            return None
        return tok if isinstance(tok, str) and _TOKEN.match(tok) else None

    def _serve(self, h: BaseHTTPRequestHandler) -> None:
        rid = self._next_id()
        method, target = h.command, h.path
        if not self._capability_ok(h.headers):
            return self._deny(h, rid, 403, "capability", rule_id="capability")
        rule, why = match_rule(self.rules, method, target)
        if rule is None:
            return self._deny(h, rid, 400 if why == "bad_target" else 403, why)
        path, query = split_target(target)
        try:
            body = self._read_body(h, rule)
        except TooLarge:
            return self._deny(h, rid, 413, "body_too_large", rule)
        except (ValueError, OSError):
            return self._deny(h, rid, 400, "bad_body", rule)
        if rule.body_check is not None and (body or method in ("POST", "PUT", "PATCH")):
            enc = (h.headers.get("Content-Encoding") or "identity").strip().lower()
            if enc != "identity":
                return self._deny(h, rid, 415, "encoded_body_not_inspectable", rule)
            try:
                verdict = rule.body_check(body)
            except Exception:
                verdict = "body_check_error"
            if verdict:
                return self._deny(h, rid, 403, "body_rejected:" + re.sub(r"[^a-z0-9_]", "_", str(verdict).lower())[:40], rule)
        token = self._credential(rule)
        if token is None:
            return self._deny(h, rid, 502, "no_credential", rule)

        headers: Dict[str, str] = {}
        allowed = set(DEFAULT_PASS_HEADERS) | set(rule.pass_headers)
        if rule.body_check is not None:
            allowed.discard("content-encoding")
        for name in allowed:
            val = h.headers.get(name)
            if val is not None and len(val) <= 1024 and "\r" not in val and "\n" not in val:
                headers[name] = val
        headers["Accept-Encoding"] = "identity"
        if rule.inject == "bearer":
            headers["Authorization"] = "Bearer " + token
        elif rule.inject == "x-api-key":
            headers["x-api-key"] = token
        else:
            headers["Authorization"] = "Basic " + base64.b64encode(b"x-access-token:" + token.encode("ascii")).decode("ascii")
        if body or method in ("POST", "PUT", "PATCH"):
            headers["Content-Length"] = str(len(body))

        if not self._log(
            {
                "phase": "decision",
                "request_id": rid,
                "decision": "allow",
                "reason": "ok",
                "status": None,
                "method": method,
                "host": rule.upstream_host,
                "rule_id": rule.rule_id,
                "path_template": rule.path_template,
            }
        ):
            return self._respond(h, 503, "audit_unavailable")  # cannot record it, so it does not happen

        port = rule.upstream_port
        if self._scheme == "https":
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(rule.upstream_host, port or 443, timeout=self._up_timeout, context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(rule.upstream_host, port or 80, timeout=self._up_timeout)
        status, sent = 502, 0
        logged = False

        def record_result() -> None:
            nonlocal logged
            if logged:
                return
            logged = True
            self._log(
                {
                    "phase": "result",
                    "request_id": rid,
                    "decision": "allow",
                    "status": status,
                    "method": method,
                    "host": rule.upstream_host,
                    "rule_id": rule.rule_id,
                    "path_template": rule.path_template,
                    "bytes_out": sent,
                }
            )

        try:
            try:
                conn.request(method, path + ("?" + query if query else ""), body=body if (body or method in ("POST", "PUT", "PATCH")) else None, headers=headers)
                resp = conn.getresponse()
            except (OSError, http.client.HTTPException, ssl.SSLError):
                status = 502
                record_result()  # recorded before the client can read the refusal
                self._respond(h, 502, "upstream_error")
                return
            status = resp.status
            if 300 <= status < 400 and self._redirects == "refuse":
                status = 502
                record_result()
                self._respond(h, 502, "redirect_refused")
                return
            declared = resp.getheader("Content-Length")
            if declared is not None and declared.isdigit() and int(declared) > self._max_response:
                status = 502
                record_result()
                self._respond(h, 502, "response_too_large")
                return
            h.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in _HOP_BY_HOP:
                    h.send_header(k, v)
            h.send_header("Connection", "close")
            h.end_headers()
            if method != "HEAD":
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    sent += len(chunk)
                    if sent > self._max_response:
                        h.close_connection = True
                        break  # truncated on purpose; the client sees a short body
                    h.wfile.write(chunk)
        except (OSError, http.client.HTTPException):
            pass  # client went away or upstream broke mid-body
        finally:
            conn.close()
            record_result()  # a streamed body is recorded when it ends: the client may already hold the headers


# --------------------------------------------------------------------------- presets


_NAMEPART = re.compile(r"^[A-Za-z0-9_.-]{1,100}\Z")


def _repo_parts(repo: str) -> Tuple[str, str]:
    if not isinstance(repo, str) or repo.count("/") != 1:
        raise ValueError("repo must be owner/name")
    owner, name = repo.split("/")
    for part in (owner, name):
        if not _NAMEPART.match(part) or part in (".", "..") or part.endswith(".git"):
            raise ValueError("invalid repository name")
    return owner, name


def _ci(text: str) -> str:
    return "(?i:%s)" % re.escape(text)  # GitHub owner and repository names are case-insensitive


def _positive(n: Any, label: str) -> int:
    if isinstance(n, bool) or not isinstance(n, int) or n <= 0:
        raise ValueError("%s must be a positive integer" % label)
    return n


def github_repo_readonly(repo: str, *, credential: str = "default") -> List[Rule]:
    """GET/HEAD on one repository's REST resources (contents, git data, commits, branches, PRs, issues, compare, releases, runs).

    Search, user, organisation, gist, secrets, hooks and every write are not matched. GraphQL is not matched.
    """
    owner, name = _repo_parts(repo)
    base = "/repos/%s/%s" % (_ci(owner), _ci(name))
    seg = r"[A-Za-z0-9_.%~+@=,-]+"
    parts = [
        r"",
        r"/readme",
        r"/tags",
        r"/contents(?:/%s)*" % seg,
        r"/git/(?:trees|blobs|commits|tags)/[0-9a-fA-F]{4,64}",
        r"/git/(?:ref|refs|matching-refs)(?:/%s)*" % seg,
        r"/commits(?:/%s)?" % seg,
        r"/commits/[A-Za-z0-9_.%%/-]+/(?:check-runs|status|statuses)",
        r"/branches(?:/%s)*" % seg,
        r"/pulls(?:/\d+(?:/(?:files|commits|comments|reviews|requested_reviewers))?)?",
        r"/issues(?:/\d+(?:/comments)?)?",
        r"/compare/[^/]+",
        r"/releases(?:/latest|/tags/%s)?" % seg,
        r"/actions/runs(?:/\d+(?:/jobs|/attempts/\d+)?)?",
    ]
    regex = base + "(?:" + "|".join(parts) + ")"
    return [
        Rule("GET|HEAD", regex, "api.github.com", 0, rule_id="github.repo_readonly", path_template="/repos/%s/%s/<read>" % (owner, name), credential=credential, pass_headers=("x-github-api-version",))
    ]


def github_pr_comment(repo: str, number: int, *, credential: str = "default", max_body: int = 65536) -> List[Rule]:
    """Read pull request `number` and its comments, and post new comments on it. Nothing else: no edits, no deletes, no reviews."""
    owner, name = _repo_parts(repo)
    n = _positive(number, "number")
    base = "/repos/%s/%s" % (_ci(owner), _ci(name))
    tmpl = "/repos/%s/%s" % (owner, name)
    return [
        Rule("GET|HEAD", base + "/pulls/%d" % n, "api.github.com", 0, rule_id="github.pr_read", path_template=tmpl + "/pulls/%d" % n, credential=credential),
        Rule("GET|HEAD", base + "/issues/%d/comments" % n, "api.github.com", 0, rule_id="github.pr_comments_read", path_template=tmpl + "/issues/%d/comments" % n, credential=credential),
        Rule("POST", base + "/issues/%d/comments" % n, "api.github.com", max_body, rule_id="github.pr_comment_create", path_template=tmpl + "/issues/%d/comments" % n, credential=credential),
    ]


def check_receive_pack_commands(body: bytes, branch: str) -> Optional[str]:
    """None if the receive-pack request updates exactly `refs/heads/<branch>` (no delete, one command), else a reason code.

    Reads only the leading pkt-line command list; the packfile after the flush packet is not looked at.
    """
    want = b"refs/heads/" + branch.encode("ascii")
    pos, commands = 0, 0
    while True:
        head = body[pos:pos + 4]
        if not re.fullmatch(rb"[0-9a-f]{4}", head):
            return "bad_pktline"
        n = int(head, 16)
        if n == 0:
            break
        if n < 4 or pos + n > len(body):
            return "bad_pktline"
        line = body[pos + 4:pos + n].split(b"\0", 1)[0].rstrip(b"\n")
        pos += n
        if re.fullmatch(rb"shallow [0-9a-f]{40}", line):
            continue
        m = re.fullmatch(rb"([0-9a-f]{40}) ([0-9a-f]{40}) (.+)", line)
        if not m:
            return "unsupported_command"  # push-cert and anything unknown
        if m.group(3) != want:
            return "ref_not_allowed"
        if set(m.group(2)) == {ord("0")}:
            return "delete_not_allowed"
        commands += 1
    if commands != 1:
        return "expected_one_command"
    return None


def _branch(branch: str) -> str:
    if (
        not isinstance(branch, str)
        or not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", branch)
        or ".." in branch
        or branch.startswith(("/", "-", "."))
        or branch.endswith(("/", ".lock", "."))
        or "//" in branch
    ):
        raise ValueError("invalid branch name")
    return branch


def github_git_over_http(repo: str, branch: str, *, allow_push: bool = True, credential: str = "default", max_fetch_body: int = 8 * 1024 * 1024, max_push_bytes: int = 64 * 1024 * 1024) -> List[Rule]:
    """Git smart-HTTP on github.com for exactly one repository: fetch/clone any ref, and push ONLY to `refs/heads/<branch>`.

    Push scoping works by reading the receive-pack command list from the request body (buffered up to `max_push_bytes`):
    one command, that exact ref, no delete, no push-cert. Pass `allow_push=False` for a read-only mirror. The credential is
    sent as HTTP Basic with the user name `x-access-token` (GitHub App installation tokens and PATs both work).
    """
    owner, name = _repo_parts(repo)
    _branch(branch)
    repo_path = "/%s/%s(?:\\.git)?" % (_ci(owner), _ci(name))
    tmpl = "/%s/%s.git" % (owner, name)
    common = dict(credential=credential, inject="basic-x-access-token", pass_headers=("git-protocol",))
    rules = [
        Rule("GET", repo_path + "/info/refs", "github.com", 0, rule_id="git.info_refs_fetch", path_template=tmpl + "/info/refs?upload-pack", query_regex=r"service=git-upload-pack", **common),
        Rule("POST", repo_path + "/git-upload-pack", "github.com", max_fetch_body, rule_id="git.upload_pack", path_template=tmpl + "/git-upload-pack", **common),
    ]
    if allow_push:
        rules += [
            Rule("GET", repo_path + "/info/refs", "github.com", 0, rule_id="git.info_refs_push", path_template=tmpl + "/info/refs?receive-pack", query_regex=r"service=git-receive-pack", **common),
            Rule(
                "POST",
                repo_path + "/git-receive-pack",
                "github.com",
                max_push_bytes,
                rule_id="git.receive_pack_one_branch",
                path_template=tmpl + "/git-receive-pack#" + branch,
                body_check=lambda body: check_receive_pack_commands(body, branch),
                **common,
            ),
        ]
    return rules


def anthropic_messages(*, allowed_models: Optional[Sequence[str]] = None, max_tokens_cap: Optional[int] = None, max_body: int = 1_000_000, credential: str = "default") -> List[Rule]:
    """POST /v1/messages (and /v1/messages/count_tokens) on api.anthropic.com with `x-api-key` injected.

    `allowed_models` pins the `model` field and `max_tokens_cap` bounds `max_tokens` (it must be present), checked on the body
    before forwarding. API-key mode only: see the module docstring about OAuth subscription tokens. Point the agent at
    `ScopedProxy.base_url` (ANTHROPIC_BASE_URL) and give it any placeholder key plus the capability header, or construct the proxy
    with `accept_capability_in_auth=True` and use the capability as the agent's API key.
    """
    models = tuple(allowed_models) if allowed_models is not None else None
    if max_tokens_cap is not None:
        _positive(max_tokens_cap, "max_tokens_cap")

    def check(body: bytes) -> Optional[str]:
        try:
            data = json.loads(body.decode("utf-8"))
        except ValueError:
            return "not_json"
        if not isinstance(data, dict):
            return "not_object"
        if models is not None and data.get("model") not in models:
            return "model_not_allowed"
        if max_tokens_cap is not None:
            mt = data.get("max_tokens")
            if isinstance(mt, bool) or not isinstance(mt, int) or not 0 < mt <= max_tokens_cap:
                return "max_tokens_not_allowed"
        return None

    return [
        Rule(
            "POST",
            r"/v1/messages(?:/count_tokens)?",
            "api.anthropic.com",
            max_body,
            rule_id="anthropic.messages",
            path_template="/v1/messages",
            query_regex=r"",
            credential=credential,
            inject="x-api-key",
            pass_headers=("anthropic-version", "anthropic-beta"),
            body_check=check,
        )
    ]

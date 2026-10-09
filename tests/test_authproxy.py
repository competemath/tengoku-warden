import base64
import http.client
import json
import time
import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from warden import authproxy as ap
from warden.authproxy import Rule, ScopedProxy

REAL = "REAL" + "-" + "UPSTREAM" + "-" + "VALUE" + "-1234"  # built at runtime, never a literal credential
CAP = "CAPABILITY" + "-" + "RUN" + "-" + "abcdef0123456789"


class FakeUpstream:
    def __init__(self):
        self.log = []
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _any(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                outer.log.append({"method": self.command, "path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
                p = self.path.split("?")[0]
                if p == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/echo")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if p == "/big":
                    payload = b"x" * 5000
                elif p == "/cookie":
                    payload = b"{}"
                else:
                    payload = json.dumps({"ok": True}).encode()
                self.send_response(200)
                if p == "/cookie":
                    self.send_header("Set-Cookie", "session=1")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _any

        class S(ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):
                pass

        self.server = S(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


def pkt(text):
    raw = text if isinstance(text, bytes) else text.encode()
    return b"%04x" % (len(raw) + 4) + raw


class ProxyCase(unittest.TestCase):
    rules = None
    kwargs = {}

    def setUp(self):
        self.up = FakeUpstream()
        self.addCleanup(self.up.close)
        self.audit = []
        self.rules = self.make_rules()
        self.proxy = ScopedProxy(
            self.rules,
            lambda: REAL,
            self.audit.append,
            capability=CAP,
            upstream_scheme="http",
            **self.kwargs
        )
        self.proxy.start()
        self.addCleanup(self.proxy.stop)

    def make_rules(self):
        return [
            Rule("GET|HEAD", r"/echo|/redirect|/big|/cookie|/graphql", "127.0.0.1", 0, rule_id="t.read", upstream_port=self.up.port),
            Rule("POST", r"/post", "127.0.0.1", 100, rule_id="t.post", upstream_port=self.up.port, path_template="/post"),
        ]

    def req(self, method, path, headers=None, body=None, cap=True, encode_chunked=False):
        host, port = self.proxy.address
        conn = http.client.HTTPConnection(host, port, timeout=10)
        try:
            h = dict(headers or {})
            if cap is True:
                h[ap.CAPABILITY_HEADER] = CAP
            elif cap:
                h[ap.CAPABILITY_HEADER] = cap
            conn.request(method, path, body=body, headers=h, encode_chunked=encode_chunked)
            r = conn.getresponse()
            data = r.read()
            return r.status, dict((k.lower(), v) for k, v in r.getheaders()), data
        finally:
            conn.close()

    def raw(self, payload):
        s = socket.create_connection(self.proxy.address, timeout=5)
        try:
            s.sendall(payload)
            chunks = []
            while True:
                b = s.recv(4096)
                if not b:
                    break
                chunks.append(b)
            return b"".join(chunks)
        finally:
            s.close()


class ForwardingTest(ProxyCase):
    def test_allowed_request_gets_the_real_credential(self):
        status, hdrs, body = self.req("GET", "/echo?x=1")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True})
        seen = self.up.log[-1]
        self.assertEqual(seen["headers"]["authorization"], "Bearer " + REAL)
        self.assertEqual(seen["path"], "/echo?x=1")
        self.assertEqual(seen["headers"]["host"], "127.0.0.1:%d" % self.up.port)  # pinned from the rule

    def test_client_credentials_cookies_and_unknown_headers_are_stripped(self):
        evil = "client" + "-" + "supplied" + "-" + "secret"
        self.req(
            "GET",
            "/echo",
            headers={
                "Authorization": "Bearer " + evil,
                "x-api-key": evil,
                "Cookie": "sid=" + evil,
                "X-Forwarded-For": "6.6.6.6",
                "Proxy-Authorization": "Basic " + evil,
                "X-Evil": "1",
                "Accept": "application/json",
            },
        )
        seen = self.up.log[-1]["headers"]
        self.assertEqual(seen["authorization"], "Bearer " + REAL)
        for k in ("x-api-key", "cookie", "x-forwarded-for", "proxy-authorization", "x-evil", ap.CAPABILITY_HEADER.lower()):
            self.assertNotIn(k, seen)
        self.assertNotIn(evil, json.dumps(seen))
        self.assertEqual(seen["accept"], "application/json")

    def test_unmatched_path_and_method_denied_with_audit(self):
        for method, path in (("GET", "/admin"), ("GET", "/echo/extra"), ("DELETE", "/echo"), ("POST", "/echo"), ("GET", "/post"), ("GET", "/echo?" + "a" * 600)):
            status, _, body = self.req(method, path, body=b"x" if method in ("POST", "DELETE") else None)
            self.assertEqual(status, 403, (method, path))
        self.assertEqual(self.up.log, [])
        denies = [e for e in self.audit if e["decision"] == "deny"]
        self.assertEqual(len(denies), 6)
        self.assertEqual(denies[0]["reason"], "no_rule")
        self.assertEqual(denies[0]["path_template"], "/admin")  # coarse shape only

    def test_graphql_denied_unless_a_rule_names_it(self):
        # the rule's regex mentions /graphql, but the rule is not marked graphql=True, so it still cannot match
        status, _, _ = self.req("GET", "/graphql")
        self.assertEqual(status, 403)
        self.assertEqual(self.audit[-1]["reason"], "graphql_denied")
        self.assertEqual(self.up.log, [])
        broad = [Rule("POST", r"/.*", "127.0.0.1", 100, rule_id="broad", upstream_port=self.up.port)]
        self.assertEqual(ap.match_rule(broad, "POST", "/graphql")[1], "graphql_denied")
        self.assertEqual(ap.match_rule(broad, "POST", "/v3/GraphQL")[1], "graphql_denied")
        named = [Rule("POST", r"/graphql", "127.0.0.1", 100, rule_id="gql", graphql=True, upstream_port=self.up.port)]
        self.assertEqual(ap.match_rule(named, "POST", "/graphql")[0].rule_id, "gql")

    def test_missing_or_wrong_capability_denied_even_for_a_valid_path(self):
        for cap in (False, "wrong" * 5, CAP[:-1], "", CAP + "x"):
            status, _, _ = self.req("GET", "/echo", cap=cap)
            self.assertEqual(status, 403, cap)
        status, _, _ = self.req("GET", "/echo", headers={"Authorization": "Bearer " + CAP}, cap=False)
        self.assertEqual(status, 403)  # the capability in Authorization does not count unless opted in
        self.assertEqual(self.up.log, [])
        self.assertTrue(all(e["rule_id"] == "capability" for e in self.audit))

    def test_redirects_are_refused_not_followed(self):
        status, hdrs, _ = self.req("GET", "/redirect")
        self.assertEqual(status, 502)
        self.assertNotIn("location", hdrs)
        self.assertEqual([e["path"] for e in self.up.log], ["/redirect"])  # /echo was never requested
        self.assertEqual(self.audit[-1]["status"], 502)

    def test_oversize_body_denied_before_upstream(self):
        status, _, _ = self.req("POST", "/post", body=b"y" * 101, headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 413)
        status, _, _ = self.req("POST", "/post", body=b"y" * 100)
        self.assertEqual(status, 200)
        self.assertEqual(self.up.log[-1]["body"], b"y" * 100)
        self.assertEqual(len(self.up.log), 1)

    def test_chunked_bodies_are_decoded_and_capped(self):
        status, _, _ = self.req("POST", "/post", body=iter([b"abc", b"def"]), encode_chunked=True)
        self.assertEqual(status, 200)
        self.assertEqual(self.up.log[-1]["body"], b"abcdef")
        status, _, _ = self.req("POST", "/post", body=iter([b"z" * 60, b"z" * 60]), encode_chunked=True)
        self.assertEqual(status, 413)
        self.assertEqual(len(self.up.log), 1)

    def test_smuggling_shapes_rejected(self):
        both = b"POST /post HTTP/1.1\r\nHost: x\r\n%s: %s\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n" % (ap.CAPABILITY_HEADER.encode(), CAP.encode())
        self.assertIn(b" 400 ", self.raw(both).split(b"\r\n")[0])
        gz = b"POST /post HTTP/1.1\r\nHost: x\r\n%s: %s\r\nTransfer-Encoding: gzip\r\n\r\n" % (ap.CAPABILITY_HEADER.encode(), CAP.encode())
        self.assertIn(b" 400 ", self.raw(gz).split(b"\r\n")[0])
        self.assertEqual(self.up.log, [])

    def test_hostile_targets_never_reach_upstream(self):
        cap = b"%s: %s" % (ap.CAPABILITY_HEADER.encode(), CAP.encode())
        for target in (b"/echo/../admin", b"/%2e%2e/admin", b"/echo%2f..%2fadmin", b"//evil.example/echo", b"http://evil.example/echo", b"/echo%00", b"/ec\\ho", b"/echo#frag", b"/%252e", b"*"):
            resp = self.raw(b"GET " + target + b" HTTP/1.1\r\nHost: evil.example\r\n" + cap + b"\r\n\r\n")
            status_line = resp.split(b"\r\n")[0]
            self.assertTrue(b" 400 " in status_line or b" 403 " in status_line, (target, status_line))
        self.assertEqual(self.up.log, [])

    def test_upstream_host_comes_from_the_rule_not_the_request(self):
        cap = b"%s: %s" % (ap.CAPABILITY_HEADER.encode(), CAP.encode())
        resp = self.raw(b"GET /echo HTTP/1.1\r\nHost: evil.example\r\n" + cap + b"\r\n\r\n")
        self.assertIn(b" 200 ", resp.split(b"\r\n")[0])
        self.assertEqual(self.up.log[-1]["headers"]["host"], "127.0.0.1:%d" % self.up.port)

    def wait_for_results(self, n):
        """A streamed response is audited when its body ends, which can be a moment after the client read it."""
        for _ in range(200):
            if len([e for e in self.audit if e.get("phase") == "result"]) >= n:
                return
            time.sleep(0.01)

    def test_audit_entries_have_no_secrets_or_header_values(self):
        evil = "client" + "-" + "supplied" + "-" + "secret"
        self.req("GET", "/echo?q=" + evil, headers={"Authorization": "Bearer " + evil, "Cookie": evil})
        self.req("GET", "/admin/" + evil, headers={"Authorization": "Bearer " + evil})
        self.req("GET", "/echo", cap="nope")
        self.req("POST", "/post", body=b"b" * 10)
        self.wait_for_results(2)
        blob = json.dumps(self.audit)
        for secret in (REAL, CAP, evil, "Bearer", "nope"):
            self.assertNotIn(secret, blob)
        allowed = [e for e in self.audit if e["decision"] == "allow"]
        self.assertEqual({e["phase"] for e in allowed}, {"decision", "result"})
        self.assertEqual([e["status"] for e in allowed if e["phase"] == "result"], [200, 200])
        for e in self.audit:
            self.assertEqual(set(e) - {"phase", "request_id", "decision", "reason", "status", "method", "host", "rule_id", "path_template", "bytes_out"}, set())
        self.assertEqual(self.audit[0]["host"], "127.0.0.1")
        self.assertEqual(self.audit[0]["path_template"], "t.read")

    def test_response_cookies_dropped_and_head_works(self):
        status, hdrs, _ = self.req("GET", "/cookie")
        self.assertEqual(status, 200)
        self.assertNotIn("set-cookie", hdrs)
        status, _, body = self.req("HEAD", "/echo")
        self.assertEqual((status, body), (200, b""))


class FailClosedTest(unittest.TestCase):
    def build(self, provider, audit, up, **kw):
        rules = [Rule("GET", r"/echo", "127.0.0.1", 0, rule_id="t", upstream_port=up.port)]
        p = ScopedProxy(rules, provider, audit, capability=CAP, upstream_scheme="http", **kw)
        p.start()
        self.addCleanup(p.stop)
        return p

    def get(self, p, path="/echo"):
        conn = http.client.HTTPConnection(*p.address, timeout=10)
        try:
            conn.request("GET", path, headers={ap.CAPABILITY_HEADER: CAP})
            r = conn.getresponse()
            r.read()
            return r.status
        finally:
            conn.close()

    def test_credential_failure_and_audit_failure_do_not_forward(self):
        up = FakeUpstream()
        self.addCleanup(up.close)

        def boom():
            raise RuntimeError("vault down")

        entries = []
        self.assertEqual(self.get(self.build(boom, entries.append, up)), 502)
        self.assertEqual(self.get(self.build(lambda: "bad token with spaces", entries.append, up)), 502)
        self.assertEqual(self.get(self.build(lambda: "", entries.append, up)), 502)
        self.assertEqual(self.get(self.build(lambda: REAL + "\r\nX-Injected: 1", entries.append, up)), 502)
        self.assertEqual(self.get(self.build(lambda: REAL + "\n", entries.append, up)), 502)

        def broken_audit(entry):
            raise OSError("disk full")

        self.assertEqual(self.get(self.build(lambda: REAL, broken_audit, up)), 503)
        self.assertEqual(up.log, [])
        self.assertTrue(all(e["reason"] == "no_credential" for e in entries))

    def test_upstream_down_is_502_and_oversize_response_refused(self):
        up = FakeUpstream()
        port = up.port
        self.addCleanup(up.close)
        entries = []
        p = self.build(lambda: REAL, entries.append, up, max_response=1000)
        rules_big = [Rule("GET", r"/big", "127.0.0.1", 0, rule_id="big", upstream_port=port)]
        p2 = ScopedProxy(rules_big, lambda: REAL, entries.append, capability=CAP, upstream_scheme="http", max_response=1000)
        p2.start()
        self.addCleanup(p2.stop)
        self.assertEqual(self.get(p2, "/big"), 502)
        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        dead.close()
        p3 = ScopedProxy([Rule("GET", r"/echo", "127.0.0.1", 0, rule_id="d", upstream_port=dead_port)], lambda: REAL, entries.append, capability=CAP, upstream_scheme="http")
        p3.start()
        self.addCleanup(p3.stop)
        self.assertEqual(self.get(p3), 502)
        self.assertEqual(self.get(p), 200)

    def test_return_redirect_policy_still_never_follows(self):
        up = FakeUpstream()
        self.addCleanup(up.close)
        p = ScopedProxy([Rule("GET", r"/redirect", "127.0.0.1", 0, rule_id="r", upstream_port=up.port)], lambda: REAL, [].append, capability=CAP, upstream_scheme="http", redirect_policy="return")
        p.start()
        self.addCleanup(p.stop)
        self.assertEqual(self.get(p, "/redirect"), 302)
        self.assertEqual([e["path"] for e in up.log], ["/redirect"])

    def test_constructor_validation(self):
        r = [Rule("GET", r"/x", "127.0.0.1", 0, upstream_port=9)]
        ok = lambda: "t"
        for kw in (
            dict(listen=("0.0.0.0", 0)),
            dict(listen=("192.0.2.1", 0)),
            dict(capability="short"),
            dict(capability="has space in it but long enough"),
            dict(upstream_scheme="ftp"),
            dict(redirect_policy="follow"),
        ):
            with self.assertRaises(ValueError, msg=kw):
                ScopedProxy(r, ok, [].append, **kw)
        with self.assertRaises(ValueError):
            ScopedProxy([], ok, [].append)
        with self.assertRaises(ValueError):
            ScopedProxy(r, "token-string", [].append)
        with self.assertRaises(ValueError):
            ScopedProxy([Rule("GET", r"/x", "api.github.com", 0)], ok, [].append, upstream_scheme="http")  # plain http only for loopback
        with self.assertRaises(ValueError):
            ScopedProxy(r, ok, "not callable")

    def test_rule_validation(self):
        for kw in (
            dict(method="CONNECT", path_regex="/x", upstream_host="a.example"),
            dict(method="GET", path_regex="x", upstream_host="a.example"),
            dict(method="GET", path_regex="/x", upstream_host="https://a.example"),
            dict(method="GET", path_regex="/x", upstream_host="a.example/path"),
            dict(method="GET", path_regex="/x", upstream_host="A.EXAMPLE"),
            dict(method="GET", path_regex="/x", upstream_host="a.example\n"),
            dict(method="GET", path_regex="/x", upstream_host="a.example", max_body=-1),
            dict(method="GET", path_regex="/x", upstream_host="a.example", inject="cookie"),
            dict(method="GET", path_regex="/x", upstream_host="a.example", upstream_port=70000),
        ):
            with self.assertRaises(ValueError, msg=kw):
                Rule(**kw)


class MultiCredentialTest(unittest.TestCase):
    def test_mapping_of_providers_and_injection_styles(self):
        up = FakeUpstream()
        self.addCleanup(up.close)
        rules = [
            Rule("GET", r"/a", "127.0.0.1", 0, rule_id="a", upstream_port=up.port, credential="gh", inject="basic-x-access-token"),
            Rule("GET", r"/b", "127.0.0.1", 0, rule_id="b", upstream_port=up.port, credential="anth", inject="x-api-key"),
        ]
        p = ScopedProxy(rules, {"gh": lambda: "GH" + "VALUE", "anth": lambda: "AN" + "VALUE"}, [].append, capability=CAP, upstream_scheme="http", accept_capability_in_auth=True)
        p.start()
        self.addCleanup(p.stop)
        for path, hdr in (("/a", {}), ("/b", {"x-api-key": CAP})):
            conn = http.client.HTTPConnection(*p.address, timeout=10)
            try:
                conn.request("GET", path, headers=dict(hdr, **({} if hdr else {"Authorization": "Bearer " + CAP})))
                self.assertEqual(conn.getresponse().status, 200)
            finally:
                conn.close()
        a, b = up.log
        self.assertEqual(a["headers"]["authorization"], "Basic " + base64.b64encode(b"x-access-token:GHVALUE").decode())
        self.assertEqual(b["headers"]["x-api-key"], "ANVALUE")
        self.assertNotIn(CAP, json.dumps([a["headers"], b["headers"]]))
        # an unknown credential name has no provider: refused
        q = ScopedProxy([Rule("GET", r"/a", "127.0.0.1", 0, upstream_port=up.port, credential="zzz")], {"gh": lambda: "t"}, [].append, capability=CAP, upstream_scheme="http")
        q.start()
        self.addCleanup(q.stop)
        conn = http.client.HTTPConnection(*q.address, timeout=10)
        try:
            conn.request("GET", "/a", headers={ap.CAPABILITY_HEADER: CAP})
            self.assertEqual(conn.getresponse().status, 502)
        finally:
            conn.close()


class PresetTest(unittest.TestCase):
    def allowed(self, rules, method, target):
        r, why = ap.match_rule(rules, method, target)
        return r is not None

    def test_repo_readonly(self):
        rules = ap.github_repo_readonly("Acme/Widgets")
        yes = [
            ("GET", "/repos/Acme/Widgets"),
            ("GET", "/repos/acme/widgets/contents/src/a%20b.py?ref=main"),
            ("GET", "/repos/acme/widgets/pulls/12/files?per_page=100"),
            ("GET", "/repos/acme/widgets/commits/abcdef123/check-runs"),
            ("GET", "/repos/acme/widgets/compare/main...feature"),
            ("HEAD", "/repos/acme/widgets/git/ref/heads/main"),
            ("GET", "/repos/acme/widgets/issues/5/comments"),
        ]
        no = [
            ("POST", "/repos/acme/widgets/issues"),
            ("PUT", "/repos/acme/widgets/contents/a.txt"),
            ("DELETE", "/repos/acme/widgets"),
            ("GET", "/repos/acme/other"),
            ("GET", "/repos/acme/widgets2"),
            ("GET", "/repos/evil/widgets"),
            ("GET", "/repos/acme/widgets/actions/secrets"),
            ("GET", "/repos/acme/widgets/hooks"),
            ("GET", "/repos/acme/widgets/../../user"),
            ("GET", "/repos/acme/widgets/contents/%2e%2e/x"),
            ("GET", "/user"),
            ("GET", "/search/code?q=x"),
            ("GET", "/graphql"),
            ("POST", "/graphql"),
            ("GET", "/repos/acme/widgets/contents/a?x=%0d%0a"),
            ("GET", "/orgs/acme/members"),
        ]
        for m, t in yes:
            self.assertTrue(self.allowed(rules, m, t), (m, t))
        for m, t in no:
            self.assertFalse(self.allowed(rules, m, t), (m, t))

    def test_pr_comment_is_scoped_to_one_number(self):
        rules = ap.github_pr_comment("acme/widgets", 7)
        self.assertTrue(self.allowed(rules, "POST", "/repos/acme/widgets/issues/7/comments"))
        self.assertTrue(self.allowed(rules, "GET", "/repos/acme/widgets/pulls/7"))
        for m, t in (
            ("POST", "/repos/acme/widgets/issues/8/comments"),
            ("POST", "/repos/acme/widgets/issues/77/comments"),
            ("POST", "/repos/acme/other/issues/7/comments"),
            ("PATCH", "/repos/acme/widgets/issues/comments/1"),
            ("DELETE", "/repos/acme/widgets/issues/comments/1"),
            ("POST", "/repos/acme/widgets/pulls/7/merge"),
            ("PUT", "/repos/acme/widgets/pulls/7/merge"),
            ("POST", "/repos/acme/widgets/pulls/7/reviews"),
        ):
            self.assertFalse(self.allowed(rules, m, t), (m, t))
        for bad in (0, -1, True, "7", None):
            with self.assertRaises(ValueError):
                ap.github_pr_comment("acme/widgets", bad)

    def test_bad_repo_names_rejected(self):
        for bad in ("acme", "a/b/c", "../x", "a/..", "a/b.git", "a b/c", "", None, "a/b\n"):
            with self.assertRaises(ValueError, msg=bad):
                ap.github_repo_readonly(bad)

    def test_git_over_http_paths_and_branch_scope(self):
        rules = ap.github_git_over_http("acme/widgets", "agent/fix-1")
        self.assertTrue(self.allowed(rules, "GET", "/acme/widgets.git/info/refs?service=git-upload-pack"))
        self.assertTrue(self.allowed(rules, "GET", "/acme/widgets/info/refs?service=git-receive-pack"))
        self.assertTrue(self.allowed(rules, "POST", "/acme/widgets.git/git-upload-pack"))
        self.assertTrue(self.allowed(rules, "POST", "/acme/widgets.git/git-receive-pack"))
        self.assertFalse(self.allowed(rules, "GET", "/acme/widgets.git/info/refs"))
        self.assertFalse(self.allowed(rules, "GET", "/acme/widgets.git/info/refs?service=git-upload-pack&x=1"))
        self.assertFalse(self.allowed(rules, "GET", "/acme/other.git/info/refs?service=git-upload-pack"))
        self.assertFalse(self.allowed(rules, "POST", "/acme/other.git/git-receive-pack"))
        self.assertFalse(self.allowed(rules, "GET", "/acme/widgets.git/archive"))
        readonly = ap.github_git_over_http("acme/widgets", "x", allow_push=False)
        self.assertFalse(self.allowed(readonly, "POST", "/acme/widgets.git/git-receive-pack"))
        self.assertFalse(self.allowed(readonly, "GET", "/acme/widgets.git/info/refs?service=git-receive-pack"))
        for bad in ("", "../x", "-rf", "a b", "a..b", "x.lock", "/x", "x/", "a//b", None):
            with self.assertRaises(ValueError, msg=bad):
                ap.github_git_over_http("acme/widgets", bad)

    def test_receive_pack_command_inspection(self):
        old, new, zero = "1" * 40, "2" * 40, "0" * 40
        good = pkt("%s %s refs/heads/agent/fix-1\0report-status side-band-64k\n" % (old, new)) + b"0000" + b"PACK...."
        check = lambda body: ap.check_receive_pack_commands(body, "agent/fix-1")
        self.assertIsNone(check(good))
        self.assertIsNone(check(pkt("shallow " + "3" * 40) + good))
        self.assertEqual(check(pkt("%s %s refs/heads/main\0x" % (old, new)) + b"0000"), "ref_not_allowed")
        self.assertEqual(check(pkt("%s %s refs/heads/agent/fix-10\0x" % (old, new)) + b"0000"), "ref_not_allowed")
        self.assertEqual(check(pkt("%s %s refs/tags/v1\0x" % (old, new)) + b"0000"), "ref_not_allowed")
        self.assertEqual(check(pkt("%s %s refs/heads/agent/fix-1\0x" % (old, zero)) + b"0000"), "delete_not_allowed")
        two = pkt("%s %s refs/heads/agent/fix-1\0x" % (old, new)) + pkt("%s %s refs/heads/main" % (old, new)) + b"0000"
        self.assertEqual(check(two), "ref_not_allowed")
        same_twice = pkt("%s %s refs/heads/agent/fix-1\0x" % (old, new)) + pkt("%s %s refs/heads/agent/fix-1" % (old, new)) + b"0000"
        self.assertEqual(check(same_twice), "expected_one_command")
        self.assertEqual(check(pkt("push-cert\0x") + b"0000"), "unsupported_command")
        self.assertEqual(check(b"0000"), "expected_one_command")
        self.assertEqual(check(b""), "bad_pktline")
        self.assertEqual(check(b"zzzz"), "bad_pktline")
        self.assertEqual(check(b"00ffshort"), "bad_pktline")
        self.assertEqual(check(b"0003"), "bad_pktline")

    def test_anthropic_preset_pins_model_and_tokens(self):
        rules = ap.anthropic_messages(allowed_models=["m-1"], max_tokens_cap=1000)
        rule = rules[0]
        self.assertEqual(rule.inject, "x-api-key")
        self.assertEqual(rule.upstream_host, "api.anthropic.com")
        self.assertTrue(self.allowed(rules, "POST", "/v1/messages"))
        self.assertFalse(self.allowed(rules, "POST", "/v1/complete"))
        self.assertFalse(self.allowed(rules, "GET", "/v1/messages"))
        self.assertFalse(self.allowed(rules, "POST", "/v1/messages?beta=true"))
        chk = rule.body_check
        self.assertIsNone(chk(json.dumps({"model": "m-1", "max_tokens": 1000, "messages": []}).encode()))
        self.assertEqual(chk(json.dumps({"model": "m-2", "max_tokens": 10}).encode()), "model_not_allowed")
        self.assertEqual(chk(json.dumps({"model": "m-1", "max_tokens": 1001}).encode()), "max_tokens_not_allowed")
        self.assertEqual(chk(json.dumps({"model": "m-1"}).encode()), "max_tokens_not_allowed")
        self.assertEqual(chk(json.dumps({"model": "m-1", "max_tokens": True}).encode()), "max_tokens_not_allowed")
        self.assertEqual(chk(b"not json"), "not_json")
        self.assertEqual(chk(b"[1]"), "not_object")


class BodyCheckThroughProxyTest(unittest.TestCase):
    def test_push_to_other_branch_is_refused_and_allowed_one_forwarded(self):
        up = FakeUpstream()
        self.addCleanup(up.close)
        rules = [
            Rule(r.method, r.path_regex, "127.0.0.1", r.max_body, rule_id=r.rule_id, upstream_port=up.port, credential=r.credential, inject=r.inject, pass_headers=r.pass_headers, query_regex=r.query_regex, body_check=r.body_check)
            for r in ap.github_git_over_http("acme/widgets", "agent/fix-1")
        ]
        audit = []
        p = ScopedProxy(rules, lambda: REAL, audit.append, capability=CAP, upstream_scheme="http")
        p.start()
        self.addCleanup(p.stop)
        old, new = "1" * 40, "2" * 40

        def push(ref, encoding=None):
            body = pkt("%s %s %s\0report-status\n" % (old, new, ref)) + b"0000" + b"PACKDATA"
            headers = {ap.CAPABILITY_HEADER: CAP, "Content-Type": "application/x-git-receive-pack-request"}
            if encoding:
                headers["Content-Encoding"] = encoding
            conn = http.client.HTTPConnection(*p.address, timeout=10)
            try:
                conn.request("POST", "/acme/widgets.git/git-receive-pack", body=body, headers=headers)
                r = conn.getresponse()
                r.read()
                return r.status
            finally:
                conn.close()

        self.assertEqual(push("refs/heads/main"), 403)
        self.assertEqual(push("refs/heads/agent/fix-1", encoding="gzip"), 415)  # cannot inspect an encoded body
        self.assertEqual(up.log, [])
        self.assertEqual(push("refs/heads/agent/fix-1"), 200)
        sent = up.log[-1]
        self.assertTrue(sent["body"].endswith(b"PACKDATA"))
        self.assertEqual(sent["headers"]["authorization"], "Basic " + base64.b64encode(b"x-access-token:" + REAL.encode()).decode())
        self.assertEqual(audit[0]["reason"], "body_rejected:ref_not_allowed")


if __name__ == "__main__":
    unittest.main()

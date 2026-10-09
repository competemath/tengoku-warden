import contextlib
import io
import json
import socket
import tempfile
import threading
import time
import unittest

from warden import egress
from warden.egress import ConnectProxy, EndpointError, parse_audit, parse_endpoint, render_allowed_endpoints

AUDIT = """\
| Process | Domain | IP Address | Port | Status |
| --- | --- | --- | --- | --- |
| node | api.github.com | 140.82.112.5 | 443 | Audited |
| curl | - | 169.254.169.254 | 80 | Audited |
| git | github.com. | 140.82.112.3 | 443 | Audited |
# a comment
- registry.npmjs.org:443
files.pythonhosted.org:443,
allowed-endpoints: >
   objects.githubusercontent.com:443 api.anthropic.com:443
[::1]:80
localhost:8080
nonsense line without endpoint
"""


class EchoServer:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.05)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.threads = []
        self.t = threading.Thread(target=self.run, daemon=True)
        self.t.start()

    def run(self):
        while not self.stop.is_set():
            try:
                c, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            th = threading.Thread(target=self.echo, args=(c,), daemon=True)
            self.threads.append(th)
            th.start()

    def echo(self, c):
        c.settimeout(0.05)
        try:
            while not self.stop.is_set():
                try:
                    d = c.recv(4096)
                except socket.timeout:
                    continue
                if not d:
                    break
                c.sendall(d)
        except OSError:
            pass
        finally:
            c.close()

    def close(self):
        self.stop.set()
        self.t.join(3)
        for th in self.threads:
            th.join(3)
        self.sock.close()


def talk(addr, payload, read=True, timeout=3.0):
    """Send payload to the proxy, return everything received until the peer closes or the timeout hits."""
    s = socket.create_connection(addr, timeout=timeout)
    try:
        s.sendall(payload)
        out = b""
        if read:
            try:
                while True:
                    d = s.recv(4096)
                    if not d:
                        break
                    out += d
            except socket.timeout:
                pass
        return out
    finally:
        s.close()


def connect_req(host, port):
    return ("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n" % (host, port, host, port)).encode()


class EndpointParsingTests(unittest.TestCase):
    def test_valid_endpoints(self):
        self.assertEqual(parse_endpoint("API.GitHub.com:443"), ("api.github.com", 443))
        self.assertEqual(parse_endpoint("github.com.:443"), ("github.com", 443))
        self.assertEqual(parse_endpoint("*.githubusercontent.com:443"), ("*.githubusercontent.com", 443))
        self.assertEqual(parse_endpoint("[2001:db8::1]:443"), ("2001:db8::1", 443))
        self.assertEqual(parse_endpoint("example.com", default_port=443), ("example.com", 443))

    def test_invalid_endpoints(self):
        for bad in ("example.com", "example.com:0", "example.com:70000", "example.com:http", "a b:443", "", "*.com:443", "exa_mple.com:443",
                    "http://example.com:443", "user@example.com:443", "2001:db8::1:443", "-bad.com:443", "a..b.com:443"):
            with self.assertRaises(EndpointError, msg=bad):
                parse_endpoint(bad)

    def test_rejection_reasons(self):
        for host in ("localhost", "metadata.google.internal", "169.254.169.254", "10.0.0.5", "127.0.0.1", "fe80::1", "192.168.1.1"):
            self.assertIsNotNone(egress.endpoint_rejection(host), host)
        for host in ("github.com", "140.82.112.3", "*.githubusercontent.com"):
            self.assertIsNone(egress.endpoint_rejection(host), host)


class AuditTests(unittest.TestCase):
    def test_parse_audit_table_list_and_block(self):
        self.assertEqual(
            parse_audit(AUDIT),
            ["api.anthropic.com:443", "api.github.com:443", "files.pythonhosted.org:443", "github.com:443",
             "objects.githubusercontent.com:443", "registry.npmjs.org:443"],
        )

    def test_metadata_loopback_and_localhost_never_enter(self):
        res = egress.parse_audit_detailed(AUDIT)
        refused = {e: why for e, why in res.rejected}
        self.assertIn("169.254.169.254:80", refused)
        self.assertIn("[::1]:80", refused)
        self.assertIn("localhost:8080", refused)
        self.assertNotIn("169.254.169.254:80", res.allow)

    def test_plain_list_and_dedupe_and_default_port(self):
        self.assertEqual(parse_audit("b.example.com:443\na.example.com:443\nb.example.com:443\n"), ["a.example.com:443", "b.example.com:443"])
        self.assertEqual(parse_audit("a.example.com\n"), [])
        self.assertEqual(parse_audit("a.example.com\n", default_port=443), ["a.example.com:443"])

    def test_garbage_gives_empty_list(self):
        self.assertEqual(parse_audit(""), [])
        self.assertEqual(parse_audit("|||\n| a | b |\nhello world: 99999999\n"), [])

    def test_render(self):
        text = render_allowed_endpoints(["b.example.com:443", "a.example.com:443", "a.example.com:443"], indent=4)
        self.assertEqual(text, "    allowed-endpoints: >\n      a.example.com:443\n      b.example.com:443\n")

    def test_render_refuses_forbidden_and_empty(self):
        with self.assertRaises(EndpointError):
            render_allowed_endpoints(["169.254.169.254:80"])
        with self.assertRaises(EndpointError):
            render_allowed_endpoints([])
        with self.assertRaises(EndpointError):
            render_allowed_endpoints(["nonsense"])


class ProxyTests(unittest.TestCase):
    def setUp(self):
        self.echo = EchoServer()
        self.addCleanup(self.echo.close)
        self.events = []

    def make(self, allow, **kw):
        kw.setdefault("allow_private", True)
        proxy = ConnectProxy(allow, self.events.append, **kw)
        proxy.start()
        self.addCleanup(proxy.stop)
        return proxy

    def decisions(self):
        return [(e["decision"], e.get("host"), e.get("port"), e["reason"]) for e in self.events if e["event"] == "decision"]

    def test_listed_target_tunnels_data(self):
        proxy = self.make(["127.0.0.1:%d" % self.echo.port])
        s = socket.create_connection(proxy.address, timeout=3)
        self.addCleanup(s.close)
        s.sendall(connect_req("127.0.0.1", self.echo.port))
        head = s.recv(4096)
        self.assertTrue(head.startswith(b"HTTP/1.1 200"), head)
        s.sendall(b"hello tunnel")
        got = b""
        while len(got) < 12:
            got += s.recv(64)
        self.assertEqual(got, b"hello tunnel")
        s.close()
        deadline = time.time() + 3
        while time.time() < deadline and not any(e["event"] == "closed" for e in self.events):
            time.sleep(0.02)
        closed = [e for e in self.events if e["event"] == "closed"][0]
        self.assertEqual((closed["bytes_up"], closed["bytes_down"]), (12, 12))
        self.assertEqual(self.decisions(), [("allow", "127.0.0.1", self.echo.port, "listed")])

    def test_unlisted_port_and_host_get_403(self):
        proxy = self.make(["127.0.0.1:%d" % self.echo.port])
        for host, port in (("127.0.0.1", self.echo.port + 1), ("localhost", self.echo.port), ("example.com", 443)):
            out = talk(proxy.address, connect_req(host, port))
            self.assertTrue(out.startswith(b"HTTP/1.1 403"), (host, out))
        self.assertTrue(all(d[0] == "deny" for d in self.decisions()))
        self.assertEqual(len(self.decisions()), 3)

    def test_non_connect_methods_get_403_and_malformed_400(self):
        proxy = self.make(["127.0.0.1:%d" % self.echo.port])
        self.assertTrue(talk(proxy.address, b"GET http://127.0.0.1/ HTTP/1.1\r\nHost: x\r\n\r\n").startswith(b"HTTP/1.1 403"))
        self.assertTrue(talk(proxy.address, b"POST / HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 403"))
        self.assertTrue(talk(proxy.address, b"garbage\r\n\r\n").startswith(b"HTTP/1.1 400"))
        self.assertTrue(talk(proxy.address, b"CONNECT nonsense HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 400"))
        self.assertTrue(talk(proxy.address, b"A" * 20000).startswith(b"HTTP/1.1 400"))

    def test_slow_header_is_cut_off(self):
        proxy = self.make(["127.0.0.1:%d" % self.echo.port], header_timeout=0.3)
        t0 = time.time()
        out = talk(proxy.address, b"CONNECT 127.0.0.1:1 HTTP/1.1\r\n", timeout=3)
        self.assertTrue(out.startswith(b"HTTP/1.1 400"))
        self.assertLess(time.time() - t0, 2.5)

    def test_idle_timeout_closes_tunnel(self):
        proxy = self.make(["127.0.0.1:%d" % self.echo.port], idle_timeout=0.4)
        s = socket.create_connection(proxy.address, timeout=3)
        self.addCleanup(s.close)
        s.sendall(connect_req("127.0.0.1", self.echo.port))
        self.assertTrue(s.recv(4096).startswith(b"HTTP/1.1 200"))
        t0 = time.time()
        self.assertEqual(s.recv(10), b"")
        self.assertLess(time.time() - t0, 2.5)

    def test_total_timeout_closes_busy_tunnel(self):
        proxy = self.make(["127.0.0.1:%d" % self.echo.port], idle_timeout=5, total_timeout=0.5)
        s = socket.create_connection(proxy.address, timeout=3)
        self.addCleanup(s.close)
        s.sendall(connect_req("127.0.0.1", self.echo.port))
        s.recv(4096)
        t0 = time.time()
        closed = False
        while time.time() - t0 < 3:
            try:
                s.sendall(b"x")
                if s.recv(10) == b"":
                    closed = True
                    break
            except OSError:
                closed = True
                break
            time.sleep(0.05)
        self.assertTrue(closed)

    def test_non_public_resolution_refused_unless_allow_private(self):
        proxy = self.make(["internal.example.com:%d" % self.echo.port], allow_private=False, resolver=lambda h, p: ["127.0.0.1"])
        out = talk(proxy.address, connect_req("internal.example.com", self.echo.port))
        self.assertTrue(out.startswith(b"HTTP/1.1 403"))
        self.assertIn("non-public", self.decisions()[0][3])

    def test_metadata_resolution_refused_even_with_allow_private(self):
        proxy = self.make(["rebind.example.com:80"], allow_private=True, resolver=lambda h, p: ["169.254.169.254"])
        out = talk(proxy.address, connect_req("rebind.example.com", 80))
        self.assertTrue(out.startswith(b"HTTP/1.1 403"))
        self.assertIn("metadata", self.decisions()[0][3])

    def test_mixed_resolution_with_one_bad_address_refused(self):
        proxy = self.make(["mixed.example.com:80"], allow_private=True, resolver=lambda h, p: ["127.0.0.1", "169.254.169.254"])
        self.assertTrue(talk(proxy.address, connect_req("mixed.example.com", 80)).startswith(b"HTTP/1.1 403"))

    def test_resolved_name_is_dialled_by_address(self):
        calls = []

        def resolver(h, p):
            calls.append(h)
            return ["127.0.0.1"]

        proxy = self.make(["svc.test:%d" % self.echo.port], resolver=resolver)
        s = socket.create_connection(proxy.address, timeout=3)
        self.addCleanup(s.close)
        s.sendall(connect_req("svc.test", self.echo.port))
        self.assertTrue(s.recv(4096).startswith(b"HTTP/1.1 200"))
        self.assertEqual(calls, ["svc.test"])

    def test_unresolvable_name_refused(self):
        def boom(h, p):
            raise socket.gaierror("no such host")

        proxy = self.make(["nx.example.com:80"], resolver=boom)
        self.assertTrue(talk(proxy.address, connect_req("nx.example.com", 80)).startswith(b"HTTP/1.1 403"))

    def test_wildcard_matches_subdomains_only(self):
        proxy = self.make(["*.corp.test:%d" % self.echo.port], resolver=lambda h, p: ["127.0.0.1"])
        for host, ok in (("a.corp.test", True), ("x.y.corp.test", True), ("corp.test", False), ("evilcorp.test", False), ("a.corp.test.evil.com", False)):
            s = socket.create_connection(proxy.address, timeout=3)
            try:
                s.sendall(connect_req(host, self.echo.port))
                head = s.recv(4096)
            finally:
                s.close()
            self.assertEqual(head.startswith(b"HTTP/1.1 200"), ok, host)

    def test_ip_literal_not_matched_by_wildcard_or_name(self):
        proxy = self.make(["*.corp.test:%d" % self.echo.port, "svc.test:%d" % self.echo.port], resolver=lambda h, p: ["127.0.0.1"])
        self.assertTrue(talk(proxy.address, connect_req("127.0.0.1", self.echo.port)).startswith(b"HTTP/1.1 403"))

    def test_failing_audit_log_means_no_access(self):
        def bad_log(event):
            raise RuntimeError("disk full")

        proxy = ConnectProxy(["127.0.0.1:%d" % self.echo.port], bad_log, allow_private=True)
        proxy.start()
        self.addCleanup(proxy.stop)
        self.assertTrue(talk(proxy.address, connect_req("127.0.0.1", self.echo.port)).startswith(b"HTTP/1.1 403"))

    def test_connection_cap(self):
        proxy = self.make(["127.0.0.1:%d" % self.echo.port], max_conns=1, idle_timeout=5)
        first = socket.create_connection(proxy.address, timeout=3)
        self.addCleanup(first.close)
        first.sendall(connect_req("127.0.0.1", self.echo.port))
        self.assertTrue(first.recv(4096).startswith(b"HTTP/1.1 200"))
        out = talk(proxy.address, connect_req("127.0.0.1", self.echo.port))
        self.assertTrue(out.startswith(b"HTTP/1.1 503"), out)

    def test_upstream_connect_failure_is_502(self):
        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        port = dead.getsockname()[1]
        dead.close()
        proxy = self.make(["127.0.0.1:%d" % port])
        self.assertTrue(talk(proxy.address, connect_req("127.0.0.1", port)).startswith(b"HTTP/1.1 502"))

    def test_constructor_refusals(self):
        with self.assertRaises(ValueError):
            ConnectProxy(["example.com:443"], host="0.0.0.0")
        with self.assertRaises(ValueError):
            ConnectProxy(["example.com:443"], host="192.168.1.5")
        with self.assertRaises(ValueError):
            ConnectProxy([])
        with self.assertRaises(EndpointError):
            ConnectProxy(["127.0.0.1:80"])
        with self.assertRaises(EndpointError):
            ConnectProxy(["169.254.169.254:80"], allow_private=True)
        with self.assertRaises(EndpointError):
            ConnectProxy(["*.com:443"])

    def test_stop_is_idempotent_and_releases_port(self):
        proxy = ConnectProxy(["example.com:443"]).start()
        port = proxy.address[1]
        proxy.stop()
        proxy.stop()
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", port))
        finally:
            s.close()

    def test_context_manager(self):
        with ConnectProxy(["example.com:443"]) as proxy:
            self.assertTrue(talk(proxy.address, connect_req("other.example.org", 443)).startswith(b"HTTP/1.1 403"))


class CliTests(unittest.TestCase):
    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = egress.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_render_from_audit_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt") as fh:
            fh.write(AUDIT)
            fh.flush()
            code, out, err = self.run_main(["--from-audit", fh.name, "--render"])
        self.assertEqual(code, 0)
        self.assertIn("api.github.com:443", out)
        self.assertNotIn("169.254", out)
        self.assertIn("refused from audit", err)

    def test_bad_inputs(self):
        self.assertEqual(self.run_main(["--allow-file", "/nonexistent/allow.txt"])[0], 2)
        self.assertEqual(self.run_main(["--listen", "nonsense", "--allow", "example.com:443"])[0], 2)
        self.assertEqual(self.run_main(["--listen", "0.0.0.0:8080", "--allow", "example.com:443"])[0], 1)
        self.assertEqual(self.run_main([])[0], 1)  # empty allowlist
        self.assertEqual(self.run_main(["--bogus"])[0], 2)
        self.assertEqual(self.run_main(["--render", "--allow", "169.254.169.254:80"])[0], 2)


if __name__ == "__main__":
    unittest.main()

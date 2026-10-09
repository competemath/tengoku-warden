import contextlib
import errno
import hashlib
import io
import json
import os
import socket
import stat
import sys
import tempfile
import unittest
from unittest import mock

from warden import selftest as st
from warden.selftest import ALLOWED, DENIED, ERROR, NA, Context, Probe, Result

GHP = "gh" + "p_" + "x" * 36
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
LINUX = sys.platform.startswith("linux")


def fake(name, status, detail="", **kw):
    return Probe(name, "why " + name, lambda ctx, s=status, d=detail: Result(s, d), **kw)


class HarnessTests(unittest.TestCase):
    def test_all_denied_passes(self):
        rep = st.run_battery([fake("a", DENIED), fake("b", DENIED)])
        self.assertTrue(rep["ok"])
        self.assertEqual(rep["counts"][DENIED], 2)
        self.assertEqual(rep["failed"], [])

    def test_allowed_fails_closed(self):
        rep = st.run_battery([fake("a", DENIED), fake("b", ALLOWED, "got out")])
        self.assertFalse(rep["ok"])
        self.assertEqual(rep["failed"], ["b"])

    def test_error_fails(self):
        self.assertFalse(st.run_battery([fake("a", ERROR, "boom")])["ok"])

    def test_probe_that_raises_is_an_error_not_a_pass(self):
        def boom(ctx):
            raise RuntimeError("kaboom")

        rep = st.run_battery([Probe("x", "w", boom)])
        self.assertFalse(rep["ok"])
        self.assertEqual(rep["results"][0]["status"], ERROR)
        self.assertIn("kaboom", rep["results"][0]["detail"])

    def test_probe_returning_garbage_is_an_error(self):
        rep = st.run_battery([Probe("x", "w", lambda ctx: "denied")])
        self.assertFalse(rep["ok"])
        self.assertEqual(rep["results"][0]["status"], ERROR)

    def test_empty_battery_is_not_ok(self):
        self.assertFalse(st.run_battery([])["ok"])

    def test_duplicate_names_are_an_error(self):
        rep = st.run_battery([fake("a", DENIED), fake("a", DENIED)])
        self.assertFalse(rep["ok"])

    def test_na_passes_unless_require_linux(self):
        probes = [fake("a", DENIED), fake("b", NA, "no feature")]
        self.assertTrue(st.run_battery(probes)["ok"])
        self.assertFalse(st.run_battery(probes, require_linux=True)["ok"])

    def test_linux_only_probe_is_not_run_elsewhere(self):
        ran = []
        probe = Probe("p", "w", lambda ctx: ran.append(1) or Result(DENIED), needs_linux=True)
        rep = st.run_battery([probe], platform_name="darwin")
        self.assertEqual((ran, rep["results"][0]["status"], rep["ok"]), ([], NA, True))
        self.assertFalse(st.run_battery([probe], platform_name="darwin", require_linux=True)["ok"])
        rep = st.run_battery([probe], platform_name="linux")
        self.assertEqual((ran, rep["results"][0]["status"]), ([1], DENIED))

    def test_expect_overrides(self):
        probes = [fake("a", ALLOWED)]
        self.assertTrue(st.run_battery(probes, expect={"a": ALLOWED})["ok"])
        self.assertFalse(st.run_battery(probes, expect={"a": DENIED})["ok"])

    def test_unconfigured_is_error_unless_allowed_and_then_recorded(self):
        p = Probe("c", "w", lambda ctx: st._unconfigured("pass --x"))
        rep = st.run_battery([p])
        self.assertFalse(rep["ok"])
        rep = st.run_battery([p], allow_unconfigured=True)
        self.assertTrue(rep["ok"])
        self.assertEqual(rep["unconfigured_allowed"], ["c"])
        self.assertEqual(rep["results"][0]["status"], NA)

    def test_report_is_json_able_and_has_no_clock_dependence(self):
        ticks = iter(range(0, 1000, 10))
        rep = st.run_battery([fake("a", DENIED)], clock=lambda: next(ticks) / 1000.0)
        json.dumps(rep)
        self.assertEqual(rep["results"][0]["ms"], 10)

    def test_result_validates_status(self):
        with self.assertRaises(ValueError):
            Result("maybe")

    def test_context_is_passed_through(self):
        seen = []
        ctx = Context(bridge_pid=42)
        st.run_battery([Probe("p", "w", lambda c: seen.append(c.bridge_pid) or Result(DENIED))], ctx=ctx)
        self.assertEqual(seen, [42])


class RegistryTests(unittest.TestCase):
    def test_at_least_twenty_unique_documented_probes(self):
        probes = st.default_probes()
        self.assertGreaterEqual(len(probes), 20)
        names = [p.name for p in probes]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(p.why and p.category for p in probes))
        for needed in ("write_etc", "write_root", "write_outside_workspace", "read_host_canary", "read_bridge_environ", "read_parent_environ",
                       "env_has_no_secrets", "sudo_denied", "docker_socket_inaccessible", "ptrace_denied", "tcp_testnet_denied",
                       "tcp_egress_canary_denied", "loopback_other_ports_denied", "dns_denied", "ipv6_egress_denied",
                       "metadata_endpoint_denied", "unix_sockets_denied", "cred_ssh_unreadable", "cred_gh_unreadable",
                       "cred_git_credentials_unreadable", "cred_claude_unreadable", "git_config_has_no_tokens", "nested_userns_denied",
                       "no_unexpected_agent_config", "github_workflow_files_unwritable", "path_has_no_writable_dir", "binaries_not_writable"):
            self.assertIn(needed, names)

    def test_linux_only_probes_are_flagged(self):
        flagged = {p.name for p in st.default_probes() if p.needs_linux}
        for n in ("read_bridge_environ", "read_parent_environ", "ptrace_denied", "nested_userns_denied", "pid1_environ_empty"):
            self.assertIn(n, flagged)


class ConnectClassificationTests(unittest.TestCase):
    def test_immediate_refusals_are_denied(self):
        for code in (errno.ECONNREFUSED, errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EPERM, errno.EACCES):
            self.assertEqual(st.classify_connect_error(OSError(code, "x")).status, DENIED)

    def test_timeout_is_not_denied_by_default(self):
        self.assertEqual(st.classify_connect_error(socket.timeout()).status, ALLOWED)
        self.assertEqual(st.classify_connect_error(OSError(errno.ETIMEDOUT, "x")).status, ALLOWED)
        self.assertEqual(st.classify_connect_error(socket.timeout(), timeout_is_denied=True).status, DENIED)

    def test_unknown_error_is_an_error(self):
        self.assertEqual(st.classify_connect_error(OSError(errno.EMFILE, "x")).status, ERROR)

    def test_tcp_probe_with_fake_connector(self):
        def ok(fam, addr, timeout):
            return None

        def refused(fam, addr, timeout):
            raise ConnectionRefusedError(errno.ECONNREFUSED, "no")

        def slow(fam, addr, timeout):
            raise socket.timeout()

        self.assertEqual(st.tcp_probe(Context(connector=ok), "192.0.2.1", 80).status, ALLOWED)
        self.assertEqual(st.tcp_probe(Context(connector=refused), "192.0.2.1", 80).status, DENIED)
        self.assertEqual(st.tcp_probe(Context(connector=slow), "192.0.2.1", 80).status, ALLOWED)

    def test_network_probes_use_the_connector_and_expected_targets(self):
        seen = []

        def refuse(fam, addr, timeout):
            seen.append((fam, addr))
            raise OSError(errno.ENETUNREACH, "unreachable")

        ctx = Context(connector=refuse, egress_canary="canary.example:9999")
        for probe in (st.probe_tcp_testnet, st.probe_tcp_canary, st.probe_ipv6, st.probe_metadata):
            self.assertEqual(probe(ctx).status, DENIED, probe.__name__)
        addrs = [a[0] if isinstance(a, tuple) else a for _, a in seen]
        self.assertIn("192.0.2.1", addrs)
        self.assertIn("169.254.169.254", addrs)
        self.assertIn("2606:4700:4700::1111", addrs)
        self.assertIn("canary.example", addrs)

    def test_each_network_probe_reports_allowed_when_connection_succeeds(self):
        ctx = Context(connector=lambda f, a, t: None, egress_canary="127.0.0.1:9")
        for probe in (st.probe_tcp_testnet, st.probe_tcp_canary, st.probe_ipv6, st.probe_metadata):
            self.assertEqual(probe(ctx).status, ALLOWED, probe.__name__)

    def test_canary_must_be_configured_and_well_formed(self):
        self.assertTrue(st.probe_tcp_canary(Context()).unconfigured)
        self.assertEqual(st.probe_tcp_canary(Context(egress_canary="nonsense")).status, ERROR)

    def test_real_tcp_probe_against_local_listener(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        self.addCleanup(srv.close)
        self.assertEqual(st.tcp_probe(Context(), "127.0.0.1", port).status, ALLOWED)
        srv.close()
        self.assertEqual(st.tcp_probe(Context(), "127.0.0.1", port).status, DENIED)

    def test_loopback_probe_connects_to_its_own_listener(self):
        res = st.probe_loopback_other_ports(Context())
        self.assertIn(res.status, (ALLOWED, DENIED))
        if res.status == ALLOWED:
            self.assertIn("arbitrary loopback", res.detail)

    def test_loopback_probe_denied_when_connect_refused(self):
        with mock.patch.object(st, "_default_connect", side_effect=ConnectionRefusedError(errno.ECONNREFUSED, "no")):
            self.assertEqual(st.probe_loopback_other_ports(Context()).status, DENIED)
        with mock.patch.object(st, "_default_connect", return_value=None):
            self.assertEqual(st.probe_loopback_other_ports(Context()).status, ALLOWED)


class DnsTests(unittest.TestCase):
    def test_loopback_only_answer_is_proxy_only(self):
        self.assertEqual(st.probe_dns(Context(dns_canary="localhost")).status, DENIED)

    def test_public_answer_is_allowed(self):
        fake_answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        with mock.patch.object(socket, "getaddrinfo", return_value=fake_answer):
            self.assertEqual(st.probe_dns(Context()).status, ALLOWED)
        with mock.patch.object(socket, "getaddrinfo", return_value=fake_answer):
            self.assertEqual(st.probe_dns(Context(dns_proxy_addrs=("93.184.216.34",))).status, DENIED)

    def test_failure_is_denied(self):
        with mock.patch.object(socket, "getaddrinfo", side_effect=socket.gaierror(-2, "nope")):
            self.assertEqual(st.probe_dns(Context()).status, DENIED)


class FilesystemProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = os.path.realpath(self.tmp.name)

    def ctx(self, **kw):
        kw.setdefault("workspace", self.root)
        kw.setdefault("system_homes", False)
        kw.setdefault("env", {"HOME": self.root, "PATH": "/usr/bin:/bin"})
        return Context(**kw)

    @unittest.skipIf(IS_ROOT, "running as root")
    def test_write_etc_and_root_denied_for_unprivileged(self):
        for active in (False, True):
            self.assertEqual(st.probe_write_etc(self.ctx(active_writes=active)).status, DENIED)
            self.assertEqual(st.probe_write_root(self.ctx(active_writes=active)).status, DENIED)

    def test_write_attempt_creates_and_removes_file(self):
        self.assertIsNotNone(st._write_attempt(self.root, self.ctx(active_writes=True)))
        self.assertEqual(os.listdir(self.root), [])
        self.assertIsNotNone(st._write_attempt(self.root, self.ctx(active_writes=False)))
        self.assertIsNone(st._write_attempt(os.path.join(self.root, "missing"), self.ctx()))

    @unittest.skipIf(IS_ROOT, "running as root")
    def test_write_attempt_on_readonly_dir_is_none(self):
        ro = os.path.join(self.root, "ro")
        os.mkdir(ro, 0o500)
        self.addCleanup(os.chmod, ro, 0o700)
        for active in (False, True):
            self.assertIsNone(st._write_attempt(ro, self.ctx(active_writes=active)))

    def test_write_outside_workspace_detects_writable_sibling(self):
        ws = os.path.join(self.root, "ws")
        os.mkdir(ws)
        res = st.probe_write_outside_workspace(self.ctx(workspace=ws, writable_ok=()))
        self.assertEqual(res.status, ALLOWED)  # the parent (self.root) is writable
        res = st.probe_write_outside_workspace(self.ctx(workspace=ws, writable_ok=(self.root,)))
        self.assertIn(res.status, (ALLOWED, DENIED))  # other system paths decide; the temp parent no longer counts
        self.assertNotIn(self.root + ",", res.detail)

    def test_host_canary(self):
        canary = os.path.join(self.root, "canary")
        with open(canary, "w") as fh:
            fh.write("host secret")
        self.assertEqual(st.probe_host_canary(self.ctx(canary_files=(canary,))).status, ALLOWED)
        self.assertEqual(st.probe_host_canary(self.ctx(canary_files=(os.path.join(self.root, "nope"),))).status, DENIED)
        self.assertTrue(st.probe_host_canary(self.ctx()).unconfigured)
        res = st.probe_host_canary(self.ctx(canary_files=(canary,)))
        self.assertNotIn("host secret", res.detail)

    @unittest.skipIf(IS_ROOT, "running as root")
    def test_unreadable_canary_is_denied(self):
        canary = os.path.join(self.root, "canary")
        open(canary, "w").close()
        os.chmod(canary, 0)
        self.addCleanup(os.chmod, canary, 0o600)
        self.assertEqual(st.probe_host_canary(self.ctx(canary_files=(canary,))).status, DENIED)

    def test_proc_environ_probes_with_fake_proc(self):
        proc = os.path.join(self.root, "proc")
        os.makedirs(os.path.join(proc, "123"))
        with open(os.path.join(proc, "123", "environ"), "wb") as fh:
            fh.write(b"SECRET=1\x00")
        os.makedirs(os.path.join(proc, "1"))
        with open(os.path.join(proc, "1", "environ"), "wb") as fh:
            fh.write(b"")
        ctx = self.ctx(proc_root=proc, bridge_pid=123)
        self.assertEqual(st.probe_bridge_environ(ctx).status, ALLOWED)
        self.assertEqual(st.probe_bridge_environ(self.ctx(proc_root=proc, bridge_pid=999)).status, DENIED)
        self.assertTrue(st.probe_bridge_environ(self.ctx(proc_root=proc)).unconfigured)
        self.assertEqual(st.probe_pid1_environ(ctx).status, DENIED)  # empty
        with open(os.path.join(proc, "1", "environ"), "wb") as fh:
            fh.write(b"A=b\x00")
        self.assertEqual(st.probe_pid1_environ(ctx).status, ALLOWED)
        self.assertEqual(st.probe_pid1_environ(self.ctx(proc_root=os.path.join(self.root, "none"))).status, DENIED)

    def test_userns_probe_with_fake_proc(self):
        proc = os.path.join(self.root, "proc")
        os.makedirs(os.path.join(proc, "self", "ns"))
        link = os.path.join(proc, "self", "ns", "user")
        try:
            os.symlink("user:[4026531837]", link)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        self.assertEqual(st.probe_userns_differs(self.ctx(proc_root=proc, host_userns="user:[4026531837]")).status, ALLOWED)
        self.assertEqual(st.probe_userns_differs(self.ctx(proc_root=proc, host_userns="user:[1]")).status, DENIED)
        self.assertTrue(st.probe_userns_differs(self.ctx(proc_root=proc)).unconfigured)

    def test_caps_probe_with_fake_proc(self):
        proc = os.path.join(self.root, "proc")
        os.makedirs(os.path.join(proc, "self"))
        status = os.path.join(proc, "self", "status")
        with open(status, "w") as fh:
            fh.write("Name:\tx\nCapEff:\t0000000000000000\n")
        self.assertEqual(st.probe_no_caps(self.ctx(proc_root=proc)).status, DENIED)
        with open(status, "w") as fh:
            fh.write("CapEff:\t000001ffffffffff\n")
        self.assertEqual(st.probe_no_caps(self.ctx(proc_root=proc)).status, ALLOWED)
        with open(status, "w") as fh:
            fh.write("nothing here\n")
        self.assertEqual(st.probe_no_caps(self.ctx(proc_root=proc)).status, ERROR)

    def test_env_secret_probe(self):
        dirty = self.ctx(env={"PATH": "/usr/bin", "GH_TOKEN": GHP})
        res = st.probe_env_secrets(dirty)
        self.assertEqual(res.status, ALLOWED)
        self.assertIn("GH_TOKEN", res.detail)
        self.assertNotIn(GHP, res.detail)
        self.assertEqual(st.probe_env_secrets(self.ctx(env={"PATH": "/usr/bin", "GH_TOKEN": GHP}, allowed_env_names=("GH_TOKEN",))).status, DENIED)
        self.assertEqual(st.probe_env_secrets(self.ctx(env={"PATH": "/usr/bin", "LANG": "C"})).status, DENIED)
        self.assertEqual(st.probe_env_secrets(self.ctx(env={"NOTE": GHP})).status, ALLOWED)

    def test_credential_probes(self):
        home = os.path.join(self.root, "home")
        os.makedirs(os.path.join(home, ".ssh"))
        os.makedirs(os.path.join(home, ".config", "gh"))
        open(os.path.join(home, ".git-credentials"), "w").close()
        os.makedirs(os.path.join(home, ".claude"))
        open(os.path.join(home, ".claude", ".credentials.json"), "w").close()
        open(os.path.join(home, ".netrc"), "w").close()
        ctx = self.ctx(env={"HOME": home, "PATH": "/usr/bin"})
        for probe in (st.probe_cred_ssh, st.probe_cred_gh, st.probe_cred_git, st.probe_cred_claude, st.probe_cred_misc):
            self.assertEqual(probe(ctx).status, ALLOWED, probe.__name__)
        empty = os.path.join(self.root, "empty")
        os.mkdir(empty)
        clean = self.ctx(env={"HOME": empty, "PATH": "/usr/bin"})
        for probe in (st.probe_cred_ssh, st.probe_cred_gh, st.probe_cred_git, st.probe_cred_claude, st.probe_cred_misc):
            self.assertEqual(probe(clean).status, DENIED, probe.__name__)
        allowed = self.ctx(env={"HOME": home, "PATH": "/usr/bin"}, allowed_readable=(os.path.join(home, ".claude"),))
        self.assertEqual(st.probe_cred_claude(allowed).status, DENIED)
        self.assertEqual(st.probe_cred_ssh(allowed).status, ALLOWED)

    def test_extra_home_dirs_are_inspected(self):
        runner = os.path.join(self.root, "runner")
        os.makedirs(os.path.join(runner, ".ssh"))
        ctx = self.ctx(home_dirs=(runner,), env={"HOME": os.path.join(self.root, "agent"), "PATH": "/usr/bin"})
        self.assertEqual(st.probe_cred_ssh(ctx).status, ALLOWED)

    def test_git_token_probe(self):
        ws = os.path.join(self.root, "ws")
        os.makedirs(os.path.join(ws, ".git"))
        cfg = os.path.join(ws, ".git", "config")
        with open(cfg, "w") as fh:
            fh.write("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://github.com/o/r\n")
        ctx = self.ctx(workspace=ws)
        self.assertEqual(st.probe_git_tokens(ctx).status, DENIED)
        for bad in ('[http "https://github.com/"]\n\textraheader = AUTHORIZATION: basic abc\n',
                    '[remote "o"]\n\turl = https://x-access-token:' + 'abc' + '@github.com/o/r\n',
                    '[credential]\n\thelper = store --file=/x\n\tpassword = %s\n' % GHP,
                    '[remote "o"]\n\turl = https://user:' + 'pw' + '@example.com/r\n'):
            with open(cfg, "w") as fh:
                fh.write(bad)
            res = st.probe_git_tokens(ctx)
            self.assertEqual(res.status, ALLOWED, bad)
            self.assertNotIn(GHP, res.detail)

    def test_git_token_probe_follows_gitdir_file(self):
        real = os.path.join(self.root, "real.git")
        os.makedirs(real)
        with open(os.path.join(real, "config"), "w") as fh:
            fh.write("[http]\n\textraheader = AUTHORIZATION: basic abc\n")
        ws = os.path.join(self.root, "wt")
        os.makedirs(ws)
        with open(os.path.join(ws, ".git"), "w") as fh:
            fh.write("gitdir: %s\n" % real)
        self.assertEqual(st.probe_git_tokens(self.ctx(workspace=ws)).status, ALLOWED)

    def test_agent_config_probe(self):
        ws = os.path.join(self.root, "a", "ws")
        os.makedirs(ws)
        ctx = self.ctx(workspace=ws)
        self.assertEqual(st.probe_agent_config(ctx).status, DENIED)
        md = os.path.join(ws, "CLAUDE.md")
        with open(md, "w") as fh:
            fh.write("be nice")
        self.assertEqual(st.probe_agent_config(ctx).status, ALLOWED)
        digest = hashlib.sha256(b"be nice").hexdigest()
        self.assertEqual(st.probe_agent_config(self.ctx(workspace=ws, allowed_agent_files={"CLAUDE.md": digest})).status, DENIED)
        self.assertEqual(st.probe_agent_config(self.ctx(workspace=ws, allowed_agent_files={md: None})).status, DENIED)
        self.assertEqual(st.probe_agent_config(self.ctx(workspace=ws, allowed_agent_files={"CLAUDE.md": "0" * 64})).status, ALLOWED)

    def test_agent_config_hooks_and_parents_and_home(self):
        ws = os.path.join(self.root, "a", "ws")
        os.makedirs(os.path.join(ws, ".claude"))
        with open(os.path.join(ws, ".claude", "settings.json"), "w") as fh:
            fh.write('{"hooks": {}}')
        res = st.probe_agent_config(self.ctx(workspace=ws))
        self.assertEqual(res.status, ALLOWED)
        self.assertIn("settings.json", res.detail)
        os.remove(os.path.join(ws, ".claude", "settings.json"))
        os.rmdir(os.path.join(ws, ".claude"))
        self.assertEqual(st.probe_agent_config(self.ctx(workspace=ws)).status, DENIED)
        with open(os.path.join(self.root, "a", "CLAUDE.md"), "w") as fh:
            fh.write("parent instructions")
        self.assertEqual(st.probe_agent_config(self.ctx(workspace=ws)).status, ALLOWED)
        os.remove(os.path.join(self.root, "a", "CLAUDE.md"))
        os.makedirs(os.path.join(self.root, "home", ".claude"))
        with open(os.path.join(self.root, "home", ".claude", "settings.json"), "w") as fh:
            fh.write("{}")
        ctx = self.ctx(workspace=ws, env={"HOME": os.path.join(self.root, "home"), "PATH": "/usr/bin"})
        self.assertEqual(st.probe_agent_config(ctx).status, ALLOWED)

    def test_github_files_probe(self):
        f = os.path.join(self.root, "GITHUB_ENV")
        open(f, "w").close()
        self.assertEqual(st.probe_github_files(self.ctx(github_files=(f,))).status, ALLOWED)
        self.assertEqual(st.probe_github_files(self.ctx(env={"GITHUB_ENV": f})).status, ALLOWED)
        self.assertEqual(st.probe_github_files(self.ctx(github_files=(os.path.join(self.root, "absent"),))).status, DENIED)
        self.assertEqual(st.probe_github_files(self.ctx()).status, NA)
        res = st.probe_github_files(self.ctx(env={"GITHUB_ACTIONS": "true"}))
        self.assertTrue(res.unconfigured)

    @unittest.skipIf(IS_ROOT, "running as root")
    def test_github_file_readonly_is_denied(self):
        f = os.path.join(self.root, "GITHUB_PATH")
        open(f, "w").close()
        os.chmod(f, 0o444)
        self.addCleanup(os.chmod, f, 0o600)
        self.assertEqual(st.probe_github_files(self.ctx(github_files=(f,))).status, DENIED)

    def test_path_probe(self):
        writable = os.path.join(self.root, "bin")
        os.mkdir(writable)
        self.assertEqual(st.probe_path_dirs(self.ctx(env={"PATH": writable + ":/usr/bin"})).status, ALLOWED)
        self.assertEqual(st.probe_path_dirs(self.ctx(env={"PATH": "/usr/bin::/bin"})).status, ALLOWED)
        self.assertEqual(st.probe_path_dirs(self.ctx(env={"PATH": "relative/bin"})).status, ALLOWED)
        self.assertEqual(st.probe_path_dirs(self.ctx(env={})).status, DENIED)

    @unittest.skipIf(IS_ROOT or not os.path.isdir("/usr/bin") or os.access("/usr/bin", os.W_OK), "needs unwritable /usr/bin")
    def test_path_probe_system_dirs_are_fine(self):
        self.assertEqual(st.probe_path_dirs(self.ctx(env={"PATH": "/usr/bin:/bin"})).status, DENIED)

    def test_binaries_probe_flags_writable_binary(self):
        exe = os.path.join(self.root, "tool")
        with open(exe, "w") as fh:
            fh.write("#!/bin/sh\n")
        os.chmod(exe, 0o755)
        res = st.probe_binaries(self.ctx(binaries=(exe,)))
        self.assertEqual(res.status, ALLOWED)
        self.assertIn("tool", res.detail)

    def test_unix_socket_probe(self):
        if not hasattr(socket, "AF_UNIX"):
            self.skipTest("no AF_UNIX")
        path = os.path.join(tempfile.mkdtemp(dir="/tmp"), "s")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        srv.listen(1)
        self.addCleanup(srv.close)
        self.addCleanup(os.rmdir, os.path.dirname(path))
        self.addCleanup(os.unlink, path)
        res = st.probe_unix_sockets(self.ctx(env={"HOME": self.root, "PATH": "/usr/bin", "SSH_AUTH_SOCK": path}))
        self.assertEqual(res.status, ALLOWED)
        self.assertIn(path, res.detail)
        res = st.probe_unix_sockets(self.ctx(env={"HOME": self.root, "PATH": "/usr/bin", "SSH_AUTH_SOCK": path + ".gone"}))
        self.assertIn(res.status, (DENIED, ALLOWED))  # a real docker socket on the machine may answer

    def test_group_probe(self):
        with mock.patch.object(st, "_group_names", return_value=["staff", "docker"]):
            self.assertEqual(st.probe_privileged_groups(Context()).status, ALLOWED)
        with mock.patch.object(st, "_group_names", return_value=["agent"]):
            self.assertEqual(st.probe_privileged_groups(Context()).status, DENIED)

    def test_uid_probes(self):
        with mock.patch.object(os, "geteuid", return_value=0):
            self.assertEqual(st.probe_not_root(Context()).status, ALLOWED)
        with mock.patch.object(os, "geteuid", return_value=1001):
            self.assertEqual(st.probe_not_root(Context()).status, DENIED)
            self.assertEqual(st.probe_running_as_agent(Context(expect_uid=1001)).status, DENIED)
            self.assertEqual(st.probe_running_as_agent(Context(expect_uid=1002)).status, ALLOWED)
            self.assertEqual(st.probe_running_as_agent(Context()).status, NA)

    def test_sudo_probe_outcomes(self):
        class R:
            def __init__(self, code):
                self.returncode = code

        with mock.patch.object(st.subprocess, "run", return_value=R(0)):
            self.assertEqual(st.probe_sudo(Context()).status, ALLOWED)
        with mock.patch.object(st.subprocess, "run", return_value=R(1)):
            self.assertEqual(st.probe_sudo(Context()).status, DENIED)
        with mock.patch.object(st.subprocess, "run", side_effect=FileNotFoundError()):
            self.assertEqual(st.probe_sudo(Context()).status, DENIED)
        with mock.patch.object(st.subprocess, "run", side_effect=st.subprocess.TimeoutExpired("sudo", 10)):
            self.assertEqual(st.probe_sudo(Context()).status, ERROR)

    def test_docker_socket_probe_uses_access(self):
        with mock.patch.object(st.os.path, "exists", return_value=True), mock.patch.object(st.os, "access", return_value=True):
            self.assertEqual(st.probe_docker_socket(self.ctx()).status, ALLOWED)
        with mock.patch.object(st.os.path, "exists", return_value=True), mock.patch.object(st.os, "access", return_value=False):
            self.assertEqual(st.probe_docker_socket(self.ctx()).status, DENIED)


@unittest.skipUnless(LINUX, "Linux-only probes")
class LinuxProbeSmokeTests(unittest.TestCase):
    def test_probes_return_valid_results(self):
        ctx = Context(system_homes=False)
        for probe in (st.probe_no_caps, st.probe_ptrace, st.probe_nested_userns, st.probe_parent_environ, st.probe_pid1_environ):
            self.assertIn(probe(ctx).status, st.STATUSES, probe.__name__)


class CliTests(unittest.TestCase):
    def run_main(self, argv, probes=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = st.main(argv, probes=probes)
        return code, out.getvalue(), err.getvalue()

    def test_list(self):
        code, out, _ = self.run_main(["--list"])
        self.assertEqual(code, 0)
        self.assertGreaterEqual(len(out.strip().splitlines()), 20)
        self.assertIn("write_etc", out)

    def test_exit_codes_fail_closed(self):
        ok = [fake("a", DENIED)]
        bad = [fake("a", DENIED), fake("b", ALLOWED)]
        self.assertEqual(self.run_main([], ok)[0], 0)
        self.assertEqual(self.run_main([], bad)[0], 1)
        self.assertEqual(self.run_main([], [fake("a", ERROR)])[0], 1)
        self.assertEqual(self.run_main(["--bogus"], ok)[0], 2)

    def test_require_linux_turns_na_into_failure(self):
        probes = [fake("a", DENIED), Probe("l", "w", lambda c: Result(DENIED), needs_linux=True)]
        code_here = self.run_main([], probes)[0]
        self.assertEqual(code_here, 0)
        if not LINUX:
            self.assertEqual(self.run_main(["--require-linux"], probes)[0], 1)

    def test_json_output_and_bad_args(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "report.json")
            code, _, _ = self.run_main(["--json", path, "--no-active-writes"], [fake("a", DENIED), fake("b", ALLOWED)])
            self.assertEqual(code, 1)
            with open(path) as fh:
                rep = json.load(fh)
            self.assertFalse(rep["ok"])
            self.assertEqual(rep["failed"], ["b"])
        self.assertEqual(self.run_main(["--egress-canary", "nonsense"], [fake("a", DENIED)])[0], 2)
        self.assertEqual(self.run_main(["--allow-agent-file", "CLAUDE.md=zz"], [fake("a", DENIED)])[0], 2)
        self.assertEqual(self.run_main(["--only", "missing"], [fake("a", DENIED)])[0], 2)

    def test_options_reach_the_context(self):
        seen = {}

        def grab(ctx):
            seen.update(canary=ctx.canary_files, pid=ctx.bridge_pid, canary_net=ctx.egress_canary, ports=ctx.allowed_ports,
                        active=ctx.active_writes, files=dict(ctx.allowed_agent_files), uid=ctx.expect_uid)
            return Result(DENIED)

        digest = "ab" * 32
        code, _, _ = self.run_main(["--canary-file", "/a", "--canary-file", "/b", "--bridge-pid", "77", "--egress-canary", "h.example:99",
                                    "--allow-port", "8080", "--allow-port", "3128", "--allow-agent-file", "CLAUDE.md=" + digest,
                                    "--expect-uid", "1001"], [Probe("g", "w", grab)])
        self.assertEqual(code, 0)
        self.assertEqual(seen["canary"], ("/a", "/b"))
        self.assertEqual((seen["pid"], seen["canary_net"], seen["ports"]), (77, "h.example:99", (8080, 3128)))
        self.assertTrue(seen["active"])
        self.assertEqual(seen["files"], {"CLAUDE.md": digest})
        self.assertEqual(seen["uid"], 1001)

    def test_partial_run_never_authorises(self):
        code, _, _ = self.run_main(["--only", "a"], [fake("a", DENIED), fake("b", DENIED)])
        self.assertEqual(code, 1)

    def test_allow_unconfigured_flag(self):
        p = Probe("c", "w", lambda ctx: st._unconfigured("x"))
        self.assertEqual(self.run_main([], [p])[0], 1)
        self.assertEqual(self.run_main(["--allow-unconfigured"], [p])[0], 0)


if __name__ == "__main__":
    unittest.main()

import shlex
import shutil
import subprocess
import unittest
from dataclasses import replace

from warden import jail
from warden.jail import JailSpec, JailSpecError

GHP = "gh" + "p_" + "x" * 36


def base(**kw):
    args = dict(workspace="/srv/warden/ws", command=("/usr/bin/claude", "-p", "hi"))
    args.update(kw)
    return JailSpec(**args)


def has_problem(spec, needle):
    return any(needle in p for p in jail.jail_problems(spec))


def bind_pairs(argv, flag):
    out = []
    for i, tok in enumerate(argv):
        if tok == flag:
            out.append((argv[i + 1], argv[i + 2]))
    return out


class SpecValidationTests(unittest.TestCase):
    def test_default_spec_is_valid(self):
        self.assertEqual(jail.jail_problems(base()), [])

    def test_workspace_rules(self):
        for ws in ("relative/dir", "/", "/srv/../etc", "/usr/local/ws", "/tmp/ws", "/proc/x", "/etc/ws"):
            self.assertTrue(has_problem(base(workspace=ws), "workspace"), ws)

    def test_command_required(self):
        self.assertTrue(has_problem(base(command=()), "command"))
        self.assertTrue(has_problem(base(command=("a", "")), "command"))

    def test_sensitive_binds_refused(self):
        for kw in ({"ro_binds": ("/",)}, {"ro_binds": ("/home",)}, {"tool_binds": ("/proc",)}, {"tool_binds": ("/home/runner/.ssh",)},
                   {"tool_binds": ("/var/run/docker.sock",)}, {"ro_binds": ("rel",)}, {"tool_binds": ("/opt/../etc",)},
                   {"channel_binds": ("/root",)}, {"channel_binds": ("/home/runner/.config/gh",)}):
            self.assertTrue(has_problem(base(**kw), "bind"), kw)
        self.assertEqual(jail.jail_problems(base(tool_binds=("/home/runner/.nvm/versions/node/v22",), channel_binds=("/run/warden-sock",))), [])

    def test_whole_etc_refused_individual_files_ok(self):
        self.assertTrue(has_problem(base(etc_binds=("/etc",)), "etc_binds"))
        self.assertTrue(has_problem(base(etc_binds=("/usr/x",)), "etc_binds"))
        self.assertEqual(jail.jail_problems(base(etc_binds=("/etc/ssl",))), [])

    def test_path_dirs_rules(self):
        self.assertTrue(has_problem(base(path_dirs=("/srv/warden/ws/bin", "/usr/bin")), "writable"))
        self.assertTrue(has_problem(base(path_dirs=("/tmp/bin",)), "writable"))
        self.assertTrue(has_problem(base(path_dirs=("bin",)), "PATH"))
        self.assertTrue(has_problem(base(path_dirs=("/opt/unbound",)), "not inside a read-only bind"))
        self.assertTrue(has_problem(base(path_dirs=()), "path_dirs"))
        self.assertEqual(jail.jail_problems(base(path_dirs=("/opt/tools/bin",), tool_binds=("/opt/tools",))), [])

    def test_env_rules(self):
        self.assertTrue(has_problem(base(env={"GH_TOKEN": "abc"}), "secret"))
        self.assertTrue(has_problem(base(env={"NOTE": GHP}), "secret"))
        self.assertTrue(has_problem(base(env={"PATH": "/x"}), "set by the jail"))
        self.assertTrue(has_problem(base(env={"BAD NAME": "x"}), "invalid"))
        self.assertEqual(jail.jail_problems(base(env={"GH_TOKEN": "abc"}, secret_ok=("GH_TOKEN",))), [])
        self.assertEqual(jail.jail_problems(base(env={"WARDEN_RUN": "1"})), [])

    def test_network_rules(self):
        self.assertTrue(has_problem(base(network=True), "uid"))
        self.assertEqual(jail.jail_problems(base(network=True, uid=1001, allowed_loopback_ports=(8080,))), [])
        self.assertEqual(jail.jail_problems(base(network=True, network_unrestricted_ok=True)), [])
        self.assertTrue(has_problem(base(allowed_loopback_ports=(8080,)), "network=True"))
        self.assertTrue(has_problem(base(network=True, uid=1001, allowed_loopback_ports=(0,)), "port"))
        self.assertTrue(has_problem(base(network=True, uid=1001, allowed_loopback_ports=(80, 80)), "twice"))
        self.assertTrue(has_problem(base(network=True, uid=0), "uid"))

    def test_user_and_hostname(self):
        self.assertTrue(has_problem(base(user="Bad User"), "user"))
        self.assertTrue(has_problem(base(hostname="a b"), "hostname"))

    def test_bwrap_argv_raises_on_problems(self):
        with self.assertRaises(JailSpecError) as cm:
            jail.bwrap_argv(base(workspace="/"))
        self.assertTrue(cm.exception.problems)


class BwrapTests(unittest.TestCase):
    def test_shape_and_flags(self):
        argv = jail.bwrap_argv(base())
        self.assertEqual(argv[:3], ["env", "-i", "/usr/bin/bwrap"])
        for flag in ("--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-net", "--unshare-uts", "--unshare-cgroup",
                     "--disable-userns", "--die-with-parent", "--new-session", "--remount-ro"):
            self.assertIn(flag, argv)
        self.assertNotIn("--unshare-all", argv)
        self.assertNotIn("--unshare-user-try", argv)
        self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")
        self.assertEqual(argv[argv.index("--tmpfs") + 1], "/")
        self.assertEqual(argv[-3:], ["/usr/bin/claude", "-p", "hi"])
        self.assertEqual(argv[argv.index("--") + 1], "/usr/bin/claude")

    def test_remount_ro_after_every_mount_and_chdir_to_workspace(self):
        argv = jail.bwrap_argv(base(tool_binds=("/opt/node",), channel_binds=("/run/sock",)))
        ro = argv.index("--remount-ro")
        for flag in ("--ro-bind", "--ro-bind-try", "--bind", "--proc", "--dev", "--tmpfs", "--dir"):
            for i, tok in enumerate(argv):
                if tok == flag and flag != "--tmpfs" or (tok == flag and argv[i + 1] != "/"):
                    self.assertLess(i, ro, flag)
        self.assertEqual(argv[argv.index("--chdir") + 1], "/srv/warden/ws")
        self.assertEqual(argv[ro + 1], "/")

    def test_only_workspace_and_declared_channels_are_writable(self):
        argv = jail.bwrap_argv(base())
        self.assertEqual(bind_pairs(argv, "--bind"), [("/srv/warden/ws", "/srv/warden/ws")])
        argv = jail.bwrap_argv(base(channel_binds=("/run/sock",)))
        self.assertEqual(bind_pairs(argv, "--bind"), [("/srv/warden/ws", "/srv/warden/ws"), ("/run/sock", "/run/sock")])
        for src, dst in bind_pairs(argv, "--ro-bind-try"):
            self.assertEqual(src, dst)
            self.assertNotIn(src, ("/", "/etc", "/home", "/root", "/proc"))

    def test_network_flag_follows_spec(self):
        self.assertIn("--unshare-net", jail.bwrap_argv(base()))
        net = jail.bwrap_argv(base(network=True, uid=1001))
        self.assertNotIn("--unshare-net", net)
        self.assertIn("--unshare-user", net)

    def test_env_goes_through_setenv_not_the_launcher(self):
        argv = jail.bwrap_argv(base(env={"WARDEN_RUN": "7"}))
        sets = {argv[i + 1]: argv[i + 2] for i, t in enumerate(argv) if t == "--setenv"}
        self.assertEqual(sets["WARDEN_RUN"], "7")
        self.assertEqual(sets["PATH"], "/usr/local/bin:/usr/bin:/bin")
        self.assertEqual(sets["HOME"], "/tmp/home")
        self.assertNotIn("WARDEN_RUN=7", argv)

    def test_assert_userns_toggle_and_no_env_i(self):
        self.assertIn("--assert-userns-disabled", jail.bwrap_argv(base()))
        self.assertNotIn("--assert-userns-disabled", jail.bwrap_argv(base(assert_userns_disabled=False)))
        self.assertEqual(jail.bwrap_argv(base(), env_i=False)[0], "/usr/bin/bwrap")

    def test_argv_elements_are_not_split_or_interpreted(self):
        weird = "a b; $(id) 'q'"
        argv = jail.bwrap_argv(base(command=("/bin/echo", weird)))
        self.assertEqual(argv[-1], weird)


class EgressTests(unittest.TestCase):
    def test_rules_for_v4_and_v6(self):
        lines = jail.uid_egress_rules(1001, [8080, 3128, 8080])
        text = "\n".join(lines)
        self.assertIn("iptables -w -A WARDEN_1001 -p tcp -d 127.0.0.1/32 --dport 3128 -j ACCEPT", text)
        self.assertIn("--dport 8080 -j ACCEPT", text)
        self.assertEqual(text.count("--dport 8080"), 1)
        self.assertIn("ip6tables -w -A WARDEN_1001 -j REJECT", text)
        self.assertIn("-m owner --uid-owner 1001", text)
        self.assertIn("169.254.169.254/32", text)
        self.assertIn("fe80::/10", text)

    def test_reject_is_last_rule_of_each_chain_and_no_accept_for_other_hosts(self):
        lines = jail.uid_egress_rules(1001, [8080])
        for tool in ("iptables", "ip6tables"):
            appends = [l for l in lines if l.startswith(tool + " -w -A WARDEN_1001")]
            self.assertTrue(appends[-1].endswith("-j REJECT") and " -d " not in appends[-1])
        for l in lines:
            if "-j ACCEPT" in l:
                self.assertIn("127.0.0.1/32", l)
                self.assertTrue(l.startswith("iptables"))

    def test_metadata_rejected_before_any_accept(self):
        lines = [l for l in jail.uid_egress_rules(1001, [80]) if l.startswith("iptables -w -A")]
        first_accept = next(i for i, l in enumerate(lines) if "ACCEPT" in l)
        meta = next(i for i, l in enumerate(lines) if "169.254.169.254" in l)
        self.assertLess(meta, first_accept)

    def test_no_ports_means_no_accept(self):
        self.assertFalse(any("ACCEPT" in l for l in jail.uid_egress_rules(1001, [])))

    def test_ipv6_loopback_only_on_request(self):
        self.assertFalse(any("::1" in l for l in jail.uid_egress_rules(1001, [80])))
        self.assertTrue(any("::1/128" in l and "ACCEPT" in l for l in jail.uid_egress_rules(1001, [80], allow_ipv6_loopback=True)))

    def test_bad_uid_and_port_refused(self):
        for uid in (0, -5, "root", "1001; reboot", True, None):
            with self.assertRaises(JailSpecError, msg=repr(uid)):
                jail.uid_egress_rules(uid, [80])
            with self.assertRaises(JailSpecError, msg=repr(uid)):
                jail.uid_egress_teardown(uid)
        for port in (0, 70000, "80", True):
            with self.assertRaises(JailSpecError, msg=repr(port)):
                jail.uid_egress_rules(1001, [port])

    def test_uid_variable_accepted(self):
        text = "\n".join(jail.uid_egress_rules(jail.UID_VAR, [80]))
        self.assertIn("--uid-owner $AGENT_UID", text)
        self.assertIn("WARDEN_AGENT_UID", text)

    def test_teardown_removes_jump_chain_for_both_families(self):
        text = "\n".join(jail.uid_egress_teardown(1001))
        for tool in ("iptables", "ip6tables"):
            self.assertIn("%s -w -D OUTPUT -m owner --uid-owner 1001 -j WARDEN_1001" % tool, text)
            self.assertIn("%s -w -F WARDEN_1001" % tool, text)
            self.assertIn("%s -w -X WARDEN_1001" % tool, text)


class UserScriptTests(unittest.TestCase):
    def test_script_content(self):
        s = jail.agent_user_script("agent", "/srv/warden/ws")
        for needle in ("set -euo pipefail", "useradd --system", "hidepid=2", "sudo -n -l -U", "chmod o-rwx", "install -d -o", "gpasswd -d"):
            self.assertIn(needle, s)
        for g in ("docker", "sudo", "admin"):
            self.assertIn(g, s)

    @unittest.skipUnless(shutil.which("bash"), "bash not available")
    def test_script_parses_with_bash(self):
        for ws in ("/srv/warden/ws", "/srv/a b/ws$(id)'x"):
            s = jail.agent_user_script("agent", ws)
            r = subprocess.run(["bash", "-n"], input=s, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("AGENT_WS=/srv/a b", s)  # quoted

    def test_refusals(self):
        for kw in ({"user": "root"}, {"user": "runner"}, {"user": "a; rm -rf /"}, {"user": "Agent"}, {"user": ""},
                   {"workspace": "/home/runner/work/ws"}, {"workspace": "/home/runner"}, {"workspace": "/"},
                   {"workspace": "rel"}, {"workspace": "/etc/ws"}, {"workspace": "/srv/../etc"}):
            args = {"user": "agent", "workspace": "/srv/warden/ws"}
            args.update(kw)
            with self.assertRaises(JailSpecError, msg=str(kw)):
                jail.agent_user_script(**args)

    def test_other_runner_home_respected(self):
        jail.agent_user_script("agent", "/home/runner/work", runner_home="/home/ci")
        with self.assertRaises(JailSpecError):
            jail.agent_user_script("agent", "/home/ci/work", runner_home="/home/ci")

    def test_setup_script_adds_egress_only_with_network(self):
        offline = jail.setup_script(base(user="agent"))
        self.assertNotIn("iptables", offline)
        online = jail.setup_script(base(user="agent", network=True, uid=1001, allowed_loopback_ports=(8080,)))
        self.assertIn("iptables -w -A WARDEN_AGENT_UID", online)
        with self.assertRaises(JailSpecError):
            jail.setup_script(base())


class RunAsTests(unittest.TestCase):
    def test_shape(self):
        argv = jail.run_as_argv("agent", ["/usr/bin/claude", "-p"], {"B": "2", "A": "1"})
        self.assertEqual(argv, ["sudo", "-n", "-u", "agent", "env", "-i", "A=1", "B=2", "/usr/bin/claude", "-p"])

    def test_quoting_roundtrip_with_hostile_values(self):
        nasty = "x; rm -rf / $(id) `id` 'q' \"d\" \n newline"
        cmd = jail.run_as_command("agent", ["/bin/echo", nasty, "-n"], {"V": nasty})
        self.assertEqual(shlex.split(cmd), jail.run_as_argv("agent", ["/bin/echo", nasty, "-n"], {"V": nasty}))

    def test_refusals(self):
        for user in ("root", "a b", "", "x;y", "-u"):
            with self.assertRaises(JailSpecError, msg=user):
                jail.run_as_argv(user, ["/bin/true"])
        for argv in ([], ["-rm"], ["A=b"], ["/bin/true", "\x00"]):
            with self.assertRaises(JailSpecError, msg=repr(argv)):
                jail.run_as_argv("agent", argv)
        with self.assertRaises(JailSpecError):
            jail.run_as_argv("agent", ["/bin/true"], {"BAD=NAME": "x"})

    def test_launch_argv_composes(self):
        spec = base(user="agent")
        argv = jail.launch_argv(spec)
        self.assertEqual(argv[:6], ["sudo", "-n", "-u", "agent", "env", "-i"])
        self.assertIn("/usr/bin/bwrap", argv)
        self.assertEqual(argv.count("env"), 1)
        self.assertEqual(jail.launch_argv(replace(spec, user=None))[:2], ["env", "-i"])


class DescribeTests(unittest.TestCase):
    def test_names_only_and_digest(self):
        spec = base(env={"GH_TOKEN": GHP}, secret_ok=("GH_TOKEN",), user="agent")
        text = jail.describe(spec)
        self.assertIn("GH_TOKEN", text)
        self.assertNotIn(GHP, text)
        self.assertIn("launch argv sha256", text)
        self.assertIn("valid", text.splitlines()[0])

    def test_invalid_spec_described_with_problems(self):
        text = jail.describe(base(workspace="/"))
        self.assertIn("INVALID", text)
        self.assertIn("PROBLEM", text)
        self.assertNotIn("sha256", text)


if __name__ == "__main__":
    unittest.main()

import io
import unittest

from warden import envscrub
from warden.envscrub import EnvRefused, build_env

ANT = "sk-" + "ant-" + "x" * 40
GHP = "gh" + "p_" + "x" * 36
HOST = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "HOME": "/home/runner",
    "TERM": "xterm",
    "GH_TOKEN": GHP,
    "OPENROUTER_MANAGEMENT_KEY": "management-key-value",
    "BRIDGE_TOKEN": "bridge-token-value",
    "CLAUDE_CODE_OAUTH_TOKEN": ANT,
    "SOMETHING_NEW": "value",
}


class BuildEnvTests(unittest.TestCase):
    def test_only_allowlisted_names_pass(self):
        env = build_env(envscrub.DEFAULT_ALLOW, source=HOST)
        self.assertEqual(env, {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TERM": "xterm"})

    def test_unlisted_secrets_and_unknown_vars_do_not_leak(self):
        env = build_env(["PATH"], source=HOST)
        for name in ("GH_TOKEN", "OPENROUTER_MANAGEMENT_KEY", "BRIDGE_TOKEN", "SOMETHING_NEW", "HOME"):
            self.assertNotIn(name, env)

    def test_secret_name_in_allowlist_refused(self):
        with self.assertRaises(EnvRefused):
            build_env(["PATH", "GH_TOKEN"], source=HOST)

    def test_secret_name_in_allowlist_ok_when_named(self):
        env = build_env(["PATH", "CLAUDE_CODE_OAUTH_TOKEN"], source=HOST, secret_ok={"CLAUDE_CODE_OAUTH_TOKEN"})
        self.assertEqual(env["CLAUDE_CODE_OAUTH_TOKEN"], ANT)

    def test_extra_secret_value_refused_under_innocent_name(self):
        with self.assertRaises(EnvRefused):
            build_env(["PATH"], extra={"NOTE": GHP}, source=HOST)

    def test_extra_secret_name_refused_even_with_innocent_value(self):
        with self.assertRaises(EnvRefused):
            build_env(["PATH"], extra={"MY_API_KEY": "abc"}, source=HOST)

    def test_extra_secret_ok_when_named(self):
        env = build_env(["PATH"], extra={"MY_API_KEY": "abc"}, source=HOST, secret_ok=["MY_API_KEY"])
        self.assertEqual(env["MY_API_KEY"], "abc")

    def test_extra_plain_value_passes_and_overrides(self):
        env = build_env(["PATH"], extra={"PATH": "/opt/bin", "WARDEN_RUN": "7"}, source=HOST)
        self.assertEqual(env["PATH"], "/opt/bin")
        self.assertEqual(env["WARDEN_RUN"], "7")

    def test_allowlisted_variable_with_secret_value_refused(self):
        with self.assertRaises(EnvRefused):
            build_env(["LANG"], source={"LANG": GHP})

    def test_home_never_inherited_and_not_allowlistable(self):
        with self.assertRaises(EnvRefused):
            build_env(["HOME"], source=HOST)
        with self.assertRaises(EnvRefused):
            build_env(["PATH"], extra={"HOME": "/x"}, source=HOST)
        self.assertEqual(build_env(["PATH"], source=HOST, home="/tmp/h")["HOME"], "/tmp/h")
        with self.assertRaises(EnvRefused):
            build_env(["PATH"], source=HOST, home="relative/home")

    def test_relative_or_empty_path_entry_refused(self):
        for bad in ("/usr/bin::/bin", "/usr/bin:.", "bin"):
            with self.assertRaises(EnvRefused):
                build_env(["PATH"], source={"PATH": bad})

    def test_bad_names_values_and_string_allow_refused(self):
        with self.assertRaises(EnvRefused):
            build_env("PATH", source=HOST)
        with self.assertRaises(EnvRefused):
            build_env(["BAD=NAME"], source=HOST)
        with self.assertRaises(EnvRefused):
            build_env(["PATH"], extra={"X": "a\x00b"}, source=HOST)
        with self.assertRaises(EnvRefused):
            build_env(["PATH"], extra={"X": 5}, source=HOST)

    def test_error_message_never_contains_the_value(self):
        try:
            build_env(["PATH"], extra={"NOTE": GHP}, source=HOST)
        except EnvRefused as exc:
            self.assertNotIn(GHP, str(exc))
        else:
            self.fail("expected refusal")

    def test_source_is_not_mutated_and_result_is_a_new_dict(self):
        src = dict(HOST)
        env = build_env(["PATH"], source=src)
        env["PATH"] = "changed"
        self.assertEqual(src, HOST)


class DetectorTests(unittest.TestCase):
    def test_secret_names(self):
        for name in ("GH_TOKEN", "OPENAI_API_KEY", "LAKE_CACHE_KEY", "BRIDGE_TOKEN", "SSH_AUTH_SOCK", "AWS_SECRET_ACCESS_KEY",
                     "githubToken", "KIRO_API_KEY", "DB_PASSWORD"):
            self.assertTrue(envscrub.looks_secret_name(name), name)

    def test_non_secret_names(self):
        for name in ("PATH", "LANG", "GIT_AUTHOR_NAME", "KEYBOARD_LAYOUT", "TMPDIR", "PWD", "HOME"):
            self.assertFalse(envscrub.looks_secret_name(name), name)

    def test_secret_values(self):
        for value in (ANT, GHP, "github_pat_" + "A" * 30, "AKIA" + "A" * 16, "Bearer " + "a1B2" * 8,
                      "https://user:" + "hunter2" + "@example.com/x", "-----BEGIN RSA " + "PRIVATE KEY-----"):
            self.assertTrue(envscrub.looks_secret_value(value), value[:12])

    def test_non_secret_values(self):
        for value in ("", "C.UTF-8", "/usr/local/bin:/usr/bin", "a" * 40 + "0123456789abcdef" * 0,
                      "0123456789abcdef0123456789abcdef01234567", "xterm-256color",
                      "/private/var/folders/jn/fvdn4xwj1x5_34209hfy__0r0000gn/T/"):
            self.assertFalse(envscrub.looks_secret_value(value), value)

    def test_high_entropy_blob_detected(self):
        blob = "Zq8vLm2XrT9bKd4Nw7YpHc3JfS6aGe1U"
        self.assertTrue(envscrub.looks_secret_value(blob))


class ReportAndPathTests(unittest.TestCase):
    def test_report_has_names_not_values(self):
        env = {"PATH": "/usr/bin", "GH_TOKEN": GHP}
        buf = io.StringIO()
        text = envscrub.report(env, stream=buf)
        self.assertEqual(text, buf.getvalue())
        self.assertIn("GH_TOKEN", text)
        self.assertIn("SECRET-LOOKING", text)
        self.assertNotIn(GHP, text)
        self.assertNotIn("/usr/bin", text)
        self.assertIn("secret-ok", envscrub.report(env, secret_ok=["GH_TOKEN"]))

    def test_secret_names_in(self):
        env = {"PATH": "/usr/bin", "GH_TOKEN": GHP, "NOTE": ANT}
        self.assertEqual(envscrub.secret_names_in(env), ["GH_TOKEN", "NOTE"])
        self.assertEqual(envscrub.secret_names_in(env, secret_ok=["GH_TOKEN", "NOTE"]), [])

    def test_path_issues(self):
        self.assertEqual(envscrub.path_issues("/usr/bin:/bin"), [])
        self.assertTrue(envscrub.path_issues("/usr/bin::/bin"))
        self.assertTrue(envscrub.path_issues("bin:/usr/bin"))
        self.assertTrue(envscrub.path_issues(""))

    def test_writable_path_dirs_uses_injected_access(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(envscrub.writable_path_dirs(d, access=lambda p, m: True), [d])
            self.assertEqual(envscrub.writable_path_dirs(d, access=lambda p, m: False), [])


if __name__ == "__main__":
    unittest.main()

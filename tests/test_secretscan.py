"""Tests for warden.secretscan. Token-like strings are built at runtime so this file matches no scanner pattern."""
import contextlib
import io
import os
import tempfile
import unittest

from warden import secretscan
from warden.secretscan import redact, scan, scan_diff, scan_paths, shannon_entropy

R = "aB3dE9xK2mQ7wZ4nP8rT1vY6uL5hC0jF"  # 32 mixed characters


def kinds(text):
    return [f.kind for f in scan(text)]


SAMPLES = {
    "anthropic_api_key": "sk-" + "ant-" + "api03-" + R * 2,
    "anthropic_oauth_token": "sk-" + "ant-" + "oat01-" + R * 2,
    "openai_key": "sk-" + "proj-" + R * 2,
    "github_token": "gh" + "p_" + R + "abcd",
    "slack_token": "xox" + "b-" + "1234567890-" + R,
    "aws_access_key_id": "AK" + "IA" + "ABCDEFGHIJKLMNOP",
    "google_api_key": "AI" + "za" + R + "abc",
    "stripe_live_key": "sk" + "_live_" + R,
    "huggingface_token": "hf" + "_" + R + "abcde",
    "npm_token": "npm" + "_" + R + "abcd",
    "jwt": "ey" + "J" + "hbGciOiJIUzI1NiJ9" + ".ey" + "J" + "zdWIiOiIxMjM0NTY3ODkwIn0" + ".dBjftJeZ4CVPmB92K27uhbUJU1p1r",
}


class PatternTests(unittest.TestCase):
    def test_each_provider_pattern_is_found(self):
        for kind, secret in SAMPLES.items():
            got = kinds("value: " + secret + " end")
            self.assertEqual(got, [kind], kind)

    def test_github_prefixes(self):
        for pre in ("gho_", "ghs_", "ghu_", "ghr_"):
            self.assertEqual(kinds("x " + "gh" + pre[2:] + R + "abcd"), ["github_token"], pre)
        self.assertEqual(kinds("github_" + "pat_" + "11ABCDEFG0" + R + "_" + R), ["github_token"])

    def test_private_key_block_multiline_and_unterminated(self):
        head = "-----BEGIN " + "RSA PRIVATE KEY-----"
        block = head + "\nMIIEow" + R + "\n" + R + "\n-----END " + "RSA PRIVATE KEY-----"
        f = scan("before\n" + block + "\nafter")
        self.assertEqual([x.kind for x in f], ["private_key"])
        self.assertEqual(redact("before\n" + block + "\nafter"), "before\n[REDACTED:private_key]\nafter")
        self.assertEqual(kinds(head + "\nMIIEow" + R), ["private_key"])

    def test_aws_secret_assignment(self):
        self.assertEqual(kinds('aws_secret_access_key = "' + R + "abcdefgh" + '"'), ["aws_secret_key"])

    def test_bearer_and_headers(self):
        self.assertEqual(kinds("Authorization: Bearer " + R), ["bearer_token"])
        self.assertEqual(kinds("curl -H 'x-api-key: " + R + "'"), ["auth_header"])
        self.assertEqual(kinds("Authorization: Bearer ${TOKEN}"), [])
        self.assertEqual(kinds("Authorization: Bearer xxxxxxxxxxxxxxxxxxxxxxxx"), [])

    def test_credential_url(self):
        self.assertEqual(kinds("git clone https://deploy:" + R + "@host.example/r.git"), ["credential_url"])
        self.assertEqual(kinds("postgres://user:password@localhost/db"), [])
        self.assertEqual(kinds("https://example.com/path?x=1"), [])

    def test_assignment_with_high_entropy_value(self):
        for line in ("MY_SERVICE_TOKEN=" + R, 'api_key: "' + R + '"', "DB_PASSWORD = '" + R + "'", "client-secret=" + R):
            self.assertEqual(kinds(line), ["key_assignment"], line)

    def test_specific_kind_beats_generic(self):
        self.assertEqual(kinds("GITHUB_TOKEN=" + SAMPLES["github_token"]), ["github_token"])


class FalsePositiveTests(unittest.TestCase):
    def test_bare_40_hex_commit_not_flagged(self):
        sha = "0123456789abcdef0123456789abcdef01234567"
        for text in (sha, "commit " + sha, "Merge " + sha + " into main", "git checkout " + sha, "base_sha: " + sha):
            self.assertEqual(kinds(text), [], text)

    def test_40_hex_in_key_context_is_flagged(self):
        sha = "9f8e7d6c5b4a39281706f5e4d3c2b1a099887766"
        self.assertEqual(kinds("SERVICE_SECRET=" + sha), ["key_assignment"])

    def test_allowlist_pragma(self):
        line = "API_TOKEN = '" + R + "'  # pragma: allowlist secret"
        self.assertEqual(kinds(line), [])
        self.assertEqual(kinds(line + "\nnext_token = '" + R + "'"), ["key_assignment"])

    def test_benign_assignments(self):
        for line in ("token: ${{ secrets.GITHUB_TOKEN }}", "api_key = os.environ['API_KEY']", "secret_name = some_variable_name_long",
                     "key_path = /home/user/.config/some/long/path/here", "monkey=" + R, "password: changeme-changeme-change",
                     "max_tokens = 4096", "PASSWORD_FILE=/run/secrets/db_password_file"):
            self.assertEqual(kinds(line), [], line)

    def test_placeholder_values_in_redacted_form_are_stable(self):
        once = redact("API_TOKEN=" + R)
        self.assertEqual(redact(once), once)


class MechanicsTests(unittest.TestCase):
    def test_preview_is_at_most_four_chars_and_ellipsis(self):
        f = scan("x " + SAMPLES["github_token"])[0]
        self.assertEqual(f.preview, "ghp_…")
        self.assertNotIn(R[:6], f.preview)

    def test_offsets_and_line_numbers(self):
        text = "a\nb\nTOKEN_KEY=" + R
        f = scan(text, "src.txt")[0]
        self.assertEqual(text[f.start:f.end], R)
        self.assertEqual((f.line, f.source), (3, "src.txt"))

    def test_zero_width_and_control_split_is_seen_through_and_removed(self):
        tok = SAMPLES["github_token"]
        split = tok[:8] + "​" + tok[8:20] + "\x00" + tok[20:]
        self.assertEqual(kinds(split), ["github_token"])
        self.assertEqual(redact("k=" + split + " z"), "k=[REDACTED:github_token] z")

    def test_entropy(self):
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(shannon_entropy("abab"), 1.0)
        self.assertGreater(shannon_entropy(R), 4.5)

    def test_redact_keeps_context_and_handles_many(self):
        text = "A=1\nGITHUB_TOKEN=" + SAMPLES["github_token"] + "\nB=" + SAMPLES["aws_access_key_id"] + "\n"
        self.assertEqual(redact(text), "A=1\nGITHUB_TOKEN=[REDACTED:github_token]\nB=[REDACTED:aws_access_key_id]\n")

    def test_non_text_rejected(self):
        with self.assertRaises(TypeError):
            scan(b"bytes")


class DiffTests(unittest.TestCase):
    def diff(self):
        tok = SAMPLES["github_token"]
        return "\n".join([
            "diff --git a/src/a.py b/src/a.py",
            "--- a/src/a.py",
            "+++ b/src/a.py",
            "@@ -1,4 +10,5 @@",
            " context = '" + SAMPLES["aws_access_key_id"] + "'",
            "-removed_token = '" + tok + "'",
            "+safe = 1",
            "+TOKEN_KEY = '" + R + "'",
            "+++ not a header, an added line: " + SAMPLES["huggingface_token"],
            "@@ -20,1 +30,2 @@",
            " same",
            "+later = '" + tok + "'",
            "",
        ])

    def test_added_lines_only_with_file_and_new_line_numbers(self):
        got = [(f.kind, f.source, f.line) for f in scan_diff(self.diff())]
        self.assertEqual(got, [("key_assignment", "src/a.py", 12), ("huggingface_token", "src/a.py", 13),
                               ("github_token", "src/a.py", 31)])

    def test_removed_and_context_secrets_ignored(self):
        d = "--- a/x\n+++ b/x\n@@ -1,2 +1,1 @@\n-" + SAMPLES["github_token"] + "\n " + SAMPLES["github_token"] + "\n"
        self.assertEqual(scan_diff(d), [])

    def test_multiline_private_key_in_added_lines(self):
        d = "+++ b/k.pem\n@@ -0,0 +1,3 @@\n+-----BEGIN " + "PRIVATE KEY-----\n+" + R + "\n+-----END " + "PRIVATE KEY-----\n"
        f = scan_diff(d)
        self.assertEqual([(x.kind, x.source, x.line) for x in f], [("private_key", "k.pem", 1)])

    def test_allowlist_in_diff(self):
        d = "+++ b/x\n@@ -0,0 +1,1 @@\n+TOKEN_KEY = '" + R + "'  # pragma: allowlist secret\n"
        self.assertEqual(scan_diff(d), [])

    def test_garbage_diff_is_safe(self):
        self.assertEqual(scan_diff("not a diff\n@@ nonsense\n+ nothing"), [])


class FileAndCliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def write(self, name, text):
        p = os.path.join(self.dir.name, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)
        return p

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = secretscan.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_scan_paths_walks_directories_and_skips_git(self):
        self.write("a.txt", "API_TOKEN=" + R)
        os.mkdir(os.path.join(self.dir.name, ".git"))
        self.write(".git/config", "API_TOKEN=" + R)
        os.mkdir(os.path.join(self.dir.name, "sub"))
        self.write("sub/b.txt", "clean")
        f = scan_paths([self.dir.name])
        self.assertEqual(len(f), 1)
        self.assertTrue(f[0].source.endswith("a.txt"))

    def test_cli_exit_codes_and_no_full_secret_in_output(self):
        bad = self.write("bad.txt", "x\nAPI_TOKEN=" + R + "\n")
        good = self.write("good.txt", "nothing here\n")
        code, out, _ = self.run_main(bad)
        self.assertEqual(code, 1)
        self.assertIn("bad.txt:2: key_assignment", out)
        self.assertNotIn(R, out)
        self.assertEqual(self.run_main(good)[0], 0)
        self.assertEqual(self.run_main(os.path.join(self.dir.name, "missing"))[0], 2)
        self.assertEqual(self.run_main()[0], 2)

    def test_cli_redact_writes_clean_text(self):
        bad = self.write("bad.txt", "API_TOKEN=" + R + "\n")
        code, out, err = self.run_main("--redact", bad)
        self.assertEqual(code, 1)
        self.assertEqual(out, "API_TOKEN=[REDACTED:key_assignment]\n")
        self.assertNotIn(R, err)

    def test_cli_diff_mode(self):
        d = self.write("p.diff", "+++ b/x.py\n@@ -0,0 +1,1 @@\n+API_TOKEN = '" + R + "'\n")
        code, out, _ = self.run_main("--diff", d)
        self.assertEqual(code, 1)
        self.assertIn("x.py:1: key_assignment", out)


if __name__ == "__main__":
    unittest.main()

import contextlib
import io
import os
import shutil
import subprocess
import tempfile
import unittest

from warden import audit
from warden.audit import Chain, ChainError, RecordError, ledger_guard, verify_dir
from warden.caps import GENESIS, entry_line, make_entry


def rec(**kw):
    base = {"schema": audit.SCHEMA_ID, "ts": "2026-10-09T12:00:00Z", "actor": "bot", "action": "ci.collect", "outcome": "info"}
    base.update(kw)
    return base


def _rd(p):
    with open(p, "rb") as fh:
        return fh.read()


def _wr(p, data):
    with open(p, "wb") as fh:
        fh.write(data)


class SchemaTest(unittest.TestCase):
    def test_valid_and_optional_keys(self):
        self.assertEqual(audit.validate_record(rec()), [])
        full = rec(agent="a1", target="repo#1", case="c", rule="r1", evidence="sha256:" + "a" * 64, detail={"n": 3, "ok": True, "s": "x", "z": None})
        self.assertEqual(audit.validate_record(full), [])

    def test_hostile_records_rejected(self):
        bad = [
            rec(extra="x"),  # closed keys
            rec(outcome="maybe"),
            rec(ts="2026-10-09 12:00:00"),
            rec(ts="2026-10-09T12:00:00+00:00"),
            rec(actor=""),
            rec(actor="a\nb"),
            rec(action="Bad Action"),
            rec(target="x" * 301),
            rec(evidence="sha256:xyz"),
            rec(schema="other/v1"),
            rec(detail={"a": {"nested": 1}}),
            rec(detail={"a": [1]}),
            rec(detail={"a": 1.5}),
            rec(detail={"k%d" % i: 1 for i in range(17)}),
            rec(detail={"a": "x" * 201}),
            rec(detail={"a\x00": 1}),
            {k: v for k, v in rec().items() if k != "actor"},
            "not a dict",
            None,
            rec(actor=5),
            rec(target="t" * 300, case="c" * 200, detail={("k%02d" % i) + "k" * 37: "y" * 200 for i in range(16)}),  # over the byte cap
        ]
        for r in bad:
            self.assertTrue(audit.validate_record(r), r)

    def test_invalid_record_is_not_written(self):
        with tempfile.TemporaryDirectory() as d:
            c = Chain(d)
            with self.assertRaises(RecordError):
                c.append(rec(extra=1), "2026-10")
            self.assertEqual([n for n in os.listdir(d) if n.endswith(".ndjson")], [])


class ChainTest(unittest.TestCase):
    def _filled(self, d):
        c = Chain(d)
        c.append(rec(), "2026-09")
        c.append(rec(actor="b"), "2026-09")
        c.append(rec(actor="c"), "2026-10")
        return c

    def test_chain_spans_periods_and_verifies(self):
        with tempfile.TemporaryDirectory() as d:
            c = self._filled(d)
            r = verify_dir(d)
            self.assertTrue(r.ok, r.errors)
            self.assertEqual((r.entries, r.files), (3, ["audit-2026-09.ndjson", "audit-2026-10.ndjson"]))
            self.assertEqual(c.head(), r.head)
            self.assertNotEqual(r.head, GENESIS)
            self.assertTrue(verify_dir(d, expected_head=r.head).ok)
            self.assertEqual(audit.head(d), r.head)

    def test_edit_of_a_record_detected(self):
        with tempfile.TemporaryDirectory() as d:
            self._filled(d)
            p = os.path.join(d, "audit-2026-09.ndjson")
            _wr(p, _rd(p).replace(b'"actor": "bot"', b'"actor": "evl"'))
            r = verify_dir(d)
            self.assertFalse(r.ok)
            self.assertIn("audit-2026-09.ndjson", r.errors[0])

    def test_deleted_file_and_deleted_tail_detected(self):
        with tempfile.TemporaryDirectory() as d:
            c = self._filled(d)
            head = c.head()
            os.remove(os.path.join(d, "audit-2026-09.ndjson"))
            self.assertFalse(verify_dir(d).ok)  # the next file no longer links to genesis
        with tempfile.TemporaryDirectory() as d:
            c = self._filled(d)
            head = c.head()
            os.remove(os.path.join(d, "audit-2026-10.ndjson"))
            self.assertTrue(verify_dir(d).ok)  # chain still intact ...
            r = verify_dir(d, expected_head=head)  # ... but the published head exposes the loss
            self.assertFalse(r.ok)
            self.assertIn("published head", r.errors[0])

    def test_reordered_or_duplicated_lines_detected(self):
        with tempfile.TemporaryDirectory() as d:
            self._filled(d)
            p = os.path.join(d, "audit-2026-09.ndjson")
            lines = _rd(p).splitlines(True)
            _wr(p, lines[1] + lines[0])
            self.assertFalse(verify_dir(d).ok)
            _wr(p, lines[0] + lines[0] + lines[1])
            self.assertFalse(verify_dir(d).ok)

    def test_append_refused_on_broken_chain_and_backwards_period(self):
        with tempfile.TemporaryDirectory() as d:
            c = self._filled(d)
            with self.assertRaises(ChainError):
                c.append(rec(), "2026-08")
            with self.assertRaises(ChainError):
                c.append(rec(), "oct")
            p = os.path.join(d, "audit-2026-10.ndjson")
            _wr(p, _rd(p) + b"junk\n")
            with self.assertRaises(ChainError):
                c.append(rec(), "2026-10")

    def test_schema_violation_inside_a_valid_chain_is_caught(self):
        with tempfile.TemporaryDirectory() as d:
            bad = make_entry(0, audit.RECORD_KIND, {"smuggled": True}, GENESIS)
            _wr(os.path.join(d, "audit-2026-10.ndjson"), entry_line(bad))
            r = verify_dir(d)
            self.assertFalse(r.ok)
            self.assertIn("schema", r.errors[0])
            wrong_kind = make_entry(0, "other", rec(), GENESIS)
            _wr(os.path.join(d, "audit-2026-10.ndjson"), entry_line(wrong_kind))
            self.assertFalse(verify_dir(d).ok)

    def test_symlinked_period_file_rejected(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as other:
            c = Chain(other)
            c.append(rec(), "2026-10")
            os.symlink(os.path.join(other, "audit-2026-10.ndjson"), os.path.join(d, "audit-2026-10.ndjson"))
            self.assertFalse(verify_dir(d).ok)

    def test_empty_directory_has_genesis_head_and_cli(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(audit.head(d), GENESIS)
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(audit.main(["verify", d]), 0)
                self.assertEqual(audit.main(["verify", d, "--head", "sha256:" + "1" * 64]), 1)
                self.assertEqual(audit.main(["head", d]), 0)
                self.assertEqual(audit.main(["nonsense"]), 2)
            self.assertFalse(verify_dir(os.path.join(d, "missing")).ok)


GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


class Repo:
    def __init__(self, path):
        self.path = path
        self.git("init", "-q", "-b", "main")

    def git(self, *args):
        env = dict(os.environ)
        env.update(GIT_ENV)
        cp = subprocess.run(["git", "-C", self.path, "-c", "commit.gpgsign=false"] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        if cp.returncode != 0:
            raise RuntimeError(cp.stderr.decode())
        return cp.stdout.decode().strip()

    def write(self, rel, text):
        full = os.path.join(self.path, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as fh:
            fh.write(text)

    def commit(self, msg="c"):
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", msg)
        return self.git("rev-parse", "HEAD")


@unittest.skipUnless(shutil.which("git"), "git not installed")
class GuardTest(unittest.TestCase):
    GLOBS = ["records/**", "ledger/*.ndjson"]

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.r = Repo(self._tmp.name)
        self.r.write("records/2026/a.ndjson", "one\n")
        self.r.write("ledger/x.ndjson", "x\n")
        self.r.write("src/code.py", "v1\n")
        self.base = self.r.commit("base")

    def guard(self, head, **kw):
        return ledger_guard(self.r.path, self.base, head, self.GLOBS, **kw)

    def test_additions_only_pass(self):
        self.r.write("records/2026/b.ndjson", "two\n")
        self.r.write("ledger/y.ndjson", "y\n")
        self.r.write("src/code.py", "v2\n")  # outside the globs: free to change
        res = self.guard(self.r.commit("add"))
        self.assertTrue(res.ok, res)
        self.assertEqual(res.added, 2)

    def test_modification_fails(self):
        self.r.write("records/2026/a.ndjson", "one edited\n")
        res = self.guard(self.r.commit("edit"))
        self.assertFalse(res.ok)
        self.assertEqual([(v.path, v.status) for v in res.violations], [("records/2026/a.ndjson", "M")])

    def test_deletion_fails(self):
        os.remove(os.path.join(self.r.path, "ledger/x.ndjson"))
        res = self.guard(self.r.commit("rm"))
        self.assertEqual([(v.path, v.status) for v in res.violations], [("ledger/x.ndjson", "D")])

    def test_rename_is_a_delete_plus_add_not_hidden(self):
        os.rename(os.path.join(self.r.path, "records/2026/a.ndjson"), os.path.join(self.r.path, "records/2026/renamed.ndjson"))
        res = self.guard(self.r.commit("mv"))
        self.assertFalse(res.ok)
        self.assertEqual([v.status for v in res.violations], ["D"])

    def test_type_change_fails(self):
        p = os.path.join(self.r.path, "records/2026/a.ndjson")
        os.remove(p)
        os.symlink("../../src/code.py", p)
        res = self.guard(self.r.commit("symlink"))
        self.assertFalse(res.ok)
        self.assertEqual(res.violations[0].status, "T")

    def test_edit_then_revert_is_caught_per_commit_only(self):
        self.r.write("records/2026/a.ndjson", "tampered\n")
        c1 = self.r.commit("tamper")
        self.r.write("records/2026/a.ndjson", "one\n")
        head = self.r.commit("revert")
        self.assertTrue(self.guard(head, per_commit=False).ok)  # the net diff is empty
        res = self.guard(head)
        self.assertFalse(res.ok)
        self.assertEqual(res.violations[0].commit, c1)

    def test_rewritten_history_fails(self):
        self.r.write("records/2026/b.ndjson", "two\n")
        good = self.r.commit("add")
        self.r.git("checkout", "-q", "--detach", "HEAD~1")
        self.r.write("records/2026/z.ndjson", "other\n")
        side = self.r.commit("sibling")
        self.assertTrue(self.guard(good).ok)
        res = ledger_guard(self.r.path, good, side, self.GLOBS)
        self.assertFalse(res.ok)
        self.assertIn("descend", res.error)

    def test_merge_commit_that_modifies_is_caught(self):
        self.r.git("checkout", "-q", "-b", "side")
        self.r.write("records/2026/a.ndjson", "side edit\n")
        self.r.commit("side")
        self.r.git("checkout", "-q", "main")
        self.r.write("src/code.py", "v3\n")
        self.r.commit("main")
        self.r.git("merge", "-q", "--no-ff", "-m", "merge", "side")
        res = self.guard(self.r.git("rev-parse", "HEAD"))
        self.assertFalse(res.ok)

    def test_bad_input_and_errors_fail_closed(self):
        head = self.r.commit("empty")
        for base, h, globs in [
            ("main", head, self.GLOBS),  # refs are not accepted
            (self.base, "HEAD", self.GLOBS),
            ("0" * 40, head, self.GLOBS),
            (self.base, head, []),
            (self.base, head, ["/abs/**"]),
            ("a" * 40, head, self.GLOBS),  # unknown object
        ]:
            res = ledger_guard(self.r.path, base, h, globs)
            self.assertFalse(res.ok, (base, h, globs))
            self.assertTrue(res.error)
        res = ledger_guard(os.path.join(self.r.path, "nope"), self.base, head, self.GLOBS)
        self.assertFalse(res.ok)

    def test_odd_filenames(self):
        self.r.write("records/we irdé/new line.ndjson", "n\n")
        res = self.guard(self.r.commit("odd"))
        self.assertTrue(res.ok, res)
        self.assertEqual(res.added, 1)

    def test_cli_exit_codes(self):
        self.r.write("records/2026/a.ndjson", "edit\n")
        head = self.r.commit("edit")
        args = ["guard", "--repo", self.r.path, "--base", self.base, "--head", head, "--glob", "records/**"]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(audit.main(args), 1)
            self.assertEqual(audit.main(args[:6] + ["--head", "bogus", "--glob", "records/**"]), 2)
            self.assertEqual(audit.main(["guard", "--repo", self.r.path, "--base", self.base, "--head", self.base, "--glob", "records/**"]), 0)


class GlobTest(unittest.TestCase):
    def test_glob_semantics(self):
        m = lambda g, p: bool(audit.glob_to_regex(g).match(p))
        self.assertTrue(m("records/**", "records/a/b/c.json"))
        self.assertFalse(m("records/**", "records"))
        self.assertTrue(m("records/*.json", "records/a.json"))
        self.assertFalse(m("records/*.json", "records/a/b.json"))
        self.assertTrue(m("**/*.ndjson", "a/b/c.ndjson"))
        self.assertTrue(m("**/*.ndjson", "c.ndjson"))
        self.assertFalse(m("records/**", "xrecords/a"))
        self.assertTrue(m("a?c", "abc"))
        self.assertFalse(m("a?c", "a/c"))
        self.assertTrue(m("a.b", "a.b"))
        self.assertFalse(m("a.b", "aXb"))


if __name__ == "__main__":
    unittest.main()

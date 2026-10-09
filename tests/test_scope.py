"""Tests for warden.scope: real git repositories in temp directories."""
from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import tempfile
import unittest

from tests import gitfixture as gf
from warden import scope


def setUpModule():
    gf.patch_env()


def tearDownModule():
    gf.restore_env()


POLICY = {
    "classes": {"agent": {"allow": ["TauCeti/", "notes/**"]},
                "human": {"allow": ["**"], "touch_protected": True}},
    "protected": ["/.github/", "AGENTS.md"],
    "max_files": 2000, "max_added": 2000, "max_deleted": 2000, "max_new_file_lines": 1000,
    "append_only": ["notes/LOG.md"],
}


def pol(**over):
    d = json.loads(json.dumps(POLICY))
    d.update(over)
    return scope.Policy.from_dict(d)


class RepoCase(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.dir = td.name
        self.repo = gf.init_repo(os.path.join(self.dir, "r"))
        self.base = gf.commit(self.repo, {
            "TauCeti/A.lean": "def a := 1\n", "docs/guide.md": "g\n", ".github/ci.yml": "ci: 1\n",
            "AGENTS.md": "rules\n", "notes/LOG.md": "one\n"}, msg="base")

    def codes(self, head, policy=None, cls="agent", base=None):
        return scope.check(self.repo, base or self.base, head, policy or pol(), cls).codes()


class ChangedTests(RepoCase):
    def test_lists_deletion_and_rename_as_delete_plus_add(self):
        gf.git(self.repo, "mv", "TauCeti/A.lean", "docs/A.lean")
        gf.git(self.repo, "commit", "-q", "-m", "mv")
        head = gf.git(self.repo, "rev-parse", "HEAD")
        got = sorted((c.status, c.path) for c in scope.changed(self.repo, self.base, head))
        self.assertEqual(got, [("A", "docs/A.lean"), ("D", "TauCeti/A.lean")])

    def test_mode_change_and_binary_are_reported(self):
        gf.git(self.repo, "update-index", "--chmod=+x", "TauCeti/A.lean")
        gf.git(self.repo, "commit", "-q", "-m", "x")
        h1 = gf.git(self.repo, "rev-parse", "HEAD")
        ch = scope.changed(self.repo, self.base, h1)
        self.assertEqual([(c.status, c.old_mode, c.new_mode) for c in ch], [("M", "100644", "100755")])
        h2 = gf.commit(self.repo, {"TauCeti/b.bin": b"\x00\x01\x02" * 50})
        self.assertTrue([c for c in scope.changed(self.repo, h1, h2) if c.path == "TauCeti/b.bin"][0].binary)

    def test_many_files_never_truncated(self):
        head = gf.commit(self.repo, {"TauCeti/f%04d.lean" % i: "x\n" for i in range(350)})
        self.assertEqual(len(scope.changed(self.repo, self.base, head)), 350)

    def test_bad_revision_raises(self):
        with self.assertRaises(scope.GitError):
            scope.changed(self.repo, "--output=/tmp/x", self.base)
        with self.assertRaises(scope.GitError):
            scope.changed(self.repo, self.base, "no-such-ref")


class CheckTests(RepoCase):
    def test_in_scope_change_passes(self):
        head = gf.commit(self.repo, {"TauCeti/A.lean": "def a := 2\n", "TauCeti/New.lean": "x\n"})
        res = scope.check(self.repo, self.base, head, pol(), "agent")
        self.assertTrue(res.ok, res.violations)
        self.assertEqual(res.files, 2)

    def test_path_outside_allowlist_fails(self):
        head = gf.commit(self.repo, {"docs/guide.md": "changed\n"})
        self.assertEqual(self.codes(head), ["path_not_allowed"])

    def test_protected_path_fails_for_agent_but_not_for_human(self):
        head = gf.commit(self.repo, {".github/ci.yml": "ci: 2\n"})
        self.assertIn("protected_path", self.codes(head))
        self.assertEqual(self.codes(head, cls="human"), [])

    def test_unknown_actor_class_fails_closed(self):
        head = gf.commit(self.repo, {"TauCeti/A.lean": "y\n"})
        self.assertEqual(self.codes(head, cls="stranger"), ["unknown_actor_class"])

    def test_empty_diff_and_unreadable_diff_fail_closed(self):
        self.assertEqual(self.codes(self.base), ["empty_diff"])
        self.assertEqual(self.codes("deadbeef" * 5), ["unreadable_diff"])

    def test_rename_out_of_allowed_path_is_caught(self):
        gf.git(self.repo, "mv", "TauCeti/A.lean", "docs/A.lean")
        gf.git(self.repo, "commit", "-q", "-m", "mv")
        head = gf.git(self.repo, "rev-parse", "HEAD")
        res = scope.check(self.repo, self.base, head, pol(), "agent")
        self.assertEqual([(v.code, v.path) for v in res.violations], [("path_not_allowed", "docs/A.lean")])

    def test_rename_of_protected_file_into_allowed_path_is_caught(self):
        gf.git(self.repo, "mv", "AGENTS.md", "TauCeti/AGENTS.md")
        gf.git(self.repo, "commit", "-q", "-m", "mv")
        head = gf.git(self.repo, "rev-parse", "HEAD")
        res = scope.check(self.repo, self.base, head, pol(), "agent")
        self.assertIn(("protected_path", "AGENTS.md"), [(v.code, v.path) for v in res.violations])

    def test_delete_forbidden_only_when_configured(self):
        head = gf.commit(self.repo, delete=["TauCeti/A.lean"])
        self.assertEqual(self.codes(head), [])
        self.assertEqual(self.codes(head, pol(forbid_delete=["TauCeti/"])), ["delete_forbidden"])
        self.assertEqual(self.codes(head, pol(forbid_delete=True)), ["delete_forbidden"])

    def test_symlink_is_refused(self):
        os.symlink("../.github/ci.yml", os.path.join(self.repo, "TauCeti", "link"))
        gf.git(self.repo, "add", "TauCeti/link")
        gf.git(self.repo, "commit", "-q", "-m", "ln")
        head = gf.git(self.repo, "rev-parse", "HEAD")
        res = scope.check(self.repo, self.base, head, pol(), "agent")
        self.assertEqual([(v.code, v.path) for v in res.violations], [("mode_not_allowed", "TauCeti/link")])
        self.assertEqual(self.codes(head, pol(allowed_modes=["100644", "120000"])), [])

    def test_type_change_file_to_symlink_is_refused(self):
        os.remove(os.path.join(self.repo, "TauCeti", "A.lean"))
        os.symlink("x", os.path.join(self.repo, "TauCeti", "A.lean"))
        gf.git(self.repo, "add", "-A")
        gf.git(self.repo, "commit", "-q", "-m", "t")
        head = gf.git(self.repo, "rev-parse", "HEAD")
        self.assertEqual(self.codes(head), ["mode_not_allowed"])

    def test_executable_bit_and_submodule_are_refused(self):
        path = os.path.join(self.repo, "TauCeti", "A.lean")
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        gf.git(self.repo, "add", "-A")
        gf.git(self.repo, "commit", "-q", "-m", "x")
        h1 = gf.git(self.repo, "rev-parse", "HEAD")
        self.assertEqual(self.codes(h1), ["mode_not_allowed"])
        gf.git(self.repo, "update-index", "--add", "--cacheinfo", "160000,%s,TauCeti/sub" % self.base)
        gf.git(self.repo, "commit", "-q", "-m", "sub")
        h2 = gf.git(self.repo, "rev-parse", "HEAD")
        res = scope.check(self.repo, h1, h2, pol(), "agent")
        self.assertEqual([(v.code, v.path) for v in res.violations], [("mode_not_allowed", "TauCeti/sub")])

    def test_oversized_pr_by_files_added_and_deleted(self):
        head = gf.commit(self.repo, {"TauCeti/f%04d.lean" % i: "x\n" for i in range(350)})
        self.assertEqual(self.codes(head), [])
        self.assertIn("too_many_files", self.codes(head, pol(max_files=300)))
        res = scope.check(self.repo, self.base, head, pol(max_files=300), "agent")
        self.assertEqual(res.files, 350)
        self.assertIn("too_many_added_lines", self.codes(head, pol(max_added=100)))
        big = gf.commit(self.repo, {"TauCeti/A.lean": "".join("l%d\n" % i for i in range(30))})
        small = gf.commit(self.repo, {"TauCeti/A.lean": "x\n"})
        self.assertIn("too_many_deleted_lines", self.codes(small, pol(max_deleted=10), base=big))
        self.assertEqual(self.codes(small, pol(max_deleted=30), base=big), [])

    def test_new_file_line_cap_and_binary_ban(self):
        head = gf.commit(self.repo, {"TauCeti/Long.lean": "l\n" * 1200})
        self.assertEqual(self.codes(head), ["new_file_too_long"])
        self.assertEqual(self.codes(head, pol(max_new_file_lines=1500)), [])
        h2 = gf.commit(self.repo, {"TauCeti/x.bin": b"\x00\xff" * 40})
        self.assertEqual(self.codes(h2, pol(forbid_binary=True), base=head), ["binary_forbidden"])
        self.assertEqual(self.codes(h2, base=head), [])

    def test_append_only_byte_prefix(self):
        ok = gf.commit(self.repo, {"notes/LOG.md": "one\ntwo\n"})
        self.assertEqual(self.codes(ok), [])
        for bad in ("two\n", "two\none\n", "one", "On\nTwo\n"):
            head = gf.commit(self.repo, {"notes/LOG.md": bad})
            self.assertEqual(self.codes(head), ["append_only_violated"], bad)
        gone = gf.commit(self.repo, delete=["notes/LOG.md"])
        self.assertEqual(self.codes(gone), ["append_only_violated"])
        created = gf.commit(self.repo, {"notes/LOG.md": "fresh\n"})
        self.assertEqual(self.codes(created, base=gone), [])

    def test_dirty_working_tree_and_index_do_not_matter(self):
        head = gf.commit(self.repo, {"TauCeti/A.lean": "def a := 3\n"})
        with open(os.path.join(self.repo, "docs", "guide.md"), "w") as fh:
            fh.write("uncommitted edit\n")
        gf.git(self.repo, "add", "docs/guide.md")
        self.assertEqual(self.codes(head), [])

    def test_unsafe_path_names(self):
        for p in (".git/hooks/x", "a/../b", "a/\nb", "/abs", "dir/.GIT/config"):
            self.assertIsNotNone(scope._unsafe_path(p), p)
        self.assertIsNone(scope._unsafe_path("TauCeti/.gitignore"))


class HostileConfigTests(RepoCase):
    def test_repo_config_hooks_attributes_and_env_cannot_run_code(self):
        head = gf.commit(self.repo, {"TauCeti/A.lean": "def a := 9\n"})
        marker = os.path.join(self.dir, "pwned")
        script = os.path.join(self.dir, "evil.sh")
        with open(script, "w") as fh:
            fh.write("#!/bin/sh\necho ran >> %s\nexit 0\n" % marker)
        os.chmod(script, 0o755)
        extra = os.path.join(self.dir, "extra.cfg")
        with open(extra, "w") as fh:
            fh.write("[core]\n\tfsmonitor = %s\n" % script)
        cfg = os.path.join(self.repo, ".git", "config")
        with open(cfg, "a") as fh:
            fh.write("[core]\n\tfsmonitor = %s\n\thooksPath = %s\n\tpager = %s\n\tattributesFile = /dev/null\n"
                     "[diff]\n\texternal = %s\n[diff \"evil\"]\n\ttextconv = %s\n\tcommand = %s\n"
                     "[include]\n\tpath = %s\n" % (script, self.dir, script, script, script, script, extra))
        with open(os.path.join(self.repo, ".git", "info", "attributes"), "a") as fh:
            fh.write("* diff=evil\n")
        for hook in ("post-checkout", "reference-transaction", "post-index-change"):
            hp = os.path.join(self.repo, ".git", "hooks", hook)
            with open(hp, "w") as fh:
                fh.write("#!/bin/sh\necho ran >> %s\n" % marker)
            os.chmod(hp, 0o755)
        old = os.environ.get("GIT_EXTERNAL_DIFF")
        os.environ["GIT_EXTERNAL_DIFF"] = script
        try:
            res = scope.check(self.repo, self.base, head, pol(), "agent")
            scope.dropped_human_owned(self.repo, self.base, head, ["AGENTS.md"])
        finally:
            if old is None:
                os.environ.pop("GIT_EXTERNAL_DIFF", None)
            else:
                os.environ["GIT_EXTERNAL_DIFF"] = old
        self.assertTrue(res.ok, res.violations)
        self.assertFalse(os.path.exists(marker), "hostile configuration executed code")
        # control: the same repository really is hostile to plain git (the setup is not vacuous)
        gf.git(self.repo, "status", "--porcelain", check=False)
        gf.git(self.repo, "diff", "--numstat", self.base, head, check=False)
        self.assertTrue(os.path.exists(marker), "control failed: the hostile setup did nothing")

    def test_replace_refs_cannot_hide_a_change(self):
        head = gf.commit(self.repo, {".github/ci.yml": "ci: evil\n"})
        gf.git(self.repo, "replace", "--force", head, self.base)
        self.assertEqual(gf.git(self.repo, "diff", "--name-only", self.base, head), "")  # the lie, to plain git
        self.assertIn("protected_path", self.codes(head))

    def test_bare_repository_works(self):
        head = gf.commit(self.repo, {"TauCeti/A.lean": "bare\n"})
        bare = gf.init_bare(os.path.join(self.dir, "bare.git"))
        gf.git(self.repo, "push", "-q", bare, "main")
        self.assertTrue(scope.check(bare, self.base, head, pol(), "agent").ok)


class DroppedHumanTests(RepoCase):
    def test_revert_of_human_change_is_flagged_though_base_diff_is_clean(self):
        prev = gf.commit(self.repo, {".github/ci.yml": "ci: 2\n", "TauCeti/A.lean": "x\n"})  # human adds CI work
        head = gf.commit(self.repo, {".github/ci.yml": "ci: 1\n"})  # agent reverts it to get green
        self.assertNotIn("protected_path", self.codes(head))  # net change vs base is no change at all
        got = scope.dropped_human_owned(self.repo, prev, head, ["/.github/"])
        self.assertEqual([(d.path, d.kind) for d in got], [(".github/ci.yml", "modified")])

    def test_deletion_flagged_and_benign_push_clean(self):
        prev = gf.commit(self.repo, {".github/ci.yml": "ci: 2\n"})
        gone = gf.commit(self.repo, delete=[".github/ci.yml"])
        self.assertEqual([(d.path, d.kind) for d in scope.dropped_human_owned(self.repo, prev, gone, ["/.github/"])],
                         [(".github/ci.yml", "deleted")])
        benign = gf.commit(self.repo, {"TauCeti/A.lean": "more\n"}, msg="benign")
        self.assertEqual(scope.dropped_human_owned(self.repo, gone, benign, ["/.github/"]), [])

    def test_waived_paths_and_unreadable_diff(self):
        prev = gf.commit(self.repo, {"AGENTS.md": "new rules\n"})
        head = gf.commit(self.repo, {"AGENTS.md": "newer\n"})
        self.assertEqual(scope.dropped_human_owned(self.repo, prev, head, ["AGENTS.md"], allow_paths=["AGENTS.md"]), [])
        with self.assertRaises(scope.GitError):
            scope.dropped_human_owned(self.repo, "nonexistent", head, ["AGENTS.md"])


class PolicyTests(unittest.TestCase):
    def test_strict_parsing(self):
        bad = [
            {},
            {"classes": {}},
            {"classes": {"a": {"allow": ["x"]}}, "surprise": 1},
            {"classes": {"a": {"allow": "x"}}},
            {"classes": {"a": {"allow": ["!x"]}}},
            {"classes": {"a": {"allow": ["x"], "extra": 1}}},
            {"classes": {"a": {"allow": ["x"]}}, "max_files": True},
            {"classes": {"a": {"allow": ["x"]}}, "max_files": -1},
            {"classes": {"a": {"allow": ["x"]}}, "allowed_modes": ["755"]},
            {"classes": {"a": {"allow": ["x"]}}, "forbid_binary": "yes"},
        ]
        for d in bad:
            with self.assertRaises(scope.PolicyError, msg=str(d)):
                scope.Policy.from_dict(d)
        p = scope.Policy.from_dict({"classes": {"a": {"allow": ["x"]}}})
        self.assertEqual(p.allowed_modes, ("100644",))

    def test_duplicate_keys_in_file_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.json")
            with open(path, "w") as fh:
                fh.write('{"classes": {"a": {"allow": ["x"]}}, "classes": {}}')
            with self.assertRaises(scope.PolicyError):
                scope.Policy.load(path)

    def test_glob_semantics(self):
        yes = [("docs/", "docs/a.md"), ("docs/", "x/docs/a.md"), ("/docs/", "docs/a/b"), ("docs/*", "docs/a"),
               ("**/foo.md", "a/b/foo.md"), ("a/**/b", "a/b"), ("a/**", "a/x/y"), ("*.lean", "a/b.lean"),
               ("TauCeti", "TauCeti/X.lean"), ("**", "x/y"), ("/AGENTS.md", "AGENTS.md")]
        no = [("/docs/", "x/docs/a.md"), ("docs/*", "docs/s/a"), ("a/**", "a"), ("/*.lean", "a/b.lean"),
              ("a/b", "x/a/b"), ("/AGENTS.md", "sub/AGENTS.md")]
        for p, path in yes:
            self.assertTrue(scope.glob_match(p, path), (p, path))
        for p, path in no:
            self.assertFalse(scope.glob_match(p, path), (p, path))


class CliTests(RepoCase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = scope.main(list(args))
        return code, out.getvalue()

    def test_exit_codes(self):
        pfile = os.path.join(self.dir, "p.json")
        with open(pfile, "w") as fh:
            json.dump(POLICY, fh)
        ok = gf.commit(self.repo, {"TauCeti/A.lean": "cli\n"})
        base = ["--repo", self.repo, "--policy", pfile, "--base", self.base]
        self.assertEqual(self.run_cli(*base, "--head", ok, "--class", "agent")[0], 0)
        bad = gf.commit(self.repo, {".github/ci.yml": "evil\n"})
        code, out = self.run_cli(*base, "--head", bad, "--class", "agent", "--json")
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(out)["ok"])
        self.assertEqual(self.run_cli(*base, "--head", ok, "--class", "nobody")[0], 1)
        self.assertEqual(self.run_cli("--repo", self.repo, "--policy", os.path.join(self.dir, "missing.json"),
                                      "--base", self.base, "--head", ok, "--class", "agent")[0], 2)
        self.assertEqual(self.run_cli("--bogus")[0], 2)

    def test_prev_head_flag_reports_dropped_work(self):
        pfile = os.path.join(self.dir, "p.json")
        with open(pfile, "w") as fh:
            json.dump(POLICY, fh)
        prev = gf.commit(self.repo, {"AGENTS.md": "human rules\n"})
        head = gf.commit(self.repo, {"AGENTS.md": "rules\n", "TauCeti/A.lean": "z\n"})
        code, out = self.run_cli("--repo", self.repo, "--policy", pfile, "--base", self.base, "--head", head,
                                 "--class", "agent", "--prev-head", prev)
        self.assertEqual(code, 1)
        self.assertIn("human_work_dropped", out)


if __name__ == "__main__":
    unittest.main()

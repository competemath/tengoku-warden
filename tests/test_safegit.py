"""Tests for warden.safegit: compare-and-swap pushes against a real local bare remote, the hook, PR checks."""
from __future__ import annotations

import os
import tempfile
import threading
import unittest
from unittest import mock

from tests import gitfixture as gf
from warden import safegit as sg


def setUpModule():
    gf.patch_env()


def tearDownModule():
    gf.restore_env()


class RemoteCase(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.dir = td.name
        self.bare = gf.init_bare(os.path.join(self.dir, "remote.git"))
        self.repo = gf.init_repo(os.path.join(self.dir, "w"))
        self.c1 = gf.commit(self.repo, {"a": "1"})
        self.c2 = gf.commit(self.repo, {"a": "2"})
        self.c3 = gf.commit(self.repo, {"a": "3"})

    def remote_ref(self, ref):
        return sg.ls_remote(self.repo, self.bare).get(ref)


class PushCasTests(RemoteCase):
    def test_create_then_update_with_matching_expectation(self):
        r = sg.push_cas(self.repo, self.bare, "refs/heads/x", self.c1, None)
        self.assertTrue(r.ok, r)
        self.assertEqual(self.remote_ref("refs/heads/x"), self.c1)
        r = sg.push_cas(self.repo, self.bare, "refs/heads/x", self.c2, self.c1)
        self.assertTrue(r.ok, r)
        self.assertEqual(self.remote_ref("refs/heads/x"), self.c2)

    def test_lease_mismatch_is_refused_and_remote_unchanged(self):
        sg.push_cas(self.repo, self.bare, "refs/heads/x", self.c2, None)
        r = sg.push_cas(self.repo, self.bare, "refs/heads/x", self.c3, self.c1)  # we believe it is c1
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "lease_mismatch")
        self.assertEqual(self.remote_ref("refs/heads/x"), self.c2)

    def test_non_fast_forward_with_correct_lease_is_allowed_because_the_lease_is_the_guard(self):
        sg.push_cas(self.repo, self.bare, "refs/heads/x", self.c3, None)
        self.assertTrue(sg.push_cas(self.repo, self.bare, "refs/heads/x", self.c1, self.c3).ok)
        self.assertEqual(self.remote_ref("refs/heads/x"), self.c1)

    def test_create_only_collision_second_creator_loses(self):
        self.assertTrue(sg.push_cas(self.repo, self.bare, "refs/heads/x", self.c1, None).ok)
        r = sg.push_cas(self.repo, self.bare, "refs/heads/x", self.c2, None)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "exists")
        self.assertEqual(self.remote_ref("refs/heads/x"), self.c1)

    def test_empty_expectation_lease_alone_stops_a_late_creator(self):
        # bypass the explicit existence check to prove the server-side lease semantics on their own
        sg.push_cas(self.repo, self.bare, "refs/heads/x", self.c1, None)
        r = sg.run_git(self.repo, ["push", "--porcelain", "--force-with-lease=refs/heads/x:", self.bare,
                                   "%s:refs/heads/x" % self.c2])
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.remote_ref("refs/heads/x"), self.c1)

    def test_racing_creators_exactly_one_wins(self):
        results = []
        barrier = threading.Barrier(6)

        def worker(sha):
            barrier.wait()
            results.append((sha, sg.push_cas(self.repo, self.bare, "refs/leases/k", sha, None)))

        shas = [self.c1, self.c2, self.c3, self.c1, self.c2, self.c3]
        threads = [threading.Thread(target=worker, args=(s,)) for s in shas]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        winners = [s for s, r in results if r.ok]
        self.assertEqual(len(results), 6)
        self.assertGreaterEqual(len(winners), 1)
        # identical shas may both "succeed" as a no-op; distinct shas never both win
        self.assertEqual(len(set(winners)), 1)
        self.assertEqual(self.remote_ref("refs/leases/k"), winners[0])
        for s, r in results:
            if not r.ok:
                self.assertIn(r.reason, ("exists", "lease_mismatch"))

    def test_racing_updates_from_the_same_expectation_one_wins(self):
        sg.push_cas(self.repo, self.bare, "refs/heads/x", self.c1, None)
        results = []
        barrier = threading.Barrier(2)

        def worker(sha):
            barrier.wait()
            results.append((sha, sg.push_cas(self.repo, self.bare, "refs/heads/x", sha, self.c1)))

        ts = [threading.Thread(target=worker, args=(s,)) for s in (self.c2, self.c3)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        winners = [s for s, r in results if r.ok]
        self.assertEqual(len(winners), 1)
        self.assertEqual(self.remote_ref("refs/heads/x"), winners[0])

    def test_unconditional_force_cannot_be_expressed(self):
        for bad in ("", "abc", self.c1.upper(), self.c1[:10], self.c1 + "\n", "0" * 40, "+" + self.c1, 12345):
            with self.assertRaises(sg.UnsafePush, msg=repr(bad)):
                sg.push_cas(self.repo, self.bare, "refs/heads/x", self.c1, bad)
        self.assertIsNone(self.remote_ref("refs/heads/x"))

    def test_bad_refs_shas_and_remotes_are_refused_before_git_runs(self):
        for ref in ("heads/x", "refs/heads/a b", "refs/heads/../x", "refs/heads/x.lock", "+refs/heads/x",
                    "refs/heads/x:refs/heads/y", "refs/heads/x\n", "refs/", "HEAD"):
            with self.assertRaises(sg.UnsafePush, msg=ref):
                sg.push_cas(self.repo, self.bare, ref, self.c1, None)
        with self.assertRaises(sg.UnsafePush):
            sg.push_cas(self.repo, self.bare, "refs/heads/x", "0" * 40, None)
        with self.assertRaises(sg.UnsafePush):
            sg.push_cas(self.repo, "--mirror", "refs/heads/x", self.c1, None)
        self.assertEqual(sg.ls_remote(self.repo, self.bare), {})

    def test_delete_with_lease(self):
        sg.push_cas(self.repo, self.bare, "refs/heads/x", self.c2, None)
        self.assertFalse(sg.delete_ref_cas(self.repo, self.bare, "refs/heads/x", self.c1).ok)
        self.assertEqual(self.remote_ref("refs/heads/x"), self.c2)
        self.assertTrue(sg.delete_ref_cas(self.repo, self.bare, "refs/heads/x", self.c2).ok)
        self.assertIsNone(self.remote_ref("refs/heads/x"))

    def test_unreachable_remote_is_an_error_not_a_success(self):
        r = sg.push_cas(self.repo, os.path.join(self.dir, "nope.git"), "refs/heads/x", self.c1, None)
        self.assertFalse(r.ok)
        self.assertEqual(r.reason, "error")


class HookTests(RemoteCase):
    def test_hook_blocks_raw_push_but_not_the_wrapper(self):
        sg.install_prepush_hook(self.repo)
        raw = sg.run_git(self.repo, ["push", self.bare, "%s:refs/heads/raw" % self.c1])
        self.assertNotEqual(raw.returncode, 0)
        forced = sg.run_git(self.repo, ["push", "--force", self.bare, "%s:refs/heads/raw" % self.c1])
        self.assertNotEqual(forced.returncode, 0)
        self.assertIsNone(self.remote_ref("refs/heads/raw"))
        self.assertTrue(sg.push_cas(self.repo, self.bare, "refs/heads/ok", self.c1, None).ok)
        self.assertTrue(sg.delete_ref_cas(self.repo, self.bare, "refs/heads/ok", self.c1).ok)

    def test_wrong_capability_is_refused_and_no_verify_bypasses_by_design(self):
        sg.install_prepush_hook(self.repo)
        wrong = sg.run_git(self.repo, ["push", self.bare, "%s:refs/heads/w" % self.c1],
                           env={sg.CAP_ENV: "guess"})
        self.assertNotEqual(wrong.returncode, 0)
        # honest limit: this is defence in depth, not a boundary
        bypass = sg.run_git(self.repo, ["push", "--no-verify", self.bare, "%s:refs/heads/w" % self.c1])
        self.assertEqual(bypass.returncode, 0)

    def test_does_not_overwrite_a_foreign_hook_unless_asked(self):
        hook = os.path.join(self.repo, ".git", "hooks", "pre-push")
        with open(hook, "w") as fh:
            fh.write("#!/bin/sh\nexit 0\n")
        with self.assertRaises(sg.HookError):
            sg.install_prepush_hook(self.repo)
        sg.install_prepush_hook(self.repo, replace=True)
        sg.install_prepush_hook(self.repo)  # our own hook may be refreshed
        with open(hook) as fh:
            self.assertIn(sg.HOOK_MARK, fh.read())

    def test_not_a_repository(self):
        with self.assertRaises(sg.HookError):
            sg.install_prepush_hook(os.path.join(self.dir, "missing"))


class GhArgsTests(RemoteCase):
    def test_argv_has_force_false_and_no_shell_strings(self):
        argv = sg.update_ref_cas_gh_args("o/r", "refs/heads/main", self.c2, self.c1)
        self.assertEqual(argv, ["gh", "api", "-X", "PATCH", "repos/o/r/git/refs/heads/main",
                                "-f", "sha=" + self.c2, "-F", "force=false"])

    def test_refusals(self):
        bad_calls = [
            ("o r", "refs/heads/main", self.c2, self.c1),
            ("o/r;x", "refs/heads/main", self.c2, self.c1),
            ("o/r", "heads/main", self.c2, self.c1),
            ("o/r", "refs/heads/main", self.c2, ""),
            ("o/r", "refs/heads/main", self.c2, self.c2),
        ]
        for call in bad_calls:
            with self.assertRaises(sg.UnsafePush, msg=str(call)):
                sg.update_ref_cas_gh_args(*call)

    def test_local_ancestry_check(self):
        sg.update_ref_cas_gh_args("o/r", "refs/heads/main", self.c3, self.c1, git_dir=self.repo)
        with self.assertRaises(sg.UnsafePush):
            sg.update_ref_cas_gh_args("o/r", "refs/heads/main", self.c1, self.c3, git_dir=self.repo)


def clean(_text):
    return 0


def dirty(_text):
    return 2


GOOD_BODY = "Does a thing.\n\n" + "<!--tengoku-target:v1 {\"target\":\"roadmap/item-1\"}-->"


def check(title="Add thing", body=GOOD_BODY, **kw):
    args = dict(base="main", head="agent/thing", allowed_bases=["main"], marker_required=True, scanner=clean)
    args.update(kw)
    return sg.validate_pr(title, body, **args)


class ValidatePrTests(unittest.TestCase):
    def test_good_pr_passes(self):
        res = check()
        self.assertTrue(res.ok, res.problems)
        self.assertEqual(res.marker, {"target": "roadmap/item-1"})
        self.assertEqual(res.scan, "clean")

    def test_marker_required_and_malformed_variants_fail(self):
        bodies = [
            "no marker",
            "<!--tengoku-target:v2 {\"target\":\"x\"}-->",
            "<!--tengoku-target:v1 {\"target\":\"x\"}",
            "<!--tengoku-target:v1 not json-->",
            "<!--tengoku-target:v1 {\"target\":\"x\",\"target\":\"y\"}-->",
            "<!--tengoku-target:v1 {\"target\":\"x\",\"extra\":\"y\"}-->",
            "<!--tengoku-target:v1 {\"target\":5}-->",
            "<!--tengoku-target:v1 {\"target\":\"has space\"}-->",
            "<!--tengoku-target:v1 {}-->",
            "<!--tengoku-target:v1 [\"x\"]-->",
            "<!--tengoku-target:v1 {\"target\":\"x\"\n}-->",
            GOOD_BODY + "\n<!--tengoku-target:v1 {\"target\":\"other\"}-->",
            "<!--tengoku-target:v1 {\"target\":\"x\",\"base\":\"release\"}-->",
        ]
        for b in bodies:
            self.assertFalse(check(body=b).ok, b)

    def test_marker_optional_when_not_required_but_checked_if_present(self):
        self.assertTrue(check(body="plain", marker_required=False).ok)
        self.assertFalse(check(body="<!--tengoku-target:v1 junk-->", marker_required=False).ok)

    def test_make_marker_round_trips_and_validates(self):
        m = sg.make_marker("a/b", actor="agent-1")
        self.assertTrue(check(body="x\n" + m).ok)
        with self.assertRaises(ValueError):
            sg.make_marker("bad id")

    def test_base_allowlist_and_head(self):
        self.assertFalse(check(base="release").ok)
        self.assertFalse(check(allowed_bases=[]).ok)
        self.assertFalse(check(head="main").ok)
        self.assertFalse(check(head="--force").ok)
        self.assertFalse(check(head="a b").ok)
        self.assertFalse(check(head="agent/x\n").ok)
        self.assertTrue(check(base="release", allowed_bases=["main", "release"]).ok)

    def test_title_and_body_limits(self):
        self.assertFalse(check(title="").ok)
        self.assertFalse(check(title="x" * 300).ok)
        self.assertFalse(check(title="two\nlines").ok)
        self.assertFalse(check(body=GOOD_BODY + "x" * 70000).ok)
        self.assertFalse(check(body=GOOD_BODY + "\x00").ok)
        self.assertFalse(check(title="t <!--tengoku-target:v1 {}-->").ok)
        self.assertTrue(check(body=GOOD_BODY + "\ttabs and\r\nnewlines are fine").ok)

    def test_secret_scan_found_unavailable_and_crash(self):
        res = check(scanner=dirty)
        self.assertFalse(res.ok)
        self.assertEqual(res.scan, "found")
        self.assertNotIn("ghp_", " ".join(res.problems))

        def boom(_t):
            raise RuntimeError("scanner exploded")

        res = check(scanner=boom)
        self.assertFalse(res.ok)
        self.assertEqual(res.scan, "unavailable")
        with mock.patch.object(sg, "_default_scanner", return_value=None):
            lenient = check(scanner=None)
            strict = check(scanner=None, require_scan=True)
        self.assertTrue(lenient.ok)
        self.assertEqual(lenient.scan, "unavailable")
        self.assertFalse(strict.ok)
        self.assertIn("unavailable", " ".join(strict.problems))

    def test_real_secretscan_integration_when_present(self):
        try:
            import warden.secretscan  # noqa: F401
        except ImportError:
            self.skipTest("warden.secretscan not available")
        token = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        res = sg.validate_pr("Add thing", GOOD_BODY + "\ntoken: " + token, base="main", head="agent/t",
                             allowed_bases=["main"], require_scan=True)
        self.assertFalse(res.ok)
        self.assertEqual(res.scan, "found")
        ok = sg.validate_pr("Add thing", GOOD_BODY, base="main", head="agent/t", allowed_bases=["main"],
                            require_scan=True)
        self.assertTrue(ok.ok, ok.problems)

    def test_non_string_input_fails_closed(self):
        self.assertFalse(sg.validate_pr(None, "b", base="main", head="h", allowed_bases=["main"]).ok)


class PrCreateArgvTests(unittest.TestCase):
    def test_argv_only_after_validation(self):
        argv = sg.pr_create_argv("Add thing", GOOD_BODY, base="main", head="agent/thing",
                                 allowed_bases=["main"], scanner=clean, repo="o/r", draft=True)
        self.assertEqual(argv[:3], ["gh", "pr", "create"])
        self.assertEqual(argv[argv.index("--base") + 1], "main")
        self.assertEqual(argv[argv.index("--title") + 1], "Add thing")
        self.assertEqual(argv[argv.index("--repo") + 1], "o/r")
        self.assertIn("--draft", argv)

    def test_refuses_with_reasons(self):
        with self.assertRaises(sg.PRRefused) as cm:
            sg.pr_create_argv("Add thing", "no marker", base="main", head="agent/thing",
                              allowed_bases=["main"], scanner=clean)
        self.assertIn("marker", str(cm.exception))
        with self.assertRaises(sg.PRRefused):
            sg.pr_create_argv("Add thing", GOOD_BODY, base="evil", head="agent/thing",
                              allowed_bases=["main"], scanner=clean)
        with self.assertRaises(sg.PRRefused):
            sg.pr_create_argv("Add thing", GOOD_BODY, base="main", head="agent/thing",
                              allowed_bases=["main"], scanner=dirty)
        with self.assertRaises(sg.PRRefused):
            sg.pr_create_argv("Add thing", GOOD_BODY, base="main", head="agent/thing",
                              allowed_bases=["main"], scanner=clean, repo="not a slug")


if __name__ == "__main__":
    unittest.main()

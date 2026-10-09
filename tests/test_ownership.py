"""Tests for warden.ownership: generation, CODEOWNERS semantics and divergence detection."""
from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest

from tests import gitfixture as gf
from warden import ownership as ow
from warden import scope

POLICY = {
    "human": ["/.github/", "AGENTS.md", "TauCeti/Core.lean"],
    "agent": ["TauCeti/", "lean-toolchain"],
    "review": ["TauCeti/**"],
}
HUMANS = "@org/humans"


def gen(**kw):
    return ow.to_codeowners(POLICY, HUMANS, **kw)


class SemanticsTests(unittest.TestCase):
    def test_last_match_wins(self):
        rules, bad = ow.parse_codeowners("* @a\n/docs/ @b\n/docs/secret.md @c\n*.md @d\n")
        self.assertEqual(bad, [])
        self.assertEqual(ow.owners_for(rules, "src/x.py"), ("@a",))
        self.assertEqual(ow.owners_for(rules, "docs/x.txt"), ("@b",))
        self.assertEqual(ow.owners_for(rules, "docs/secret.md"), ("@d",))  # *.md is later
        self.assertEqual(ow.owners_for(rules, "docs/secret.txt"), ("@b",))
        self.assertEqual(ow.owners_for(rules, "docs/secret.md.bak"), ("@b",))

    def test_ownerless_line_removes_ownership(self):
        rules, _ = ow.parse_codeowners("* @a\nTauCeti/\n")
        self.assertEqual(ow.owners_for(rules, "TauCeti/X.lean"), ())
        self.assertEqual(ow.owners_for(rules, "README.md"), ("@a",))

    def test_comments_inline_comments_and_blank_lines(self):
        rules, _ = ow.parse_codeowners("# c\n\n* @a  # trailing\n   # indented\n")
        self.assertEqual(rules, [("*", ("@a",))])

    def test_unsupported_syntax_is_reported_not_guessed(self):
        rules, bad = ow.parse_codeowners("* @a\n!docs/ @b\nfile[0-9].txt @c\n")
        self.assertEqual(sorted(bad), ["!docs/", "file[0-9].txt"])
        self.assertEqual(rules, [("*", ("@a",))])

    def test_single_star_does_not_cross_directories_but_double_star_does(self):
        rules, _ = ow.parse_codeowners("* @a\ndocs/* @b\nlib/** @c\n")
        self.assertEqual(ow.owners_for(rules, "docs/x.md"), ("@b",))
        self.assertEqual(ow.owners_for(rules, "docs/sub/x.md"), ("@a",))
        self.assertEqual(ow.owners_for(rules, "lib/a/b/c.py"), ("@c",))


class GenerateTests(unittest.TestCase):
    def test_default_agent_then_human_order_and_ownerless_comments(self):
        text = gen()
        lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
        self.assertEqual(lines, ["* @org/humans", "TauCeti/", "lean-toolchain", "/.github/ @org/humans",
                                 "AGENTS.md @org/humans", "TauCeti/Core.lean @org/humans"])
        self.assertIn("# ai-gated (ownerless): TauCeti/", text)
        rules, _ = ow.parse_codeowners(text)
        self.assertEqual(ow.owners_for(rules, "TauCeti/Foo.lean"), ())
        self.assertEqual(ow.owners_for(rules, "TauCeti/Core.lean"), (HUMANS,))  # human carve-out wins
        self.assertEqual(ow.owners_for(rules, ".github/ci.yml"), (HUMANS,))

    def test_agent_owner_variant(self):
        text = gen(agent_owner="@bots")
        rules, _ = ow.parse_codeowners(text)
        self.assertEqual(ow.owners_for(rules, "TauCeti/Foo.lean"), ("@bots",))

    def test_bad_owner_and_bad_policy_are_refused(self):
        with self.assertRaises(ow.OwnershipError):
            ow.to_codeowners(POLICY, "humans")
        with self.assertRaises(ow.OwnershipError):
            ow.to_codeowners(POLICY, HUMANS, "@x y")
        for bad in ({"human": [], "agent": []}, dict(POLICY, extra=[]), dict(POLICY, human="x"),
                    dict(POLICY, human=["a"], agent=["a"]), dict(POLICY, agent=["!no"]),
                    dict(POLICY, agent=["a", "a"]), [], "x"):
            self.assertTrue(ow.validate_policy(bad), bad)
            with self.assertRaises(ow.OwnershipError):
                ow.to_review_allowlist(bad)

    def test_review_must_lie_inside_agent_paths(self):
        self.assertEqual(ow.validate_policy(POLICY), [])
        outside = dict(POLICY, review=["docs/**"])
        self.assertTrue(ow.validate_policy(outside))
        over_human = dict(POLICY, review=["TauCeti/Core.lean"])
        self.assertTrue(ow.validate_policy(over_human))
        self.assertEqual(ow.to_review_allowlist(POLICY), ["TauCeti/**"])

    def test_scope_policy_is_accepted_by_scope_module_and_enforces_the_same_split(self):
        d = ow.to_scope_policy(POLICY, extra={"max_files": 50})
        pol = scope.Policy.from_dict(d)
        self.assertEqual(pol.max_files, 50)
        with tempfile.TemporaryDirectory() as tmp:
            gf.patch_env()
            try:
                repo = gf.init_repo(os.path.join(tmp, "r"))
                base = gf.commit(repo, {"TauCeti/Core.lean": "c\n", "TauCeti/Other.lean": "o\n",
                                        "AGENTS.md": "a\n", "README.md": "r\n"})
                ok = gf.commit(repo, {"TauCeti/Other.lean": "o2\n"})
                self.assertTrue(scope.check(repo, base, ok, pol, "agent").ok)
                for path in ("TauCeti/Core.lean", "AGENTS.md", "README.md"):
                    head = gf.commit(repo, {path: "changed by agent\n"})
                    res = scope.check(repo, ok, head, pol, "agent")
                    self.assertFalse(res.ok, path)
                    ok = head
                self.assertTrue(scope.check(repo, base, ok, pol, "human").ok)
            finally:
                gf.restore_env()


class DivergenceTests(unittest.TestCase):
    def test_generated_file_is_in_step(self):
        self.assertEqual(ow.divergence(gen(), POLICY), [])
        self.assertEqual(ow.divergence(gen(agent_owner="@bots"), POLICY, agent_owner="@bots"), [])

    def test_textually_different_but_equivalent_file_is_in_step(self):
        text = ("# my own comments\n* @org/humans\n\nTauCeti/\nTauCeti/Core.lean   @org/humans\n"
                "lean-toolchain\n/.github/ @org/humans # ci\nAGENTS.md @org/humans\n")
        self.assertEqual(ow.divergence(text, POLICY), [])

    def test_anchoring_difference_is_a_real_divergence(self):
        text = gen().replace("\nTauCeti/\n", "\n/TauCeti/\n").replace("(ownerless): /TauCeti/", "(ownerless): TauCeti/")
        diffs = ow.divergence(text, POLICY)
        self.assertTrue(any(d.probe == "deep/dir/TauCeti/x.txt" for d in diffs), diffs)

    def test_missing_ownerless_agent_path_is_caught(self):
        text = gen().replace("lean-toolchain\n", "")
        diffs = ow.divergence(text, POLICY)
        self.assertTrue(any(d.probe == "lean-toolchain" and d.committed == "human" and d.expected == "ownerless"
                            for d in diffs), diffs)

    def test_extra_human_owner_on_agent_path_is_caught(self):
        text = gen().replace("\nTauCeti/\n", "\nTauCeti/ @org/humans\n", 1)
        diffs = ow.divergence(text, POLICY)
        self.assertTrue(any(d.probe and d.probe.startswith("TauCeti/") for d in diffs), diffs)

    def test_wrong_order_breaks_human_carve_out(self):
        lines = gen().splitlines()
        i = next(n for n, ln in enumerate(lines) if ln == "TauCeti/")
        lines.append(lines.pop(i))  # agent rule moved last: it now overrides the human carve-out
        diffs = ow.divergence("\n".join(lines) + "\n", POLICY)
        self.assertTrue(any(d.probe == "TauCeti/Core.lean" for d in diffs), diffs)

    def test_missing_default_and_wrong_owner_and_unsupported_lines(self):
        no_default = "\n".join(ln for ln in gen().splitlines() if not ln.startswith("* "))
        self.assertTrue(any("default" in d.why for d in ow.divergence(no_default, POLICY)))
        other_owner = gen().replace("AGENTS.md @org/humans", "AGENTS.md @someone")
        diffs = ow.divergence(other_owner, POLICY)
        self.assertTrue(any(d.probe == "AGENTS.md" for d in diffs))
        weird = gen() + "!docs/\nfoo[ab].txt @x\n"
        self.assertEqual(sum(1 for d in ow.divergence(weird, POLICY) if d.why.startswith("pattern syntax")), 2)

    def test_extra_committed_rule_that_changes_ownership_is_caught(self):
        text = gen() + "docs/ @somebody-else\n"
        diffs = ow.divergence(text, POLICY)
        self.assertTrue(any(d.probe and d.probe.startswith("docs/") for d in diffs), diffs)

    def test_later_star_rule_hides_everything_before_it(self):
        text = gen() + "* @org/humans\n"
        self.assertTrue(ow.divergence(text, POLICY))


class CliTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.dir = td.name
        self.policy = os.path.join(self.dir, "agent-paths.json")
        with open(self.policy, "w") as fh:
            json.dump(POLICY, fh)

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ow.main(list(args))
        return code, out.getvalue()

    def test_generate_then_check_round_trip_exit_codes(self):
        code, text = self.run_cli("--policy", self.policy, "--generate", "--human-owner", HUMANS)
        self.assertEqual(code, 0)
        path = os.path.join(self.dir, "CODEOWNERS")
        with open(path, "w") as fh:
            fh.write(text)
        self.assertEqual(self.run_cli("--policy", self.policy, "--check", path)[0], 0)
        with open(path, "w") as fh:
            fh.write(text.replace("lean-toolchain\n", ""))
        code, out = self.run_cli("--policy", self.policy, "--check", path)
        self.assertEqual(code, 1)
        self.assertIn("lean-toolchain", out)

    def test_bad_input_exits_2(self):
        self.assertEqual(self.run_cli("--policy", os.path.join(self.dir, "none.json"), "--generate",
                                      "--human-owner", HUMANS)[0], 2)
        self.assertEqual(self.run_cli("--policy", self.policy, "--generate")[0], 2)  # no owner
        self.assertEqual(self.run_cli("--policy", self.policy, "--check", os.path.join(self.dir, "none"))[0], 2)
        self.assertEqual(self.run_cli("--policy", self.policy, "--generate", "--check", "x")[0], 2)
        bad = os.path.join(self.dir, "dup.json")
        with open(bad, "w") as fh:
            fh.write('{"human": [], "human": [], "agent": [], "review": []}')
        self.assertEqual(self.run_cli("--policy", bad, "--scope-policy")[0], 2)

    def test_emit_scope_policy_and_review_allowlist(self):
        code, out = self.run_cli("--policy", self.policy, "--scope-policy")
        self.assertEqual(code, 0)
        scope.Policy.from_dict(json.loads(out))
        code, out = self.run_cli("--policy", self.policy, "--review-allowlist")
        self.assertEqual((code, out.split()), (0, ["TauCeti/**"]))


if __name__ == "__main__":
    unittest.main()

import contextlib
import io
import json
import os
import tempfile
import unittest

from warden import eligibility as el

APP = 3947238
REPO = "o/r"
HEAD = "1" * 40
BASE = "2" * 40
D = lambda c: "sha256:" + c * 64
VERDICT = {"decision": "ACCEPT", "evidence_digest": D("e"), "policy_sha256": D("a"), "reasons": ["free text that must not be copied"]}
CASE = {"repo": REPO, "head_sha": HEAD, "class": "other"}


def check(cid=10, app=APP, **over):
    body = el.build_check_run(VERDICT, CASE, BASE, 7)
    c = {"id": cid, "app": {"id": app}, "name": body["name"], "head_sha": body["head_sha"], "status": "completed", "conclusion": body["conclusion"], "external_id": body["external_id"]}
    c.update(over)
    return c


def ext(**over):
    base = dict(repo=REPO, pr=7, head_sha=HEAD, merge_base=BASE, decision="ACCEPT", verdict_digest=D("b"), policy_sha256=D("a"), evidence_digest=D("e"))
    base.update(over)
    return el.build_external_id(**base)


def verify(checks, **kw):
    args = dict(expected_app_id=APP, repo=REPO, pr=7, live_head=HEAD, live_merge_base=BASE, block_labels=el.DEFAULT_BLOCK_LABELS, labels=())
    args.update(kw)
    return el.verify_check(checks, **args)


class BuildTest(unittest.TestCase):
    def test_check_run_body_and_mapping(self):
        body = el.build_check_run(VERDICT, CASE, BASE, 7)
        self.assertEqual((body["name"], body["status"], body["head_sha"]), ("merge eligibility", "completed", HEAD))
        self.assertEqual(body["conclusion"], "success")
        self.assertNotIn("free text", json.dumps(body))
        payload = json.loads(body["external_id"])
        self.assertEqual(payload["schema"], "tengoku-merge.eligibility/v1")
        self.assertEqual(set(payload), set(el._KEYS))
        self.assertEqual(payload["evidence_digest"], D("e"))
        self.assertEqual(payload["verdict_digest"], el.digest_of(VERDICT))
        for dec, concl in (("HOLD", "neutral"), ("ESCALATE", "neutral"), ("REJECT", "failure")):
            self.assertEqual(el.build_check_run(dict(VERDICT, decision=dec), CASE, BASE, 7)["conclusion"], concl)

    def test_builder_rejects_bad_input(self):
        for v, c, mb, pr in [
            (dict(VERDICT, decision="MAYBE"), CASE, BASE, 7),
            (VERDICT, dict(CASE, head_sha="abc"), BASE, 7),
            (VERDICT, CASE, "xyz", 7),
            (VERDICT, CASE, BASE, 0),
            (VERDICT, CASE, BASE, True),
            (dict(VERDICT, evidence_digest="nope"), CASE, BASE, 7),
            (VERDICT, dict(CASE, repo="no-slash"), BASE, 7),
            ("verdict", CASE, BASE, 7),
        ]:
            with self.assertRaises(ValueError):
                el.build_check_run(v, c, mb, pr)


class VerifyTest(unittest.TestCase):
    def test_happy_path_admits(self):
        a = verify([check()])
        self.assertEqual((a.decision, a.reasons, a.check_id), ("admit", ("eligible",), 10))

    def test_forged_app_id_cannot_admit_or_hide(self):
        self.assertEqual(verify([check(app=999)]).decision, "wait")
        # a forged success from another App with a HIGHER id does not hide the real failure
        real_fail = check(cid=5, conclusion="failure", external_id=ext(decision="REJECT"))
        forged = check(cid=50, app=999)
        self.assertEqual(verify([forged, real_fail]).decision, "cancel")
        # app ids must be exact integers
        self.assertEqual(verify([check(app="3947238")]).decision, "wait")
        self.assertEqual(verify([check(app=True)], expected_app_id=1).decision, "wait")

    def test_wrong_head_waits(self):
        self.assertEqual(verify([check()], live_head="3" * 40).reasons, ("stale_head",))
        self.assertEqual(verify([check(head_sha="3" * 40)]).decision, "wait")
        # payload head disagrees with the check's own head: someone edited one of them
        self.assertEqual(verify([check(external_id=ext(head_sha="3" * 40))]).reasons, ("payload_head_mismatch",))

    def test_replay_on_different_evidence_or_policy(self):
        c = check()
        self.assertEqual(verify([c], expected_evidence_digest=D("e")).decision, "admit")
        self.assertEqual(verify([c], expected_evidence_digest=D("f")).reasons, ("evidence_digest_mismatch",))
        self.assertEqual(verify([c], expected_policy_sha256=D("c")).reasons, ("policy_mismatch",))

    def test_replay_on_other_pr_or_repo(self):
        self.assertEqual(verify([check(external_id=ext(pr=8))]).reasons, ("wrong_repo_or_pr",))
        self.assertEqual(verify([check(external_id=ext(repo="evil/r"))]).reasons, ("wrong_repo_or_pr",))
        self.assertEqual(verify([check()], repo="O/R").decision, "admit")  # GitHub names are case-insensitive

    def test_malformed_external_id_waits(self):
        good = json.loads(ext())
        bad = [
            "not json",
            "[]",
            "",
            None,
            json.dumps(dict(good, schema="other/v1")),
            json.dumps(dict(good, extra="x")),
            json.dumps({k: v for k, v in good.items() if k != "evidence_digest"}),
            json.dumps(dict(good, pr="7")),
            json.dumps(dict(good, pr=True)),
            json.dumps(dict(good, merge_base="abc")),
            json.dumps(dict(good, merge_base="A" * 40)),
            json.dumps(dict(good, decision="accept")),
            json.dumps(dict(good, evidence_digest="sha256:short")),
            "x" * 5000,
        ]
        for b in bad:
            a = verify([check(external_id=b)])
            self.assertEqual((a.decision, a.reasons), ("wait", ("external_id_malformed",)), b)

    def test_conclusion_mismatch_waits_never_admits(self):
        # payload says REJECT but the check says success, and vice versa
        self.assertEqual(verify([check(conclusion="success", external_id=ext(decision="REJECT"))]).reasons, ("conclusion_mismatch",))
        self.assertEqual(verify([check(conclusion="failure")]).reasons, ("conclusion_mismatch",))
        self.assertEqual(verify([check(conclusion="neutral")]).reasons, ("conclusion_mismatch",))
        for odd in ("cancelled", "timed_out", "skipped", None, "SUCCESS"):
            self.assertEqual(verify([check(conclusion=odd)]).decision, "wait")

    def test_stale_merge_base_waits(self):
        a = verify([check()], live_merge_base="9" * 40)
        self.assertEqual((a.decision, a.reasons), ("wait", ("merge_base_stale",)))
        self.assertEqual(verify([check()], live_merge_base="short").reasons, ("live_merge_base_invalid",))
        self.assertEqual(verify([check()], live_merge_base=None).decision, "wait")

    def test_block_labels(self):
        for lab in el.DEFAULT_BLOCK_LABELS:
            self.assertEqual(verify([check()], labels=["bug", lab]).decision, "ignore")
        self.assertEqual(verify([check()], labels=["HOLD"]).decision, "ignore")
        self.assertEqual(verify([check()], labels=["bug", "needs-review"]).decision, "admit")
        self.assertEqual(verify([check()], labels=["custom"], block_labels=["custom"]).decision, "ignore")

    def test_highest_id_wins_even_when_it_is_worse(self):
        old_ok = check(cid=1)
        new_fail = check(cid=2, conclusion="failure", external_id=ext(decision="REJECT"))
        self.assertEqual(verify([old_ok, new_fail]).decision, "cancel")
        self.assertEqual(verify([new_fail, old_ok]).decision, "cancel")  # order of the list is irrelevant
        newest_broken = check(cid=3, external_id="garbage")
        self.assertEqual(verify([old_ok, newest_broken]).decision, "wait")  # not skipped in favour of the older success
        newer_ok = check(cid=4)
        self.assertEqual(verify([new_fail, newer_ok]).decision, "admit")

    def test_neutral_waits_without_cancelling_and_failure_cancels(self):
        neutral = check(conclusion="neutral", external_id=ext(decision="HOLD"))
        a = verify([neutral])
        self.assertEqual((a.decision, a.reasons), ("wait", ("review_not_accepted",)))
        self.assertEqual(verify([check(conclusion="neutral", external_id=ext(decision="ESCALATE"))]).decision, "wait")
        fail = check(conclusion="failure", external_id=ext(decision="REJECT"))
        self.assertEqual(verify([fail]).decision, "cancel")
        # a failure from the wrong App, or for a stale head, cancels nothing
        self.assertEqual(verify([dict(fail, app={"id": 5})]).decision, "wait")
        self.assertEqual(verify([fail], live_head="4" * 40).decision, "wait")

    def test_missing_or_pending_evidence_waits(self):
        self.assertEqual(verify([]).reasons, ("no_eligibility_check",))
        self.assertEqual(verify(None).decision, "wait")
        self.assertEqual(verify("nope").decision, "wait")
        self.assertEqual(verify([check(status="in_progress", conclusion=None)]).reasons, ("check_not_completed",))
        self.assertEqual(verify([check(name="other check")]).reasons, ("no_eligibility_check",))
        self.assertEqual(verify([check(name="Merge Eligibility")]).decision, "wait")
        self.assertEqual(verify(["junk", None, 5, {"id": "x"}]).decision, "wait")
        self.assertEqual(verify([check(id=True)]).decision, "wait")

    def test_trailing_newline_is_not_a_valid_sha_or_digest(self):
        self.assertEqual(verify([check()], live_head=HEAD + "\n").reasons, ("bad_expectation",))
        self.assertEqual(verify([check()], live_merge_base=BASE + "\n").reasons, ("live_merge_base_invalid",))
        with self.assertRaises(ValueError):
            ext(head_sha=HEAD + "\n")
        with self.assertRaises(ValueError):
            ext(evidence_digest=D("e") + "\n")

    def test_bad_expectations_fail_closed(self):
        for kw in (dict(expected_app_id=0), dict(expected_app_id="1"), dict(pr=0), dict(live_head="abc"), dict(repo="x")):
            self.assertEqual(verify([check()], **kw).reasons, ("bad_expectation",))


class CliTest(unittest.TestCase):
    def run_cli(self, checks, extra=()):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "checks.json")
            with open(p, "w", encoding="utf-8") as fh:
                if isinstance(checks, str):
                    fh.write(checks)
                else:
                    json.dump({"check_runs": checks}, fh)
            argv = ["verify", "--checks", p, "--app-id", str(APP), "--repo", REPO, "--pr", "7", "--head", HEAD, "--merge-base", BASE] + list(extra)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = el.main(argv)
            return code, out.getvalue()

    def test_exit_codes(self):
        code, out = self.run_cli([check()])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["decision"], "admit")
        self.assertEqual(self.run_cli([check()], ["--label", "hold"])[0], 1)
        self.assertEqual(self.run_cli([])[0], 1)
        self.assertEqual(self.run_cli("{not json")[0], 2)
        self.assertEqual(self.run_cli('{"check_runs": 5}')[0], 2)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(el.main(["verify", "--checks", "/nonexistent/x.json", "--app-id", "1", "--repo", REPO, "--pr", "7", "--head", HEAD, "--merge-base", BASE]), 2)
            self.assertEqual(el.main(["verify"]), 2)
            self.assertEqual(el.main([]), 2)


if __name__ == "__main__":
    unittest.main()

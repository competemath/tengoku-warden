import unittest

from warden import ciclean as cc

SHA = "a" * 40
DIGEST = "b" * 64


def api_run(**kw):
    r = {
        "id": 1001,
        "run_attempt": 2,
        "name": "ci",
        "path": ".github/workflows/ci.yml",
        "event": "pull_request",
        "status": "completed",
        "conclusion": "failure",
        "head_sha": SHA,
        "head_branch": "feature",
        "actor": {"login": "alice"},
        "triggering_actor": {"login": "agent-runner"},
        "created_at": "2026-10-09T10:00:00Z",
        "run_started_at": "2026-10-09T10:00:30Z",
        "updated_at": "2026-10-09T10:20:30Z",
        "repository": {"full_name": "o/r"},
    }
    r.update(kw)
    return r


def api_job(**kw):
    j = {
        "id": 55,
        "name": "build",
        "status": "completed",
        "conclusion": "failure",
        "labels": ["self-hosted", "linux"],
        "runner_name": "runner-1",
        "created_at": "2026-10-09T10:00:31Z",
        "started_at": "2026-10-09T10:01:01Z",
        "completed_at": "2026-10-09T10:20:01Z",
        "steps": [
            {"number": 1, "name": "checkout", "conclusion": "success", "started_at": "2026-10-09T10:01:02Z", "completed_at": "2026-10-09T10:01:05Z"},
            {"number": 2, "name": "build", "conclusion": "failure", "started_at": "2026-10-09T10:01:05Z", "completed_at": "2026-10-09T10:19:59Z"},
        ],
    }
    j.update(kw)
    return j


class RunRecordTest(unittest.TestCase):
    def test_normalised_fields_and_durations(self):
        rec = cc.run_record(api_run(), {"jobs": [api_job()]}, "sha256:" + DIGEST)
        self.assertEqual((rec["run_id"], rec["attempt"], rec["repo"]), (1001, 2, "o/r"))
        self.assertEqual((rec["actor"], rec["triggering_actor"]), ("alice", "agent-runner"))
        self.assertEqual(rec["queue_s"], 30)
        self.assertEqual(rec["duration_s"], 20 * 60)
        j = rec["jobs"][0]
        self.assertEqual((j["queue_s"], j["duration_s"]), (30, 19 * 60))
        self.assertEqual(j["runner_labels"], ["linux", "self-hosted"])
        self.assertEqual(j["failed_step"]["number"], 2)
        self.assertEqual(rec["api_response_sha256"], "sha256:" + DIGEST)
        self.assertTrue(rec["jobs_complete"])

    def test_incomplete_jobs_flagged_not_hidden(self):
        rec = cc.run_record(api_run(), [api_job()], DIGEST, jobs_total_count=3)
        self.assertFalse(rec["jobs_complete"])

    def test_hostile_payloads_rejected(self):
        bad = [
            dict(api_run(), id=True),
            dict(api_run(), id=-1),
            dict(api_run(), head_sha="abc"),
            dict(api_run(), head_sha="A" * 40),
            dict(api_run(), created_at="yesterday"),
            dict(api_run(), run_attempt=0),
        ]
        for r in bad:
            with self.assertRaises(ValueError, msg=r):
                cc.run_record(r, [], DIGEST)
        for bd in ("zz", "sha256:12", None, "b" * 63):
            with self.assertRaises(ValueError):
                cc.run_record(api_run(), [], bd)
        with self.assertRaises(ValueError):
            cc.run_record(api_run(), "jobs", DIGEST)
        with self.assertRaises(ValueError):
            cc.run_record(api_run(), [api_job(id="x")], DIGEST)
        with self.assertRaises(ValueError):
            cc.run_record("run", [], DIGEST)

    def test_negative_duration_and_control_chars_neutralised(self):
        rec = cc.run_record(api_run(updated_at="2026-10-09T09:00:00Z", name="a\x1b[31mb\x00" + "x" * 500), [], DIGEST)
        self.assertIsNone(rec["duration_s"])
        self.assertNotIn("\x00", rec["workflow"])
        self.assertLessEqual(len(rec["workflow"]), 200)

    def test_missing_triggering_actor_is_none_not_actor(self):
        r = api_run()
        del r["triggering_actor"]
        self.assertIsNone(cc.run_record(r, [], DIGEST)["triggering_actor"])


TS = "2026-10-09T10:%02d:%02d.%07dZ "


def L(minute, sec, text):
    return (TS % (minute, sec, 1234567)) + text


class ExcerptTest(unittest.TestCase):
    def test_ansi_stripped_truncated_and_capped(self):
        log = "\n".join(
            [L(1, 6, "\x1b[31;1merror\x1b[0m: " + "x" * 400)] + [L(1, 7, "error: line %d" % i) for i in range(60)]
        )
        ex = cc.failure_excerpt(log)
        self.assertEqual(len(ex), 30)
        self.assertEqual(len(ex[0]), 300)
        self.assertTrue(ex[0].startswith("error: xxx"))
        self.assertNotIn("\x1b", "".join(ex))
        self.assertEqual(ex[-1], "error: line 59")  # tail kept: that is where exit codes and watchdogs print

    def test_echoed_workflow_command_source_skipped_but_real_annotation_kept(self):
        log = "\n".join(
            [
                L(1, 6, '##[group]Run echo "::error::Lint failed"'),
                L(1, 6, 'echo "::error::Lint failed"'),
                L(1, 6, "shell: /usr/bin/bash -e {0}"),
                L(1, 6, "::error file=a.py,line=3::Lint failed"),
                L(1, 6, "##[error]Lint failed"),
                L(1, 7, "##[error]Process completed with exit code 1."),
            ]
        )
        ex = cc.failure_excerpt(log)
        self.assertEqual(ex, ["##[error]Lint failed", "##[error]Process completed with exit code 1."])

    def test_step_window_selects_only_the_failing_step(self):
        log = "\n".join(
            [
                L(1, 3, "error: from the checkout step"),
                L(1, 10, "error: inside the build step"),
                "ERROR continued without a stamp, so it still belongs to the build step",
                L(1, 11, "error: still inside"),
                L(30, 0, "error: after the step"),
                "an untimestamped error line that follows the out-of-window line",
            ]
        )
        ex = cc.failure_excerpt(log, ("2026-10-09T10:01:05Z", "2026-10-09T10:01:15Z"))
        self.assertEqual(ex, ["error: inside the build step", "ERROR continued without a stamp, so it still belongs to the build step", "error: still inside"])
        self.assertEqual(cc.failure_excerpt(log, ("garbage", "2026-10-09T10:01:15Z")), [])
        self.assertEqual(cc.failure_excerpt(log, ("2026-10-09T10:05:00Z", "2026-10-09T10:01:15Z")), [])

    def test_non_string_input(self):
        self.assertEqual(cc.failure_excerpt(None), [])


class ClassifierGoldenTest(unittest.TestCase):
    def test_version_constant(self):
        self.assertIsInstance(cc.VERSION, int)

    def test_killed_substring_trap(self):
        # The TauCetiCI defect: module names containing 'Killed' made 271 of 274 'timeout' jobs. Our rules cannot do that.
        trap = [
            "error: Mathlib/Order/KilledByRank.lean:12:3: unknown identifier 'foo'",
            "error: ././././Mathlib/Order/KilledByRank.lean:12:3: unknown identifier 'foo'",
        ]
        self.assertEqual(cc.classify_failure(trap[:1]), ("build", "build.lean_error"))
        for line in (
            "\u2716 [3012/3300] Building Mathlib.Order.KilledByRank",
            "info: Mathlib.Order.KilledByRank: declaration uses sorry",
        ):
            self.assertEqual(cc.classify_failure([line]), ("unknown", "none"), line)
        for line in ("12 Killed things", "x KilledByRank", "KilledByRank", "Process Killed by user", "It was Killed.", "3 Killed"):
            self.assertNotEqual(cc.classify_failure([line])[0], "timeout")
            self.assertEqual(cc.classify_failure([line]), ("unknown", "none"), line)

    def test_real_sigkill_is_killed_not_timeout(self):
        line = "/home/runner/work/_temp/9f3c.sh: line 1:  4242 Killed                  lake build"
        self.assertEqual(cc.classify_failure([line]), ("killed", "killed.shell_job_message"))
        self.assertEqual(cc.classify_failure(["Killed"]), ("killed", "killed.shell_job_message"))
        self.assertEqual(cc.classify_failure(["##[error]Process completed with exit code 137."]), ("killed", "killed.exit_137"))

    def test_real_timeouts(self):
        golden = {
            "##[error]The job running on runner GitHub Actions 12 has exceeded the maximum execution time of 360 minutes.": "timeout.gha_job_limit",
            "The action 'Build' has timed out after 30 minutes.": "timeout.gha_step_limit",
            "##[error]Process completed with exit code 124.": "timeout.coreutils_exit_124",
            "timeout: sending signal TERM to command 'lake'": "timeout.coreutils_signal",
            "lean-watchdog: deadline exceeded after 3000s": "timeout.watchdog_deadline",
        }
        for line, rid in golden.items():
            self.assertEqual(cc.classify_failure([line]), ("timeout", rid), line)

    def test_timeout_wins_over_build_error_lines_and_anchors_need_whole_lines(self):
        ex = ["error: A/B.lean:1:1: foo", "##[error]Process completed with exit code 124."]
        self.assertEqual(cc.classify_failure(ex)[0], "timeout")
        # a line that merely MENTIONS a watchdog message does not count
        self.assertEqual(cc.classify_failure(["note: grep 'Process completed with exit code 124' in the docs"])[0], "unknown")
        self.assertEqual(cc.classify_failure(["see lean-watchdog: deadline exceeded for details, not " + "x" * 400])[0], "unknown")

    def test_other_classes_and_edges(self):
        self.assertEqual(cc.classify_failure(["##[error]The operation was canceled."]), ("cancelled", "cancelled.gha_operation_canceled"))
        self.assertEqual(cc.classify_failure(["Out of memory: Killed process 77 (lean) total-vm:1kB"])[0], "oom")
        self.assertEqual(cc.classify_failure(["##[error]The runner has received a shutdown signal. This can happen when the runner service is stopped."])[0], "runner_lost")
        self.assertEqual(cc.classify_failure(["##[error]Process completed with exit code 1."]), ("exit_nonzero", "exit.generic"))
        self.assertEqual(cc.classify_failure("error: build failed\n"), ("build", "build.lake_build_failed"))
        self.assertEqual(cc.classify_failure([]), ("unknown", "empty_excerpt"))
        self.assertEqual(cc.classify_failure(None), ("unknown", "bad_input"))
        self.assertEqual(cc.classify_failure(["\x1b[1m##[error]Process completed with exit code 124.\x1b[0m"])[0], "timeout")

    def test_log_to_class_end_to_end_with_the_trap_in_the_log(self):
        log = "\n".join(
            [
                L(1, 6, "\x1b[1mBuilding Mathlib.Order.KilledByRank\x1b[0m"),
                L(1, 7, "error: Mathlib/Order/KilledByRank.lean:9:2: type mismatch"),
                L(1, 8, "error: build failed"),
                L(1, 8, "##[error]Process completed with exit code 1."),
            ]
        )
        ex = cc.failure_excerpt(log)
        self.assertEqual(cc.classify_failure(ex), ("build", "build.lean_error"))

    def test_every_rule_is_fully_anchored_and_ids_unique(self):
        ids = [r.rule_id for r in cc.RULES]
        self.assertEqual(len(ids), len(set(ids)))
        for r in cc.RULES:
            self.assertTrue(r.pattern.pattern.startswith("^"), r.rule_id)
            self.assertTrue(r.pattern.pattern.endswith("$") or r.pattern.pattern.endswith("$)"), r.rule_id)


def run(rid, status="completed", created="2026-10-09T10:00:00Z", attempt=1, started=None):
    d = {"id": rid, "run_attempt": attempt, "status": status, "created_at": created}
    if started:
        d["run_started_at"] = started
    return d


class PlanTest(unittest.TestCase):
    def test_oldest_first_within_budget_and_holds_reported(self):
        runs = [
            run(3, created="2026-10-09T10:03:00Z"),
            run(1, created="2026-10-09T10:01:00Z"),
            run(2, created="2026-10-09T10:02:00Z"),
            run(4, status="in_progress", created="2026-10-09T10:04:00Z"),
            run(5, created="2026-10-09T10:05:00Z"),
            run(5, created="2026-10-09T10:05:00Z"),  # duplicate
            {"id": "x"},
            run(9, created="nonsense"),
        ]
        plan = cc.plan_collection({(5, 1), "9:1"}, runs, 2)
        self.assertEqual(plan.fetch, [(1, 1), (2, 1)])
        self.assertEqual(plan.deferred, [3])
        self.assertEqual(plan.pending, [4])
        self.assertEqual(plan.already_recorded, [(5, 1)])
        self.assertEqual(len(plan.skipped_invalid), 2)

    def test_new_attempt_of_recorded_run_is_fetched_and_bad_budget_rejected(self):
        plan = cc.plan_collection({(1, 1)}, [run(1, attempt=2)], 5)
        self.assertEqual(plan.fetch, [(1, 2)])
        for bad in (-1, True, 1.5, None):
            with self.assertRaises(ValueError):
                cc.plan_collection([], [], bad)
        self.assertEqual(cc.plan_collection([], [run(1)], 0).deferred, [1])


NOW = "2026-10-09T12:00:00Z"  # window end is 11:45:00 with the default 15 minute lag


class WatermarkTest(unittest.TestCase):
    def adv(self, prev, rec, prog, total, **kw):
        return cc.advance_watermark(prev, rec, prog, total, NOW, **kw)

    def test_all_recorded_and_reconciled_advances_to_window_end(self):
        rec = [run(1, created="2026-10-09T10:00:00Z"), run(2, created="2026-10-09T11:00:00Z")]
        res = self.adv("2026-10-09T09:00:00Z", rec, [], 2)
        self.assertTrue(res.advanced)
        self.assertEqual(res.watermark, "2026-10-09T11:45:00Z")
        self.assertEqual(res.window, ("2026-10-09T09:00:00Z", "2026-10-09T11:45:00Z"))

    def test_missing_run_refuses_incident_2026_09_27(self):
        # the API says 3 runs exist in the window but only 2 were recorded: do NOT move past the missing one
        rec = [run(1, created="2026-10-09T10:00:00Z"), run(3, created="2026-10-09T11:00:00Z")]
        res = self.adv("2026-10-09T09:00:00Z", rec, [], 3)
        self.assertFalse(res.advanced)
        self.assertEqual(res.watermark, "2026-10-09T09:00:00Z")
        self.assertIn("count_mismatch", res.reasons)

    def test_silent_repo_recording_nothing_refuses_incident_2026_10_01(self):
        res = self.adv("2026-10-06T09:00:00Z", [], [], 40)
        self.assertFalse(res.advanced)
        self.assertEqual(res.reasons[0], "count_mismatch")
        # a genuinely empty window is fine
        self.assertTrue(self.adv("2026-10-09T09:00:00Z", [], [], 0).advanced)

    def test_in_progress_run_holds_the_watermark_back(self):
        rec = [run(1, created="2026-10-09T10:00:00Z")]
        prog = [run(2, status="in_progress", created="2026-10-09T10:30:00Z", started="2026-10-09T10:31:00Z")]
        res = self.adv("2026-10-09T09:00:00Z", rec, prog, 2)
        self.assertTrue(res.advanced)
        self.assertEqual(res.watermark, "2026-10-09T10:30:00Z")
        self.assertEqual(res.held_by, [2])
        # the held run sits exactly at the watermark already: no movement
        res = self.adv("2026-10-09T10:30:00Z", [], prog, 1)
        self.assertFalse(res.advanced)
        self.assertEqual(res.watermark, "2026-10-09T10:30:00Z")

    def test_stuck_run_over_six_hours_stops_holding(self):
        now = "2026-10-10T12:00:00Z"
        prog = [run(2, status="queued", created="2026-10-10T01:00:00Z", started="2026-10-10T01:00:00Z")]
        res = cc.advance_watermark("2026-10-10T00:00:00Z", [], prog, 1, now)
        self.assertTrue(res.advanced)
        self.assertEqual(res.watermark, "2026-10-10T11:45:00Z")
        self.assertIn("stuck:2", res.reasons)
        fresh = [run(2, status="queued", created="2026-10-10T08:00:00Z", started="2026-10-10T08:00:00Z")]  # 4 h old: still holds
        res = cc.advance_watermark("2026-10-10T00:00:00Z", [], fresh, 1, now)
        self.assertEqual(res.watermark, "2026-10-10T08:00:00Z")

    def test_unrecorded_completed_run_holds(self):
        rec = [run(1, created="2026-10-09T10:00:00Z")]
        late = [run(2, created="2026-10-09T10:10:00Z")]  # completed but over the job budget
        res = self.adv("2026-10-09T09:00:00Z", rec, [], 2, unrecorded_runs=late)
        self.assertEqual(res.watermark, "2026-10-09T10:10:00Z")

    def test_bad_inputs_refuse(self):
        for kw in (
            dict(prev="not a time", rec=[], prog=[], total=0),
            dict(prev="2026-10-09T09:00:00Z", rec=[], prog=[], total=None),
            dict(prev="2026-10-09T09:00:00Z", rec=[], prog=[], total=-1),
            dict(prev="2026-10-09T09:00:00Z", rec=[], prog=[], total=True),
            dict(prev="2026-10-09T09:00:00Z", rec=[{"id": 1}], prog=[], total=1),
        ):
            res = self.adv(kw["prev"], kw["rec"], kw["prog"], kw["total"])
            self.assertFalse(res.advanced, kw)
            self.assertEqual(res.watermark, kw["prev"])
        res = cc.advance_watermark("2026-10-09T09:00:00Z", [], [], 0, "garbage")
        self.assertFalse(res.advanced)

    def test_run_listed_twice_and_out_of_window_runs(self):
        r = run(1, created="2026-10-09T10:00:00Z")
        res = self.adv("2026-10-09T09:00:00Z", [r], [dict(r, status="in_progress")], 1)
        self.assertEqual(res.reasons, ["run_listed_twice"])
        early = run(7, created="2026-10-09T08:00:00Z")  # before the window: ignored, not counted
        late = run(8, created="2026-10-09T11:50:00Z")  # inside the lag: ignored, not counted
        res = self.adv("2026-10-09T09:00:00Z", [early, late, r], [], 1)
        self.assertTrue(res.advanced)

    def test_empty_window_and_bootstrap(self):
        res = cc.advance_watermark("2026-10-09T11:50:00Z", [], [], 0, NOW)
        self.assertFalse(res.advanced)
        self.assertEqual(res.reasons, ["empty_window"])
        boot = cc.advance_watermark(None, [run(1, created="2026-10-01T00:00:00Z")], [], 1, NOW)
        self.assertTrue(boot.advanced)
        self.assertEqual(cc.window_for(None, NOW), (None, "2026-10-09T11:45:00Z"))


def rr(actor, conclusion, trig=None, rid=[0]):
    rid[0] += 1
    return {"repo": "o/r", "run_id": rid[0], "attempt": 1, "actor": actor, "triggering_actor": trig or actor, "conclusion": conclusion}


class RatesTest(unittest.TestCase):
    def test_wilson_known_values(self):
        lo, hi = cc.wilson(5, 10)
        self.assertAlmostEqual(lo, 0.2366, places=3)
        self.assertAlmostEqual(hi, 0.7634, places=3)
        self.assertEqual(cc.wilson(0, 0), None)
        lo, hi = cc.wilson(0, 20)
        self.assertEqual(lo, 0.0)
        self.assertGreater(hi, 0.1)

    def test_by_actor_and_agent_breakdown(self):
        recs = (
            [rr("alice", "success") for _ in range(8)]
            + [rr("alice", "failure") for _ in range(2)]
            + [rr("bot-account", "failure") for _ in range(6)]
            + [rr("bot-account", "success") for _ in range(4)]
            + [rr("bot-account", "cancelled"), rr("bot-account", None), rr("zed", "timed_out")]
        )
        out = cc.failure_rates(recs, {"bot-account": "claude-opus"})
        self.assertEqual(out["overall"]["n"], 21)
        self.assertEqual(out["by_actor"]["alice"]["failures"], 2)
        self.assertAlmostEqual(out["by_actor"]["bot-account"]["rate"], 0.6)
        self.assertEqual(out["by_agent"]["claude-opus"]["n"], 10)  # cancelled / in-progress excluded
        self.assertEqual(out["by_agent"]["unattributed"]["n"], 11)
        self.assertEqual(out["by_agent"]["unattributed"]["failures"], 3)
        self.assertLess(out["by_agent"]["claude-opus"]["wilson_low"], 0.6)
        self.assertGreater(out["by_agent"]["claude-opus"]["wilson_high"], 0.6)

    def test_rerun_by_human_still_attributed_and_duplicates_once(self):
        a = rr("bot-account", "failure", trig="alice")
        out = cc.failure_rates([a, dict(a)], {"bot-account": "agent-x"})
        self.assertEqual(out["overall"]["n"], 1)
        self.assertEqual(out["by_agent"]["agent-x"]["n"], 1)
        self.assertIn("alice", out["by_triggering_actor"])
        self.assertEqual(cc.failure_rates([], {})["overall"]["rate"], None)


if __name__ == "__main__":
    unittest.main()

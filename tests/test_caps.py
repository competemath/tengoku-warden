import contextlib
import io
import json
import os
import tempfile
import unittest

from warden import caps
from warden.caps import Budget, BudgetDenied, Caps, Ledger, LedgerError, GENESIS, entry_hash


def _rd(p):
    with open(p, encoding="utf-8") as fh:
        return fh.read()


def _wr(p, text, mode="w"):
    with open(p, mode, encoding="utf-8", errors="surrogateescape") as fh:
        fh.write(text)


def _budget(tmp, **kw):
    base = dict(per_day_usd=10, per_case_usd=5, max_usd=2, initial_estimate_usd=0.5, min_samples=5, min_estimate_usd=0.01)
    base.update(kw)
    return Budget(Ledger(os.path.join(tmp, "ledger.jsonl")), Caps(**base))


class LedgerChainTest(unittest.TestCase):
    def test_format_matches_juridicator_and_verifies(self):
        with tempfile.TemporaryDirectory() as d:
            led = Ledger(os.path.join(d, "l.jsonl"))
            e0 = led.append("a", {"x": 1})
            e1 = led.append("b", {"y": "é"})
            self.assertEqual(e0["prev"], GENESIS)
            self.assertEqual(GENESIS, "sha256:" + "0" * 64)
            self.assertEqual(e1["prev"], e0["hash"])
            expected = "sha256:" + __import__("hashlib").sha256(
                json.dumps({"seq": 1, "kind": "b", "body": {"y": "é"}, "prev": e0["hash"]}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
            ).hexdigest()
            self.assertEqual(e1["hash"], expected)
            self.assertEqual(entry_hash(1, "b", {"y": "é"}, e0["hash"]), expected)
            self.assertEqual(led.verify(), (True, None))
            self.assertEqual(led.verify(expected_head=e1["hash"]), (True, None))

    def test_tamper_and_truncation_detected(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "l.jsonl")
            led = Ledger(p)
            led.append("a", {"x": 1})
            head = led.append("b", {"x": 2})["hash"]
            led.append("c", {"x": 3})
            raw = _rd(p)
            _wr(p, raw.replace('"x":1', '"x":9').replace('"x": 1', '"x": 9'))
            self.assertEqual(led.verify(), (False, 0))
            _wr(p, raw)
            self.assertTrue(led.verify()[0])
            lines = raw.splitlines(True)
            _wr(p, "".join(lines[:2]))
            self.assertTrue(led.verify()[0])
            self.assertEqual(led.verify(expected_head=led.head()), (True, None))
            ok, _ = led.verify(expected_head=json.loads(lines[2])["hash"])
            self.assertFalse(ok)
            self.assertNotEqual(head, GENESIS)

    def test_torn_duplicate_keys_nan_and_garbage_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "l.jsonl")
            led = Ledger(p)
            led.append("a", {"x": 1})
            good = _rd(p)
            for bad in (good.rstrip("\n"), good + "{not json}\n", good + "\xff\n", good.replace('"seq": 0', '"seq": 0, "seq": 0')):
                with open(p, "w", encoding="utf-8", errors="surrogateescape") as fh:
                    fh.write(bad)
                self.assertFalse(led.verify()[0], bad)
                with self.assertRaises(LedgerError):
                    led.entries()
            with self.assertRaises(ValueError):
                with open(p, "w") as fh:
                    fh.write(good)
                led.append("n", {"v": float("nan")})


class BudgetTest(unittest.TestCase):
    def test_reserve_is_written_before_it_returns(self):
        with tempfile.TemporaryDirectory() as d:
            b = _budget(d)
            r = b.reserve("case1", None, "2026-10-09")
            entries = b.ledger.entries()
            self.assertEqual([e["kind"] for e in entries], ["reserve"])  # on disk before any spend, nothing settled yet
            self.assertEqual(entries[0]["body"]["attempt"], 1)
            self.assertEqual(r.attempt, 1)
            self.assertGreater(r.estimate_usd, 0)
            b.settle(r, 0.2)
            self.assertEqual([e["kind"] for e in b.ledger.entries()], ["reserve", "settle"])

    def test_attempt_counted_even_if_never_settled(self):
        with tempfile.TemporaryDirectory() as d:
            b = _budget(d, max_attempts_per_case=2)
            b.reserve("c", None, "2026-10-09")  # crash here: never settled
            b.reserve("c", None, "2026-10-09")
            with self.assertRaises(BudgetDenied) as cm:
                b.reserve("c", None, "2026-10-09")
            self.assertEqual(cm.exception.code, "attempt_cap")

    def test_balance_never_negative_and_overrun_recorded(self):
        with tempfile.TemporaryDirectory() as d:
            b = _budget(d, per_day_usd=1, per_case_usd=1)
            r = b.reserve("c", 0.5, "2026-10-09")
            s = b.settle(r, 100.0)  # absurd overshoot
            self.assertEqual(s.day_remaining_usd, 0.0)
            self.assertEqual(s.case_remaining_usd, 0.0)
            self.assertGreater(s.overrun_usd, 0)
            st = b.status("2026-10-09", "c")
            self.assertGreaterEqual(st["day_remaining_usd"], 0)
            self.assertLessEqual(st["day_spent_usd"], 1.0)
            self.assertIn("overrun", [e["kind"] for e in b.ledger.entries()])
            with self.assertRaises(BudgetDenied):
                b.reserve("other", 0.01, "2026-10-09")  # the day is exhausted

    def test_settle_twice_or_unknown_refused(self):
        with tempfile.TemporaryDirectory() as d:
            b = _budget(d)
            r = b.reserve("c", None, "2026-10-09")
            b.settle(r, 0.1)
            with self.assertRaises(BudgetDenied) as cm:
                b.settle(r, 0.1)
            self.assertEqual(cm.exception.code, "already_closed")
            with self.assertRaises(BudgetDenied):
                b.settle("r99", 0.1)
            r2 = b.reserve("c", None, "2026-10-09")
            for bad in (-1, float("nan"), float("inf"), True, "x"):
                with self.assertRaises(BudgetDenied):
                    b.settle(r2, bad)
            self.assertEqual(b.settle(r2, 0.0).actual_usd, 0.0)  # still open after the bad attempts

    def test_corrupt_or_unreadable_ledger_denies(self):
        with tempfile.TemporaryDirectory() as d:
            b = _budget(d)
            r = b.reserve("c", None, "2026-10-09")
            p = b.ledger.path
            good = _rd(p)
            _wr(p, good.replace("reserve", "reserveX", 1))
            with self.assertRaises(BudgetDenied) as cm:
                b.reserve("c2", None, "2026-10-09")
            self.assertEqual(cm.exception.code, "ledger_corrupt")
            with self.assertRaises(BudgetDenied):
                b.settle(r, 0.1)
            with self.assertRaises(BudgetDenied):
                b.status("2026-10-09")
            _wr(p, good + "garbage\n")
            with self.assertRaises(BudgetDenied) as cm:
                b.reserve("c2", None, "2026-10-09")
            self.assertEqual(cm.exception.code, "ledger_corrupt")
            os.remove(p)
            os.mkdir(p)  # unreadable as a file
            with self.assertRaises(BudgetDenied) as cm:
                b.reserve("c2", None, "2026-10-09")
            self.assertEqual(cm.exception.code, "ledger_corrupt")

    def test_semantic_inconsistency_denies(self):
        with tempfile.TemporaryDirectory() as d:
            b = _budget(d)
            b.ledger.append("settle", {"rid": "r0", "actual_micro": 1})  # chain-valid but settles nothing
            with self.assertRaises(BudgetDenied) as cm:
                b.reserve("c", None, "2026-10-09")
            self.assertEqual(cm.exception.code, "ledger_corrupt")

    def test_deleted_ledger_denied_when_new_not_allowed(self):
        with tempfile.TemporaryDirectory() as d:
            b = Budget(Ledger(os.path.join(d, "none.jsonl")), Caps(), allow_new=False)
            with self.assertRaises(BudgetDenied) as cm:
                b.reserve("c", None, "2026-10-09")
            self.assertEqual(cm.exception.code, "ledger_corrupt")

    def test_estimate_grows_after_overruns(self):
        with tempfile.TemporaryDirectory() as d:
            b = _budget(d, per_day_usd=1000, per_case_usd=1000, max_attempts_per_case=None, max_usd=3)
            for i in range(12):
                b.settle(b.reserve("k%d" % i, None, "2026-10-09"), 0.10)
            before = b.current_estimate_usd()
            self.assertAlmostEqual(before, 0.10, places=6)  # p99 of past costs, not the 0.5 prior
            r = b.reserve("big", None, "2026-10-09")
            s = b.settle(r, 2.0)
            self.assertGreater(s.overrun_usd, 0)
            after = b.current_estimate_usd()
            self.assertGreater(after, before)
            self.assertGreaterEqual(after, 2.0)
            self.assertGreaterEqual(b.reserve("next", None, "2026-10-09").estimate_usd, 2.0)

    def test_caller_estimate_can_only_raise(self):
        with tempfile.TemporaryDirectory() as d:
            b = _budget(d)
            low = b.reserve("a", 0.0001, "2026-10-09")
            self.assertGreaterEqual(low.estimate_usd, 0.5)  # the prior, not the caller's tiny number
            high = b.reserve("b", 1.5, "2026-10-09")
            self.assertEqual(high.estimate_usd, 1.5)
            capped = b.reserve("c", 99, "2026-10-09")
            self.assertEqual(capped.estimate_usd, 2.0)  # clipped to max_usd

    def test_day_case_caps_and_rollover(self):
        with tempfile.TemporaryDirectory() as d:
            b = _budget(d, per_day_usd=1.2, per_case_usd=1.0, initial_estimate_usd=0.5, max_attempts_per_case=None)
            b.reserve("c", None, "2026-10-09")
            b.reserve("c", None, "2026-10-09")  # case at 1.0
            with self.assertRaises(BudgetDenied) as cm:
                b.reserve("c", None, "2026-10-09")
            self.assertEqual(cm.exception.code, "case_cap")
            with self.assertRaises(BudgetDenied) as cm:
                b.reserve("d", None, "2026-10-09")  # day has 0.2 left
            self.assertEqual(cm.exception.code, "day_cap")
            r = b.reserve("d", None, "2026-10-10")  # new day string, fresh day budget
            self.assertEqual(r.day, "2026-10-10")
            with self.assertRaises(BudgetDenied) as cm:
                b.reserve("c", None, "2026-10-10")  # the case cap does not reset
            self.assertEqual(cm.exception.code, "case_cap")
            for bad in ("2026-13-01", "10/09/2026", "", None, "2026-10-09T00:00", "2026-10-09\n"):
                with self.assertRaises(BudgetDenied):
                    b.reserve("x", None, bad)

    def test_hard_cap_clipped_to_room_left(self):
        with tempfile.TemporaryDirectory() as d:
            b = _budget(d, per_day_usd=1.0, per_case_usd=5, max_usd=2, initial_estimate_usd=0.4)
            r = b.reserve("c", None, "2026-10-09")
            self.assertEqual(r.hard_cap_usd, 1.0)  # not 2.0: the day cannot cover a run that large
            self.assertEqual(r.estimate_usd, 0.4)

    def test_refunds_bounded_and_only_when_open(self):
        with tempfile.TemporaryDirectory() as d:
            b = _budget(d, max_refunds_per_case=1, max_attempts_per_case=2)
            r1 = b.reserve("c", None, "2026-10-09")
            b.refund(r1, "outage")
            self.assertEqual(b.status("2026-10-09", "c")["case_attempts"], 0)
            r2 = b.reserve("c", None, "2026-10-09")
            with self.assertRaises(BudgetDenied) as cm:
                b.refund(r2)
            self.assertEqual(cm.exception.code, "refund_cap")
            b.settle(r2, 0.1)
            with self.assertRaises(BudgetDenied):
                b.refund(r2)  # already settled: money was spent
            with self.assertRaises(BudgetDenied):
                b.refund(r1)  # already refunded

    def test_command_rendering(self):
        with tempfile.TemporaryDirectory() as d:
            b = _budget(d, max_turns=7, max_seconds=90)
            r = b.reserve("c", None, "2026-10-09")
            cmd = b.command(["claude", "-p", "go"], r)
            self.assertEqual(cmd[:3], ["timeout", "--kill-after=30", "90"])
            self.assertEqual(cmd[-4:], ["--max-turns", "7", "--max-budget-usd", "2"])
            with self.assertRaises(BudgetDenied):
                b.command(["claude", "--max-turns=999"], r)

    def test_cli_verify(self):
        with tempfile.TemporaryDirectory() as d:
            led = Ledger(os.path.join(d, "l.jsonl"))
            led.append("a", {})
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(caps.main(["verify", led.path]), 0)
                _wr(led.path, "junk\n", "a")
                self.assertEqual(caps.main(["verify", led.path]), 1)
                self.assertEqual(caps.main(["bogus"]), 2)


if __name__ == "__main__":
    unittest.main()

"""Hard spend and effort caps for agent invocations, kept in an append-only hash-chained ledger.

What it does: every agent invocation first `reserve`s money from a per-day and a per-case budget, then runs under hard
per-invocation limits (`--max-turns N`, `--max-budget-usd X`, and a `timeout` prefix), then `settle`s with the real cost.
All state (balances, attempt counts, refunds, the cost history behind the next estimate) is replayed from the ledger; there
is no separate mutable file to edit or lose. A corrupt, unreadable or inconsistent ledger denies every reservation.

Credit: the Tau Ceti Project (TauCetiWorker and TauCetiReview) showed which spend controls are worth having and where they leak.
Their worker counts fix attempts before checkout (commit 539df22, after a PR was churned all night) and bounds outage refunds
(<= 20 per head); the review path reserves budget before spending and fails closed on a corrupt ledger; the Claude API ledger
added in TauCetiWorker PR #241 (2026-10-08) is an append-only, fsynced admission control. Our research reports on those repos
(2026-10-09) also recorded the gaps: no per-session turn or dollar cap, a flat $1 reservation below the p99 cost (2.9% of runs
exceed it), a local budget that can go negative, and caps only per head or PR. The ledger entry format below is the same as the
tengoku-juridicator ledger on purpose, so the two interoperate.

What we do differently: (1) the reservation is a rolling p99 of past costs, never a constant, and an overrun tightens the next
one; (2) every invocation carries a hard turn, wall-clock and dollar cap rendered as CLI flags, with the dollar flag clipped to
what the day and the case still have, so the sum cannot be driven past the caps by one runaway run; (3) settling can never push
a balance below zero (the shortfall is recorded as an `overrun` entry, and reported balances are clamped to [0, cap]);
(4) caps exist per invocation, per day and per case, not only per head; (5) refunds are bounded and only possible for a still-open
reservation (an outage, nothing spent), while the attempt itself is counted before the fragile step; (6) the chain can be
checked against a head published out of band, which catches a deleted tail or a replaced file.

Limits, stated honestly: the dollar flag is enforced by the agent CLI between turns, so one turn can overshoot it; the ledger is
only as trustworthy as the directory it lives in (publish `Ledger.head()` somewhere the agent cannot write); without `fcntl`
(not POSIX) the ledger is not safe against two processes writing at once; `timeout` is GNU coreutils (`gtimeout` on macOS).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import re
import sys
from dataclasses import dataclass
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal, InvalidOperation
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

try:  # POSIX advisory locking; absent elsewhere (documented limit)
    import fcntl  # type: ignore
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore

GENESIS = "sha256:" + "0" * 64
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}\Z")
_DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\Z")
_MICRO = 1_000_000


class LedgerError(Exception):
    """The ledger is corrupt, unreadable or inconsistent. Callers must treat this as 'deny'."""

    def __init__(self, index: Optional[int], message: str) -> None:
        super().__init__("ledger entry %s: %s" % (index, message) if index is not None else message)
        self.index = index
        self.message = message


class BudgetDenied(Exception):
    """A reservation (or refund) was refused. `code` is a stable machine-readable reason."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__("%s: %s" % (code, detail) if detail else code)
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------- chain primitives (shared with audit.py)


def canonical_json(obj: Any) -> str:
    """The same canonical form tengoku-juridicator uses: sorted keys, no spaces, UTF-8 characters kept."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry_hash(seq: int, kind: str, body: Any, prev: str) -> str:
    text = canonical_json({"seq": seq, "kind": kind, "body": body, "prev": prev})
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _reject_constant(name: str) -> Any:
    raise ValueError("non-finite number %s" % name)


def _no_duplicate_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key %r" % k)
        out[k] = v
    return out


def parse_chain(data: bytes, prev: str = GENESIS, seq0: int = 0) -> Tuple[List[Dict[str, Any]], str]:
    """Parse and verify NDJSON chain bytes. Returns (entries, head). Raises LedgerError at the first bad entry.

    Strict on purpose: UTF-8 only, every line a JSON object with exactly the keys seq/kind/body/prev/hash, no duplicate keys,
    no NaN, no torn final line, contiguous `seq`, each `prev` the previous `hash`, each `hash` recomputed.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise LedgerError(0, "not valid UTF-8")
    if text and not text.endswith("\n"):
        raise LedgerError(len([x for x in text.split("\n") if x.strip()]) - 1, "torn final line (no newline)")
    entries: List[Dict[str, Any]] = []
    for line in text.split("\n"):
        if not line.strip():
            continue
        i = len(entries)
        try:
            e = json.loads(line, parse_constant=_reject_constant, object_pairs_hook=_no_duplicate_keys)
        except ValueError as exc:
            raise LedgerError(i, "unparseable line (%s)" % str(exc)[:80])
        if not isinstance(e, dict) or set(e) != {"seq", "kind", "body", "prev", "hash"}:
            raise LedgerError(i, "wrong keys")
        seq = e["seq"]
        if isinstance(seq, bool) or not isinstance(seq, int) or seq != seq0 + i:
            raise LedgerError(i, "bad sequence number")
        if not isinstance(e["kind"], str) or not isinstance(e["body"], dict):
            raise LedgerError(i, "bad kind or body")
        if e["prev"] != prev:
            raise LedgerError(i, "prev does not match the previous hash")
        if not isinstance(e["hash"], str) or not _HASH_RE.match(e["hash"]):
            raise LedgerError(i, "malformed hash")
        if e["hash"] != entry_hash(seq, e["kind"], e["body"], prev):
            raise LedgerError(i, "hash does not match the content")
        prev = e["hash"]
        entries.append(e)
    return entries, prev


def make_entry(seq: int, kind: str, body: Dict[str, Any], prev: str) -> Dict[str, Any]:
    if not isinstance(kind, str) or not kind:
        raise ValueError("kind must be a non-empty string")
    if not isinstance(body, dict):
        raise ValueError("body must be a dict")
    json.dumps(body, allow_nan=False)  # raises on NaN / inf
    return {"seq": seq, "kind": kind, "body": body, "prev": prev, "hash": entry_hash(seq, kind, body, prev)}


def entry_line(entry: Dict[str, Any]) -> bytes:
    return (json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def lock_fd(fd: int) -> None:
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_EX)


def write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]
    os.fsync(fd)


def read_all(fd: int) -> bytes:
    size = os.fstat(fd).st_size
    chunks = []
    off = 0
    while off < size:
        chunk = os.pread(fd, min(1 << 20, size - off), off)
        if not chunk:
            break
        chunks.append(chunk)
        off += len(chunk)
    return b"".join(chunks)


# --------------------------------------------------------------------------- the ledger


class _Txn:
    def __init__(self, fd: int, entries: List[Dict[str, Any]], head: str) -> None:
        self._fd = fd
        self.entries = entries
        self.head = head

    def append(self, kind: str, body: Dict[str, Any]) -> Dict[str, Any]:
        entry = make_entry(len(self.entries), kind, body, self.head)
        write_all(self._fd, entry_line(entry))
        self.entries.append(entry)
        self.head = entry["hash"]
        return entry


class Ledger:
    """Append-only, hash-chained JSONL. Entry hash = sha256 of the canonical JSON of {seq, kind, body, prev}."""

    def __init__(self, path: str) -> None:
        self.path = str(path)

    def _read(self) -> Tuple[List[Dict[str, Any]], str]:
        try:
            fd = os.open(self.path, os.O_RDONLY)
        except FileNotFoundError:
            return [], GENESIS
        except OSError as exc:
            raise LedgerError(None, "unreadable: %s" % exc.__class__.__name__)
        try:
            return parse_chain(read_all(fd))
        except OSError as exc:
            raise LedgerError(None, "unreadable: %s" % exc.__class__.__name__)
        finally:
            os.close(fd)

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def entries(self) -> List[Dict[str, Any]]:
        """Verified entries. Raises LedgerError when anything is wrong (never returns a partial list)."""
        return self._read()[0]

    def head(self) -> str:
        return self._read()[1]

    @contextlib.contextmanager
    def atomic(self, create: bool = True) -> Iterator[_Txn]:
        """Lock the file, verify the whole chain, and let the caller append under that lock."""
        flags = os.O_RDWR | os.O_APPEND | (os.O_CREAT if create else 0)
        try:
            fd = os.open(self.path, flags, 0o600)
        except FileNotFoundError:
            raise LedgerError(None, "ledger file does not exist")
        except OSError as exc:
            raise LedgerError(None, "unreadable: %s" % exc.__class__.__name__)
        try:
            try:
                lock_fd(fd)
                entries, head = parse_chain(read_all(fd))
            except OSError as exc:
                raise LedgerError(None, "unreadable: %s" % exc.__class__.__name__)
            yield _Txn(fd, entries, head)
        finally:
            os.close(fd)

    def append(self, kind: str, body: Dict[str, Any]) -> Dict[str, Any]:
        with self.atomic() as txn:
            return txn.append(kind, body)

    def verify(self, expected_head: Optional[str] = None) -> Tuple[bool, Optional[int]]:
        """(True, None) when intact, else (False, index of the first bad entry). With the published head a removed tail is caught."""
        try:
            entries, head = self._read()
        except LedgerError as exc:
            return False, exc.index if exc.index is not None else 0
        if expected_head is not None and head != expected_head:
            return False, len(entries)
        return True, None


# --------------------------------------------------------------------------- money helpers


def _micro(usd: Any, up: bool) -> int:
    if isinstance(usd, bool) or not isinstance(usd, (int, float, str, Decimal)):
        raise ValueError("amount must be a number")
    try:
        d = Decimal(str(usd))
    except InvalidOperation:
        raise ValueError("amount is not a number")
    if not d.is_finite() or d < 0:
        raise ValueError("amount must be finite and non-negative")
    return int((d * _MICRO).to_integral_value(ROUND_CEILING if up else ROUND_FLOOR))


def _usd(micro: int) -> float:
    return micro / _MICRO


def _fmt_usd(micro: int) -> str:
    s = "%d.%06d" % (micro // _MICRO, micro % _MICRO)
    return s.rstrip("0").rstrip(".") if "." in s else s


def percentile_nearest_rank(values: Sequence[int], q: float) -> int:
    ordered = sorted(values)
    rank = max(1, int(math.ceil(q * len(ordered))))
    return ordered[min(rank, len(ordered)) - 1]


# --------------------------------------------------------------------------- budget


@dataclass(frozen=True)
class Caps:
    """Limits. `max_*` apply to one invocation, `per_day_usd` to one day string, `per_case_usd` to one case key forever."""

    max_turns: int = 30
    max_seconds: int = 3600
    max_usd: float = 5.0
    per_day_usd: float = 50.0
    per_case_usd: float = 10.0
    max_attempts_per_case: Optional[int] = 3
    max_refunds_per_case: int = 2
    initial_estimate_usd: float = 1.0  # prior used until `min_samples` costs have been seen
    min_estimate_usd: float = 0.05
    window: int = 200  # how many recent settled costs the rolling p99 looks at
    min_samples: int = 20
    overrun_memory: int = 10  # a recent overrun keeps the estimate at least that high for this many settlements

    def __post_init__(self) -> None:
        for name in ("max_turns", "max_seconds", "window", "min_samples", "overrun_memory"):
            v = getattr(self, name)
            if isinstance(v, bool) or not isinstance(v, int) or v < 1:
                raise ValueError("%s must be a positive integer" % name)
        for name in ("max_usd", "per_day_usd", "per_case_usd", "initial_estimate_usd", "min_estimate_usd"):
            if _micro(getattr(self, name), True) <= 0:
                raise ValueError("%s must be positive" % name)
        if self.max_attempts_per_case is not None and (
            isinstance(self.max_attempts_per_case, bool) or not isinstance(self.max_attempts_per_case, int) or self.max_attempts_per_case < 1
        ):
            raise ValueError("max_attempts_per_case must be None or a positive integer")
        if isinstance(self.max_refunds_per_case, bool) or not isinstance(self.max_refunds_per_case, int) or self.max_refunds_per_case < 0:
            raise ValueError("max_refunds_per_case must be a non-negative integer")


@dataclass(frozen=True)
class Reservation:
    rid: str
    case_key: str
    day: str
    estimate_usd: float
    hard_cap_usd: float  # the value rendered into --max-budget-usd
    attempt: int
    max_turns: int
    max_seconds: int


@dataclass(frozen=True)
class Settlement:
    rid: str
    estimate_usd: float
    actual_usd: float
    overrun_usd: float
    day_remaining_usd: float
    case_remaining_usd: float


class _State:
    """Everything the budget needs, replayed from the ledger entries. Raises LedgerError on an inconsistent history."""

    def __init__(self, entries: Sequence[Dict[str, Any]], caps: Caps) -> None:
        self.res: Dict[str, Dict[str, Any]] = {}
        self.samples: List[int] = []  # settled actual costs, oldest first
        self.overruns: List[Tuple[int, int]] = []  # (index into samples, actual)
        for e in entries:
            kind, b = e["kind"], e["body"]
            try:
                if kind == "reserve":
                    rid = b["rid"]
                    if rid in self.res:
                        raise LedgerError(e["seq"], "duplicate reservation id")
                    self.res[rid] = {"case": b["case"], "day": b["day"], "estimate": int(b["estimate_micro"]), "status": "open", "actual": 0}
                elif kind == "settle":
                    r = self.res.get(b["rid"])
                    if r is None or r["status"] != "open":
                        raise LedgerError(e["seq"], "settlement without an open reservation")
                    r["status"], r["actual"] = "settled", int(b["actual_micro"])
                    self.samples.append(r["actual"])
                elif kind == "overrun":
                    r = self.res.get(b["rid"])
                    if r is None or r["status"] != "settled":
                        raise LedgerError(e["seq"], "overrun without a settlement")
                    self.overruns.append((len(self.samples) - 1, int(b["actual_micro"])))
                elif kind == "refund":
                    r = self.res.get(b["rid"])
                    if r is None or r["status"] != "open":
                        raise LedgerError(e["seq"], "refund without an open reservation")
                    r["status"] = "refunded"
                else:
                    raise LedgerError(e["seq"], "unknown entry kind %r" % kind)
            except (KeyError, TypeError, ValueError):
                raise LedgerError(e["seq"], "malformed %s entry" % kind)
        self.caps = caps

    def committed(self, r: Dict[str, Any]) -> int:
        if r["status"] == "open":
            return r["estimate"]
        if r["status"] == "settled":
            return r["actual"]
        return 0

    def day_committed(self, day: str) -> int:
        return sum(self.committed(r) for r in self.res.values() if r["day"] == day)

    def case_committed(self, case: str) -> int:
        return sum(self.committed(r) for r in self.res.values() if r["case"] == case)

    def attempts(self, case: str) -> int:
        return sum(1 for r in self.res.values() if r["case"] == case and r["status"] != "refunded")

    def refunds(self, case: str) -> int:
        return sum(1 for r in self.res.values() if r["case"] == case and r["status"] == "refunded")

    def estimate_micro(self) -> int:
        """Rolling p99 of recent settled costs; the prior until enough samples exist; raised by a recent overrun."""
        c = self.caps
        recent = self.samples[-c.window:]
        if len(recent) < c.min_samples:
            est = max([_micro(c.initial_estimate_usd, True)] + recent)
        else:
            est = percentile_nearest_rank(recent, 0.99)
        floor_from = len(self.samples) - c.overrun_memory
        est = max([est] + [a for (idx, a) in self.overruns if idx >= floor_from])
        return min(max(est, _micro(c.min_estimate_usd, True)), _micro(c.max_usd, False))


def _check_key(case_key: Any) -> str:
    if not isinstance(case_key, str) or not (1 <= len(case_key) <= 200) or re.search(r"[\x00-\x1f\x7f]", case_key):
        raise BudgetDenied("bad_input", "case key must be 1-200 printable characters")
    return case_key


def _check_day(day: Any) -> str:
    import datetime

    if not isinstance(day, str) or not _DAY_RE.match(day):
        raise BudgetDenied("bad_input", "day must be YYYY-MM-DD")
    try:
        datetime.date.fromisoformat(day)
    except ValueError:
        raise BudgetDenied("bad_input", "day is not a real date")
    return day


class Budget:
    """Spend control over a `Ledger`. Day rollover is the caller's `day` string; this class never reads a clock."""

    def __init__(self, ledger: Ledger, caps: Optional[Caps] = None, *, allow_new: bool = True) -> None:
        self.ledger = ledger
        self.caps = caps or Caps()
        self.allow_new = allow_new  # False: a missing ledger file is a denial (it may have been deleted to reset the budget)

    # -- reserve / settle / refund -------------------------------------------------------------------------------

    def reserve(self, case_key: str, estimate_usd: Optional[float], day: str) -> Reservation:
        """Write the reservation (fsynced) and return it, or raise BudgetDenied. Call this BEFORE any spend.

        `estimate_usd` is the caller's own estimate; it can only raise the reservation above the rolling p99, never lower it.
        The attempt is counted here, before the fragile step, so a crash cannot make it free.
        """
        case_key = _check_key(case_key)
        day = _check_day(day)
        c = self.caps
        try:
            caller = _micro(estimate_usd, True) if estimate_usd is not None else 0
        except ValueError:
            raise BudgetDenied("bad_input", "estimate must be a finite non-negative number")
        try:
            with self.ledger.atomic(create=self.allow_new) as txn:
                st = _State(txn.entries, c)
                est = min(max(st.estimate_micro(), caller), _micro(c.max_usd, False))
                if c.max_attempts_per_case is not None and st.attempts(case_key) >= c.max_attempts_per_case:
                    raise BudgetDenied("attempt_cap", "case has used its %d attempts" % c.max_attempts_per_case)
                case_room = _micro(c.per_case_usd, False) - st.case_committed(case_key)
                day_room = _micro(c.per_day_usd, False) - st.day_committed(day)
                if est > case_room:
                    raise BudgetDenied("case_cap", "estimate %s exceeds what the case has left" % _fmt_usd(est))
                if est > day_room:
                    raise BudgetDenied("day_cap", "estimate %s exceeds what the day has left" % _fmt_usd(est))
                hard = min(_micro(c.max_usd, False), case_room, day_room)
                rid = "r%d" % len(txn.entries)
                attempt = st.attempts(case_key) + 1
                txn.append(
                    "reserve",
                    {"rid": rid, "case": case_key, "day": day, "estimate_micro": est, "hard_cap_micro": hard, "attempt": attempt},
                )
        except LedgerError as exc:
            raise BudgetDenied("ledger_corrupt", str(exc))
        return Reservation(rid, case_key, day, _usd(est), _usd(hard), attempt, c.max_turns, c.max_seconds)

    def settle(self, reservation: Any, actual_usd: float) -> Settlement:
        """Record what the invocation really cost. Never lowers the spend below the truth, never reports a negative balance."""
        rid = reservation.rid if isinstance(reservation, Reservation) else reservation
        try:
            actual = _micro(actual_usd, True)
        except ValueError:
            raise BudgetDenied("bad_input", "actual cost must be a finite non-negative number (reservation stays counted)")
        try:
            with self.ledger.atomic(create=False) as txn:
                st = _State(txn.entries, self.caps)
                r = st.res.get(rid)
                if r is None:
                    raise BudgetDenied("unknown_reservation", str(rid))
                if r["status"] != "open":
                    raise BudgetDenied("already_closed", "reservation %s is %s" % (rid, r["status"]))
                txn.append("settle", {"rid": rid, "case": r["case"], "day": r["day"], "estimate_micro": r["estimate"], "actual_micro": actual})
                over = max(0, actual - r["estimate"])
                if over:
                    txn.append(
                        "overrun",
                        {"rid": rid, "case": r["case"], "day": r["day"], "estimate_micro": r["estimate"], "actual_micro": actual, "excess_micro": over},
                    )
                st2 = _State(txn.entries, self.caps)
                day_left = max(0, _micro(self.caps.per_day_usd, False) - st2.day_committed(r["day"]))
                case_left = max(0, _micro(self.caps.per_case_usd, False) - st2.case_committed(r["case"]))
        except LedgerError as exc:
            raise BudgetDenied("ledger_corrupt", str(exc))
        return Settlement(rid, _usd(r["estimate"]), _usd(actual), _usd(over), _usd(day_left), _usd(case_left))

    def refund(self, reservation: Any, reason: str = "outage") -> None:
        """Give back an attempt whose reservation is still open (nothing was spent). Bounded by max_refunds_per_case."""
        rid = reservation.rid if isinstance(reservation, Reservation) else reservation
        if not isinstance(reason, str) or len(reason) > 80 or re.search(r"[\x00-\x1f\x7f]", reason):
            raise BudgetDenied("bad_input", "reason must be a short printable string")
        try:
            with self.ledger.atomic(create=False) as txn:
                st = _State(txn.entries, self.caps)
                r = st.res.get(rid)
                if r is None:
                    raise BudgetDenied("unknown_reservation", str(rid))
                if r["status"] != "open":
                    raise BudgetDenied("already_closed", "reservation %s is %s" % (rid, r["status"]))
                if st.refunds(r["case"]) >= self.caps.max_refunds_per_case:
                    raise BudgetDenied("refund_cap", "case has used its %d refunds" % self.caps.max_refunds_per_case)
                txn.append("refund", {"rid": rid, "case": r["case"], "day": r["day"], "reason": reason})
        except LedgerError as exc:
            raise BudgetDenied("ledger_corrupt", str(exc))

    # -- read side -----------------------------------------------------------------------------------------------

    def status(self, day: str, case_key: Optional[str] = None) -> Dict[str, Any]:
        """Balances clamped to [0, cap]. Raises BudgetDenied('ledger_corrupt') when the ledger cannot be trusted."""
        day = _check_day(day)
        try:
            st = _State(self.ledger.entries(), self.caps)
        except LedgerError as exc:
            raise BudgetDenied("ledger_corrupt", str(exc))
        c = self.caps
        out: Dict[str, Any] = {
            "estimate_usd": _usd(st.estimate_micro()),
            "day_spent_usd": _usd(min(st.day_committed(day), _micro(c.per_day_usd, False))),
            "day_remaining_usd": _usd(max(0, _micro(c.per_day_usd, False) - st.day_committed(day))),
        }
        if case_key is not None:
            k = _check_key(case_key)
            out["case_remaining_usd"] = _usd(max(0, _micro(c.per_case_usd, False) - st.case_committed(k)))
            out["case_attempts"] = st.attempts(k)
            out["case_refunds"] = st.refunds(k)
        return out

    def current_estimate_usd(self) -> float:
        try:
            return _usd(_State(self.ledger.entries(), self.caps).estimate_micro())
        except LedgerError as exc:
            raise BudgetDenied("ledger_corrupt", str(exc))

    # -- rendering -----------------------------------------------------------------------------------------------

    def cli_flags(self, reservation: Reservation) -> List[str]:
        return ["--max-turns", str(reservation.max_turns), "--max-budget-usd", _fmt_usd(_micro(reservation.hard_cap_usd, False))]

    def timeout_prefix(self, reservation: Reservation) -> List[str]:
        return ["timeout", "--kill-after=30", str(reservation.max_seconds)]

    def command(self, argv: Sequence[str], reservation: Reservation) -> List[str]:
        """`timeout ... <argv> --max-turns N --max-budget-usd X`. Pass an argv without those flags already in it."""
        if any(a in ("--max-turns", "--max-budget-usd") or a.startswith(("--max-turns=", "--max-budget-usd=")) for a in argv):
            raise BudgetDenied("bad_input", "argv already carries a cap flag")
        return self.timeout_prefix(reservation) + list(argv) + self.cli_flags(reservation)


# --------------------------------------------------------------------------- CLI


def main(argv: Optional[Sequence[str]] = None) -> int:
    """`caps verify LEDGER [--head H]` (exit 1 when the chain is broken) and `caps head LEDGER`."""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) >= 2 and args[0] == "verify":
        expected = None
        if len(args) == 4 and args[2] == "--head":
            expected = args[3]
        elif len(args) != 2:
            print("usage: caps verify LEDGER [--head H]", file=sys.stderr)
            return 2
        ok, bad = Ledger(args[1]).verify(expected)
        print(json.dumps({"ok": ok, "first_bad_entry": bad}))
        return 0 if ok else 1
    if len(args) == 2 and args[0] == "head":
        try:
            print(Ledger(args[1]).head())
        except LedgerError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    print("usage: caps verify LEDGER [--head H] | caps head LEDGER", file=sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

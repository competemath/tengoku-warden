"""Tests for warden.leases against a real local bare remote."""
from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import unittest

from tests import gitfixture as gf
from warden import leases as L
from warden import safegit

T0 = 1_700_000_000
KEY = b"k" * 32
OTHER_KEY = b"z" * 32
A = L.make_owner("alice", "11111111aaaa", "w1")
B = L.make_owner("bob", "22222222bbbb", "w2")
C = L.make_owner("carol", "33333333cccc", "w3")


def setUpModule():
    gf.patch_env()


def tearDownModule():
    gf.restore_env()


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


class LeaseCase(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.dir = td.name
        self.bare = gf.init_bare(os.path.join(self.dir, "leases.git"))
        self.clock = Clock()

    def client(self, name="c", **kw):
        repo = gf.init_repo(os.path.join(self.dir, name))
        return L.LeaseClient(repo, self.bare, self.clock, **kw)

    def raw_write(self, cl, key, message, when=T0, kind="commit", expected_old=None):
        """Plant an arbitrary lease-ref object the way a hostile collaborator with push access could."""
        env = {"GIT_AUTHOR_NAME": "x", "GIT_AUTHOR_EMAIL": "x@x", "GIT_COMMITTER_NAME": "x",
               "GIT_COMMITTER_EMAIL": "x@x", "GIT_AUTHOR_DATE": "@%d +0000" % when,
               "GIT_COMMITTER_DATE": "@%d +0000" % when}
        if kind == "blob":
            oid = gf.git(cl.repo, "hash-object", "-w", "--stdin", input_bytes=b"junk")
        else:
            tree = gf.git(cl.repo, "hash-object", "-t", "tree", "-w", "--stdin", input_bytes=b"")
            r = safegit.run_git(cl.repo, ["commit-tree", tree, "-F", "-"], env=env,
                                input_bytes=message.encode())
            oid = r.stdout.strip()
        res = safegit.push_cas(cl.repo, self.bare, L.NAMESPACE + key, oid, expected_old)
        self.assertTrue(res.ok, res)
        return oid


class PureTests(unittest.TestCase):
    def lease(self, **over):
        d = dict(key="k", owner=A, nonce="ab" * 8, issued_at=T0, expires_at=T0 + 100,
                 host_hash=L.host_hash_of(A))
        d.update(over)
        return L.Lease(**d)

    def test_sign_verify(self):
        payload = self.lease().payload()
        payload["sig"] = L.sign(payload, KEY)
        self.assertTrue(L.verify(payload, KEY))
        self.assertFalse(L.verify(payload, OTHER_KEY))
        tampered = dict(payload, owner=B)
        self.assertFalse(L.verify(tampered, KEY))
        self.assertFalse(L.verify({k: v for k, v in payload.items() if k != "sig"}, KEY))
        with self.assertRaises(ValueError):
            L.sign(payload, b"short")

    def test_parse_message_accepts_canonical_and_rejects_everything_else(self):
        good = self.lease().message()
        lease, why = L.parse_message(good + "\n", "k", T0)
        self.assertIsNotNone(lease, why)
        d = self.lease().payload()
        bad = {
            "empty": "",
            "not json": "hello",
            "array": "[]",
            "not canonical": json.dumps(d, indent=1),
            "extra field": json.dumps(dict(d, pid=123), sort_keys=True, separators=(",", ":")),
            "missing field": json.dumps({k: v for k, v in d.items() if k != "nonce"}, sort_keys=True,
                                        separators=(",", ":")),
            "key mismatch": self.lease(key="other").message(),
            "bad owner": self.lease(owner="just-a-name").message(),
            "host hash mismatch": self.lease(host_hash=L.host_hash_of(B)).message(),
            "ttl too long": self.lease(expires_at=T0 + L.DEFAULT_MAX_TTL + 1).message(),
            "zero ttl": self.lease(expires_at=T0).message(),
            "future": self.lease(issued_at=T0 + 10_000, expires_at=T0 + 10_100).message(),
            "bool time": json.dumps(dict(d, issued_at=True), sort_keys=True, separators=(",", ":")),
        }
        for name, msg in bad.items():
            lease, why = L.parse_message(msg, "k", T0)
            self.assertIsNone(lease, name)
            self.assertTrue(why, name)

    def test_message_publishes_no_host_or_pid(self):
        msg = self.lease().message()
        self.assertEqual(set(json.loads(msg)), {"key", "owner", "nonce", "issued_at", "expires_at", "host_hash"})
        self.assertNotIn(socket.gethostname().lower(), msg.lower())
        self.assertNotIn("pid", msg)

    def test_owner_and_key_validation(self):
        for bad in (("a/b", "h", "w"), ("a", "h h", "w"), ("", "h", "w"), ("a", "h", "w\n")):
            with self.assertRaises(ValueError):
                L.make_owner(*bad)
        for bad in ("", "../x", "a//b", "a b", ".hidden", "x.lock", "a/.b", "x" * 200):
            with self.assertRaises(ValueError, msg=bad):
                L.check_key(bad)
        self.assertEqual(L.check_key("branch/123"), "branch/123")

    def test_evaluate_states(self):
        ok = self.lease()
        obs = L.Observed("a" * 40, "commit", ok.message(), T0)
        kw = dict(key="k", now=T0 + 10)
        self.assertEqual(L.evaluate(obs, me=A, **kw).status, "mine")
        self.assertEqual(L.evaluate(obs, me=B, **kw).status, "held")
        self.assertEqual(L.evaluate(obs, me=A, nonce="cd" * 8, **kw).status, "held")
        self.assertEqual(L.evaluate(obs, me=A, key="k", now=T0 + 100).status, "expired")
        self.assertEqual(L.evaluate(L.Observed(None), me=A, **kw).status, "absent")

    def test_evaluate_stray_age_rules(self):
        empty = L.Observed("a" * 40, "commit", "", T0)
        self.assertEqual(L.evaluate(empty, key="k", now=T0 + 10).status, "stray_young")
        self.assertEqual(L.evaluate(empty, key="k", now=T0 + L.DEFAULT_MAX_AGE).status, "stray_reclaimable")
        future = L.Observed("a" * 40, "commit", "", T0 + 10 ** 7)
        self.assertEqual(L.evaluate(future, key="k", now=T0).status, "stray_reclaimable")
        blob = L.Observed("a" * 40, "other")
        self.assertEqual(L.evaluate(blob, key="k", now=T0).status, "stray_reclaimable")

    def test_require_signature_needs_a_verifier(self):
        with self.assertRaises(ValueError):
            L.evaluate(L.Observed(None), key="k", now=T0, require_signature=True)
        with self.assertRaises(ValueError):
            L.LeaseClient("r", "x", Clock(), require_signature=True)
        with self.assertRaises(ValueError):
            L.LeaseClient("r", "x", Clock(), on_error="whatever")


class AcquireTests(LeaseCase):
    def test_acquire_hold_renew_release(self):
        ca, cb = self.client("a"), self.client("b")
        out = ca.acquire("branch/1", A, 600)
        self.assertEqual((out.acquired, out.status), (True, "acquired"))
        denied = cb.acquire("branch/1", B, 600)
        self.assertEqual((denied.acquired, denied.proceed, denied.status), (False, False, "held"))
        self.assertEqual(denied.lease.owner, A)
        again = ca.acquire("branch/1", A, 600)  # same owner: renews, keeps the nonce
        self.assertEqual((again.status, again.lease.nonce), ("renewed", out.lease.nonce))
        self.clock.t += 100
        r = ca.renew("branch/1", A, out.lease.nonce, 600)
        self.assertEqual(r.status, "renewed")
        self.assertEqual(r.lease.expires_at, T0 + 700)
        self.assertEqual(cb.release("branch/1", B, out.lease.nonce).status, "not_holder")
        self.assertEqual(ca.release("branch/1", A, "ff" * 8).status, "not_holder")
        self.assertEqual(ca.release("branch/1", A, out.lease.nonce).status, "released")
        self.assertEqual(safegit.ls_remote(ca.repo, self.bare), {})
        self.assertEqual(cb.acquire("branch/1", B, 600).status, "acquired")

    def test_two_owners_racing_exactly_one_acquires(self):
        owners = [L.make_owner("u%d" % i, "%032x" % i, "w") for i in range(6)]
        clients = [self.client("c%d" % i) for i in range(6)]
        outs = []
        barrier = threading.Barrier(6)

        def go(cl, owner):
            barrier.wait()
            outs.append(cl.acquire("task/7", owner, 600))

        ts = [threading.Thread(target=go, args=(c, o)) for c, o in zip(clients, owners)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        winners = [o for o in outs if o.acquired]
        self.assertEqual(len(winners), 1, [o.status for o in outs])
        self.assertTrue(all(o.status in ("held", "lost_race") for o in outs if not o.acquired))
        holder = clients[0].inspect("task/7")
        self.assertEqual(holder.lease.owner, winners[0].lease.owner)

    def test_expired_lease_is_taken_over_and_old_holder_is_locked_out(self):
        ca, cb = self.client("a"), self.client("b")
        first = ca.acquire("k1", A, 100)
        self.clock.t = T0 + 99
        self.assertEqual(cb.acquire("k1", B, 100).status, "held")
        self.clock.t = T0 + 100
        taken = cb.acquire("k1", B, 100)
        self.assertEqual((taken.acquired, taken.status), (True, "taken_over"))
        self.assertEqual(ca.renew("k1", A, first.lease.nonce, 100).status, "not_holder")
        self.assertEqual(ca.release("k1", A, first.lease.nonce).status, "not_holder")
        self.assertEqual(ca.inspect("k1").lease.owner, B)

    def test_takeover_race_over_an_expired_lease_has_one_winner(self):
        ca = self.client("a")
        ca.acquire("k2", A, 10)
        self.clock.t = T0 + 50
        owners = [B, C]
        clients = [self.client("b"), self.client("c")]
        outs = []
        barrier = threading.Barrier(2)

        def go(cl, o):
            barrier.wait()
            outs.append(cl.acquire("k2", o, 100))

        ts = [threading.Thread(target=go, args=(c, o)) for c, o in zip(clients, owners)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(sum(1 for o in outs if o.acquired), 1, [o.status for o in outs])

    def test_renew_does_not_resurrect_an_expired_lease(self):
        ca = self.client("a")
        out = ca.acquire("k3", A, 10)
        self.clock.t = T0 + 11
        self.assertEqual(ca.renew("k3", A, out.lease.nonce, 10).status, "not_holder")

    def test_ttl_bounds(self):
        ca = self.client("a")
        for bad in (0, -5, L.DEFAULT_MAX_TTL + 1, True, 1.5):
            with self.assertRaises(ValueError, msg=str(bad)):
                ca._build("k4", A, "ab" * 8, T0, bad)


class SignatureTests(LeaseCase):
    def test_signed_leases_work_and_are_authentic(self):
        ca = self.client("a", shared_key=KEY, require_signature=True)
        cb = self.client("b", shared_key=KEY, require_signature=True)
        out = ca.acquire("s1", A, 100)
        self.assertTrue(out.acquired)
        self.assertEqual(cb.inspect("s1").authentic, True)
        self.assertEqual(cb.acquire("s1", B, 100).status, "held")
        self.assertEqual(ca.renew("s1", A, out.lease.nonce, 100).status, "renewed")

    def test_forged_unsigned_lease_is_not_held_by_owner_but_still_blocks_until_expiry(self):
        ca = self.client("a", shared_key=KEY, require_signature=True)
        cb = self.client("b", shared_key=KEY, require_signature=True)
        mallory = self.client("m")
        forged = L.Lease("s2", A, "ab" * 8, T0, T0 + 100, L.host_hash_of(A)).message()  # claims to be alice
        self.raw_write(mallory, "s2", forged)
        self.assertEqual(ca.inspect("s2").status, "held_unauthenticated")
        self.assertEqual(ca.renew("s2", A, "ab" * 8, 100).status, "not_holder")
        self.assertEqual(ca.release("s2", A, "ab" * 8).status, "not_holder")
        blocked = cb.acquire("s2", B, 100)
        self.assertEqual((blocked.acquired, blocked.status), (False, "held_unauthenticated"))
        self.clock.t = T0 + 100
        self.assertEqual(cb.acquire("s2", B, 100).status, "taken_over")

    def test_badly_signed_lease_is_rejected(self):
        cb = self.client("b", shared_key=KEY, require_signature=True)
        mallory = self.client("m")
        base = L.Lease("s3", A, "ab" * 8, T0, T0 + 100, L.host_hash_of(A))
        sig = L.sign(base.payload(), OTHER_KEY)  # signed, but with the wrong key
        forged = L.Lease("s3", A, "ab" * 8, T0, T0 + 100, base.host_hash, sig)
        self.raw_write(mallory, "s3", forged.message())
        self.assertEqual(cb.inspect("s3").status, "held_unauthenticated")

    def test_same_forgery_is_accepted_when_signatures_are_not_required(self):
        # contrast: this is the Tau Ceti weakness, a self-asserted owner
        ca = self.client("a")
        mallory = self.client("m")
        forged = L.Lease("s4", A, "ab" * 8, T0, T0 + 100, L.host_hash_of(A)).message()
        self.raw_write(mallory, "s4", forged)
        self.assertEqual(ca.inspect("s4").status, "held")  # inspect has no 'me'; the forged owner is accepted below
        self.assertEqual(ca.renew("s4", A, "ab" * 8, 100).status, "renewed")

    def test_lease_copied_to_another_key_is_rejected(self):
        ca = self.client("a", shared_key=KEY, require_signature=True)
        out = ca.acquire("s5", A, 100)
        oid = safegit.ls_remote(ca.repo, self.bare)[L.NAMESPACE + "s5"]
        r = safegit.push_cas(ca.repo, self.bare, L.NAMESPACE + "s6", oid, None)
        self.assertTrue(r.ok)
        v = ca.inspect("s6")
        self.assertEqual(v.status, "stray_young")  # its key field says s5
        self.assertIsNone(v.lease)
        self.assertTrue(out.acquired)


class StrayTests(LeaseCase):
    def test_stray_ref_is_reclaimed_after_max_age_not_before(self):
        ca = self.client("a", max_age=600)
        self.raw_write(ca, "stray1", "", when=T0)
        self.clock.t = T0 + 10
        young = ca.acquire("stray1", A, 100)
        self.assertEqual((young.acquired, young.status), (False, "stray_young"))
        self.clock.t = T0 + 600
        got = ca.acquire("stray1", A, 100)
        self.assertEqual((got.acquired, got.status), (True, "reclaimed_stray"))
        self.assertEqual(ca.inspect("stray1").lease.owner, A)

    def test_non_json_and_non_commit_strays(self):
        ca = self.client("a", max_age=600)
        self.raw_write(ca, "stray2", "garbage message", when=T0)
        self.raw_write(ca, "stray3", "", kind="blob")
        self.clock.t = T0 + 700
        self.assertEqual(ca.acquire("stray2", A, 100).status, "reclaimed_stray")
        self.assertEqual(ca.acquire("stray3", A, 100).status, "reclaimed_stray")

    def test_sweep_removes_expired_and_strays_and_keeps_live(self):
        ca, cb = self.client("a", max_age=600), self.client("b")
        ca.acquire("live", A, 5000)
        ca.acquire("old", A, 50)
        self.raw_write(cb, "stray4", "", when=T0)
        self.raw_write(cb, "stray5", "nope", when=T0 + 4000)
        self.clock.t = T0 + 1000
        report = {k: (s, d) for k, s, d in ca.sweep()}
        self.assertEqual(report["live"], ("held", False))
        self.assertEqual(report["old"], ("expired", True))
        self.assertEqual(report["stray4"], ("stray_reclaimable", True))  # forged-future would be reclaimed too
        self.assertEqual(report["stray5"], ("stray_reclaimable", True))
        remaining = sorted(safegit.ls_remote(ca.repo, self.bare))
        self.assertEqual(remaining, [L.NAMESPACE + "live"])


class ErrorPolicyTests(LeaseCase):
    def test_deny_is_default_and_blocks_work_when_the_store_is_unreachable(self):
        repo = gf.init_repo(os.path.join(self.dir, "x"))
        cl = L.LeaseClient(repo, os.path.join(self.dir, "missing.git"), self.clock)
        out = cl.acquire("e1", A, 100)
        self.assertEqual((out.acquired, out.proceed, out.status), (False, False, "error"))

    def test_proceed_is_explicit_and_never_claims_the_lease(self):
        repo = gf.init_repo(os.path.join(self.dir, "x"))
        cl = L.LeaseClient(repo, os.path.join(self.dir, "missing.git"), self.clock, on_error="proceed")
        out = cl.acquire("e1", A, 100)
        self.assertEqual((out.acquired, out.proceed, out.status), (False, True, "error_proceed"))

    def test_a_held_lease_still_denies_under_proceed(self):
        ca = self.client("a", on_error="proceed")
        cb = self.client("b", on_error="proceed")
        ca.acquire("e2", A, 100)
        out = cb.acquire("e2", B, 100)
        self.assertEqual((out.proceed, out.status), (False, "held"))


if __name__ == "__main__":
    unittest.main()

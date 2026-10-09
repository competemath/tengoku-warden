"""Cooperative task leases stored as git refs, with compare-and-swap, expiry and optional signatures.

A lease is the ref `refs/tengoku-leases/<key>` pointing at an orphan commit on the empty tree
whose message is canonical JSON `{key, owner, nonce, issued_at, expires_at, host_hash}` (plus
`sig` when signed). `owner` is `login/host-uuid/worker`; no raw host name or pid is published.
Acquire is a create-only push; renew, takeover of an expired lease and reclaiming of a stray ref
are pushes against the exact object id that was observed; release is a delete with a lease. Expiry
is decided by an injected `clock()`: feed it a server-derived time (for example the HTTP `Date`
header of a GitHub API response), not the local clock. `LeaseClient` does the git IO; `evaluate`,
`parse_message`, `sign` and `verify` are pure.

Credit: Tau Ceti Project, TauCetiWorker `claim.sh`, the `refs/tauceti-claims/<key>` leases and the
tauceti-claims repository (commit cc6222c, 2026-06-13; TTL 1500 s with a 300 s heartbeat; their
`claims-access.yml` sweeper, PR #3164 in TauCeti). Flaws we fix, taken from their research report:
the owner is a self-asserted free-text id (the one live lease was owned by `default`) so owners
collide across operators and any collaborator can overwrite a lease; expiry uses the local clock;
leases publish host and pid; the sweeper skips unparseable leases (three empty-message refs stayed
in the live claims repository); an error while claiming means "proceed unclaimed" (fail open).

What we do differently: owner ids carry the login and a per-host random uuid; the lease can be
authenticated (HMAC-SHA256 with a shared key, or any signer/verifier pair, which is the hook for SSH
signatures) and `require_signature=True` makes an unsigned or badly signed lease count as not held by
its claimed owner while still blocking takeover until it expires (a forged lease cannot be used to
steal a task, and cannot be used to block it for long, because the lifetime is capped at `max_ttl`);
a lease whose message does not parse is a stray and is reclaimable once it is `max_age` old, and
`sweep` removes expired and stray refs; both error policies are explicit (`deny` for
security-critical work, `proceed` only for duplicate-avoidance); and the compare-and-swap is tested
against a real bare remote. Without signatures this is a cooperative protocol: a participant with
push access to the lease namespace can still delete or replace leases. Enforce that with a ruleset.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import uuid
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from warden import safegit

NAMESPACE = "refs/tengoku-leases/"
DEFAULT_MAX_TTL = 86400
DEFAULT_MAX_AGE = 3600
DEFAULT_SKEW = 300
MAX_MESSAGE_BYTES = 8192
_KEY_RE = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9._-]{0,80}(?:/[A-Za-z0-9_-][A-Za-z0-9._-]{0,80}){0,4}\Z")
_PART_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_HEX_RE = re.compile(r"^[0-9a-f]{16,64}\Z")
_OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_FIELDS = ("key", "owner", "nonce", "issued_at", "expires_at", "host_hash")
_MAX_INT = 1 << 40


class LeaseIOError(RuntimeError):
    """The lease store could not be read or written (network, git, permissions)."""


# --------------------------------------------------------------------------- pure logic


def check_key(key: str) -> str:
    if (not isinstance(key, str) or not _KEY_RE.match(key) or ".." in key or key.endswith(".lock")
            or "/." in key or key.endswith(".")):
        raise ValueError("bad lease key %r" % (key,))
    return key


def make_owner(login: str, host_uuid: str, worker: str) -> str:
    """`login/host-uuid/worker`. host_uuid should be a random id generated once per host."""
    for part in (login, host_uuid, worker):
        if not isinstance(part, str) or not _PART_RE.match(part):
            raise ValueError("owner part %r is not acceptable" % (part,))
    return "%s/%s/%s" % (login, host_uuid, worker)


def new_host_uuid() -> str:
    return uuid.uuid4().hex


def _owner_parts(owner: str) -> Optional[Tuple[str, str, str]]:
    parts = owner.split("/") if isinstance(owner, str) else []
    if len(parts) == 3 and all(_PART_RE.match(p) for p in parts):
        return parts[0], parts[1], parts[2]
    return None


def host_hash_of(owner: str) -> str:
    """Public, stable digest of the host uuid inside `owner` (never the host name or pid)."""
    parts = _owner_parts(owner)
    if parts is None:
        raise ValueError("bad owner %r" % (owner,))
    return hashlib.sha256(("tengoku-host:" + parts[1]).encode("utf-8")).hexdigest()[:16]


def canonical(payload: Dict[str, object]) -> str:
    """Canonical JSON of a payload, excluding any `sig` field: the exact bytes that are signed."""
    body = {k: v for k, v in payload.items() if k != "sig"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sign(payload: Dict[str, object], key: bytes) -> str:
    """HMAC-SHA256 tag (`hmac-sha256:<hex>`) over the canonical payload, with a caller-supplied shared key."""
    if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
        raise ValueError("signing key must be at least 16 bytes")
    return "hmac-sha256:" + hmac.new(bytes(key), canonical(payload).encode("utf-8"), hashlib.sha256).hexdigest()


def verify(payload: Dict[str, object], key: bytes) -> bool:
    """True only if `payload['sig']` is a valid tag for the rest of the payload under `key`."""
    sig = payload.get("sig")
    if not isinstance(sig, str) or not isinstance(key, (bytes, bytearray)) or len(key) < 16:
        return False
    return hmac.compare_digest(sig, sign(payload, key))


Signer = Callable[[bytes], str]
Verifier = Callable[[bytes, str], bool]
# Hook for other schemes (for example `ssh-keygen -Y sign` / `-Y verify`): a Signer maps the
# canonical bytes to a signature string; a Verifier checks (canonical bytes, signature string).


@dataclass(frozen=True)
class Lease:
    key: str
    owner: str
    nonce: str
    issued_at: int
    expires_at: int
    host_hash: str
    sig: Optional[str] = None

    def payload(self) -> Dict[str, object]:
        d: Dict[str, object] = {"key": self.key, "owner": self.owner, "nonce": self.nonce,
                                "issued_at": self.issued_at, "expires_at": self.expires_at,
                                "host_hash": self.host_hash}
        if self.sig is not None:
            d["sig"] = self.sig
        return d

    def message(self) -> str:
        d = self.payload()
        return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def parse_message(message: str, ref_key: str, now: int, *, max_ttl: int = DEFAULT_MAX_TTL,
                  skew: int = DEFAULT_SKEW) -> Tuple[Optional[Lease], str]:
    """Parse a lease commit message strictly. Returns (lease, '') or (None, reason it is a stray)."""
    msg = message[:-1] if message.endswith("\n") else message
    if not msg.strip():
        return None, "empty message"
    try:
        data = json.loads(msg)
    except ValueError:
        return None, "not JSON"
    if not isinstance(data, dict):
        return None, "not a JSON object"
    if set(data) - set(_FIELDS) - {"sig"} or any(f not in data for f in _FIELDS):
        return None, "wrong field set"
    if json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True) != msg:
        return None, "not canonical JSON"
    for f in ("issued_at", "expires_at"):
        v = data[f]
        if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v < _MAX_INT:
            return None, "bad %s" % f
    for f in ("key", "owner", "nonce", "host_hash"):
        if not isinstance(data[f], str):
            return None, "bad %s" % f
    if data["key"] != ref_key:
        return None, "lease key does not match its ref"
    if _owner_parts(data["owner"]) is None:
        return None, "bad owner"
    if not _HEX_RE.match(data["nonce"]) or not _HEX_RE.match(data["host_hash"]):
        return None, "bad nonce or host_hash"
    if data["host_hash"] != host_hash_of(data["owner"]):
        return None, "host_hash does not match owner"
    sig = data.get("sig")
    if sig is not None and (not isinstance(sig, str) or not 0 < len(sig) <= 4096):
        return None, "bad sig"
    if not data["issued_at"] < data["expires_at"] <= data["issued_at"] + max_ttl:
        return None, "lifetime out of range"
    if data["issued_at"] > now + skew:
        return None, "issued in the future"
    return Lease(data["key"], data["owner"], data["nonce"], data["issued_at"], data["expires_at"],
                 data["host_hash"], sig), ""


@dataclass(frozen=True)
class Observed:
    """What the remote holds under one lease ref right now (an input to `evaluate`)."""
    oid: Optional[str]            # None: the ref does not exist
    kind: str = "absent"          # absent | commit | other
    message: str = ""
    commit_time: Optional[int] = None


@dataclass(frozen=True)
class Verdict:
    status: str  # absent | mine | held | held_unauthenticated | expired | stray_young | stray_reclaimable
    lease: Optional[Lease] = None
    authentic: Optional[bool] = None  # None: nothing to check against
    reason: str = ""


def evaluate(obs: Observed, *, key: str, now: int, me: Optional[str] = None,
             nonce: Optional[str] = None, require_signature: bool = False,
             verifier: Optional[Verifier] = None, max_age: int = DEFAULT_MAX_AGE,
             max_ttl: int = DEFAULT_MAX_TTL, skew: int = DEFAULT_SKEW) -> Verdict:
    """Decide what an observed ref means for `me`. No IO, no clock reads."""
    if require_signature and verifier is None:
        raise ValueError("require_signature needs a verifier")
    if obs.oid is None or obs.kind == "absent":
        return Verdict("absent")
    lease = None
    reason = "not a commit"
    if obs.kind == "commit":
        lease, reason = parse_message(obs.message, key, now, max_ttl=max_ttl, skew=skew)
    if lease is None:
        ts = obs.commit_time
        forged_future = ts is not None and ts > now + skew
        age = None if (ts is None or forged_future) else now - ts
        if age is None or age >= max_age:
            return Verdict("stray_reclaimable", None, None, reason)
        return Verdict("stray_young", None, None, reason)
    authentic: Optional[bool] = None
    if verifier is not None:
        authentic = lease.sig is not None and bool(verifier(canonical(lease.payload()).encode("utf-8"), lease.sig))
        if lease.sig is None and not require_signature:
            authentic = None
    elif lease.sig is not None:
        authentic = None  # signed, but we hold no way to check it
    if now >= lease.expires_at:
        return Verdict("expired", lease, authentic, "expired")
    if authentic is False:
        return Verdict("held_unauthenticated", lease, False, "signature missing or invalid")
    if me is not None and lease.owner == me and (nonce is None or lease.nonce == nonce):
        return Verdict("mine", lease, authentic)
    return Verdict("held", lease, authentic)


# --------------------------------------------------------------------------- IO


@dataclass(frozen=True)
class Outcome:
    acquired: bool   # the caller holds the lease after this call
    proceed: bool    # the caller may go ahead with the work (acquired, or on_error='proceed' after an error)
    status: str
    lease: Optional[Lease] = None
    detail: str = ""


class LeaseClient:
    """Lease operations against `remote`, using `repo` (any local repository) as scratch space.

    `clock` returns the trusted current time in seconds; pass a server-derived time. `on_error`
    is 'deny' (default; for security-critical work an unreachable store means no lease) or
    'proceed' (duplicate-avoidance only: an error lets the caller continue unclaimed, which is the
    fail-open behaviour of Tau Ceti's claims; never use it where a duplicate is harmful).
    """

    def __init__(self, repo: str, remote: str, clock: Callable[[], float], *,
                 shared_key: Optional[bytes] = None, signer: Optional[Signer] = None,
                 verifier: Optional[Verifier] = None, require_signature: bool = False,
                 on_error: str = "deny", max_age: int = DEFAULT_MAX_AGE,
                 max_ttl: int = DEFAULT_MAX_TTL, skew: int = DEFAULT_SKEW,
                 env: Optional[Dict[str, str]] = None) -> None:
        if on_error not in ("deny", "proceed"):
            raise ValueError("on_error must be 'deny' or 'proceed'")
        if shared_key is not None:
            if len(shared_key) < 16:
                raise ValueError("shared_key must be at least 16 bytes")
            k = bytes(shared_key)
            signer = signer or (lambda data: "hmac-sha256:" + hmac.new(k, data, hashlib.sha256).hexdigest())
            verifier = verifier or (lambda data, sig: hmac.compare_digest(
                sig, "hmac-sha256:" + hmac.new(k, data, hashlib.sha256).hexdigest()))
        if require_signature and (signer is None or verifier is None):
            raise ValueError("require_signature needs a shared_key or a signer and a verifier")
        self.repo, self.remote, self.clock = repo, remote, clock
        self.signer, self.verifier, self.require_signature = signer, verifier, require_signature
        self.on_error, self.max_age, self.max_ttl, self.skew = on_error, max_age, max_ttl, skew
        self.env = env

    # -- git plumbing
    def _git(self, args: List[str], *, input_bytes: Optional[bytes] = None,
             env: Optional[Dict[str, str]] = None) -> str:
        merged = dict(self.env or {})
        merged.update(env or {})
        r = safegit.run_git(self.repo, args, env=merged, input_bytes=input_bytes)
        if r.returncode != 0:
            raise LeaseIOError("git %s failed: %s" % (args[0], r.stderr.strip()[:300]))
        return r.stdout

    def _now(self) -> int:
        return int(self.clock())

    def observe(self, key: str) -> Observed:
        """Read the remote's current lease ref. Raises LeaseIOError when it cannot be read."""
        check_key(key)
        ref = NAMESPACE + key
        try:
            listed = safegit.ls_remote(self.repo, self.remote, ref, env=self.env)
        except RuntimeError as exc:
            raise LeaseIOError(str(exc))
        if ref not in listed:
            return Observed(None)
        self._git(["-c", "transfer.fsckObjects=true", "fetch", "--no-tags", "--quiet", self.remote, ref])
        oid = self._git(["rev-parse", "--verify", "FETCH_HEAD"]).strip()
        if not _OID_RE.match(oid):
            raise LeaseIOError("fetched ref did not resolve")
        kind = self._git(["cat-file", "-t", oid]).strip()
        if kind != "commit":
            return Observed(oid, "other")
        size = int(self._git(["cat-file", "-s", oid]).strip() or "0")
        if size > MAX_MESSAGE_BYTES:
            return Observed(oid, "other")
        raw = self._git(["cat-file", "commit", oid])
        head, _, message = raw.partition("\n\n")
        ts = None
        for line in head.splitlines():
            if line.startswith("committer "):
                m = re.search(r"> (\d{1,12}) [+-]\d{4}$", line)
                if m:
                    ts = int(m.group(1))
        return Observed(oid, "commit", message, ts)

    def _evaluate(self, obs: Observed, key: str, now: int, me: Optional[str] = None,
                  nonce: Optional[str] = None) -> Verdict:
        return evaluate(obs, key=key, now=now, me=me, nonce=nonce, require_signature=self.require_signature,
                        verifier=self.verifier, max_age=self.max_age, max_ttl=self.max_ttl, skew=self.skew)

    def _write(self, lease: Lease, expected_old: Optional[str], status: str) -> Outcome:
        """Create the lease commit and CAS the ref from `expected_old` (None: create-only)."""
        ident = {"GIT_AUTHOR_NAME": "tengoku-lease", "GIT_AUTHOR_EMAIL": "lease@tengoku.invalid",
                 "GIT_COMMITTER_NAME": "tengoku-lease", "GIT_COMMITTER_EMAIL": "lease@tengoku.invalid",
                 "GIT_AUTHOR_DATE": "@%d +0000" % lease.issued_at,
                 "GIT_COMMITTER_DATE": "@%d +0000" % lease.issued_at}
        tree = self._git(["hash-object", "-t", "tree", "-w", "--stdin"], input_bytes=b"").strip()
        oid = self._git(["-c", "commit.gpgsign=false", "commit-tree", tree, "-F", "-"],
                        input_bytes=lease.message().encode("utf-8"), env=ident).strip()
        res = safegit.push_cas(self.repo, self.remote, NAMESPACE + lease.key, oid, expected_old, env=self.env)
        if res.ok:
            return Outcome(True, True, status, lease)
        if res.reason in ("exists", "lease_mismatch"):
            return Outcome(False, False, "lost_race", None, "another participant changed the lease first")
        raise LeaseIOError("push failed (%s): %s" % (res.reason, res.detail[:200]))

    def _error(self, exc: Exception) -> Outcome:
        if self.on_error == "proceed":
            return Outcome(False, True, "error_proceed", None, str(exc))
        return Outcome(False, False, "error", None, str(exc))

    def _build(self, key: str, owner: str, nonce: str, now: int, ttl: int) -> Lease:
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not 0 < ttl <= self.max_ttl:
            raise ValueError("ttl must be between 1 and max_ttl (%d) seconds" % self.max_ttl)
        base = Lease(key, owner, nonce, now, now + ttl, host_hash_of(owner))
        if self.signer is None:
            return base
        sig = self.signer(canonical(base.payload()).encode("utf-8"))
        return Lease(key, owner, nonce, now, now + ttl, base.host_hash, sig)

    # -- operations
    def acquire(self, key: str, owner: str, ttl: int, *, nonce: Optional[str] = None) -> Outcome:
        """Take the lease on `key`, renew it if `owner` already holds it, or take over an expired or stray one."""
        check_key(key)
        if _owner_parts(owner) is None:
            raise ValueError("bad owner %r" % (owner,))
        try:
            now = self._now()
            obs = self.observe(key)
            v = self._evaluate(obs, key, now, owner)
            if v.status in ("held", "held_unauthenticated", "stray_young"):
                return Outcome(False, False, v.status, v.lease, v.reason)
            use_nonce = v.lease.nonce if v.status == "mine" and v.lease else (nonce or secrets.token_hex(16))
            status = {"absent": "acquired", "mine": "renewed", "expired": "taken_over",
                      "stray_reclaimable": "reclaimed_stray"}[v.status]
            lease = self._build(key, owner, use_nonce, now, ttl)
            return self._write(lease, obs.oid, status)
        except LeaseIOError as exc:
            return self._error(exc)

    def renew(self, key: str, owner: str, nonce: str, ttl: int) -> Outcome:
        """Extend a lease this owner/nonce still holds (live and authentic); never resurrects an expired one."""
        check_key(key)
        try:
            now = self._now()
            obs = self.observe(key)
            v = self._evaluate(obs, key, now, owner, nonce)
            if v.status != "mine":
                return Outcome(False, False, "not_holder", v.lease, "lease is %s" % v.status)
            return self._write(self._build(key, owner, nonce, now, ttl), obs.oid, "renewed")
        except LeaseIOError as exc:
            return self._error(exc)

    def release(self, key: str, owner: str, nonce: str) -> Outcome:
        """Delete the lease (with a lease on the observed object) if this owner/nonce holds it."""
        check_key(key)
        try:
            now = self._now()
            obs = self.observe(key)
            if obs.oid is None:
                return Outcome(False, False, "absent")
            v = self._evaluate(obs, key, now, owner, nonce)
            lease = v.lease
            ours = (lease is not None and lease.owner == owner and lease.nonce == nonce
                    and v.authentic is not False)
            if not ours:
                return Outcome(False, False, "not_holder", lease, "lease is %s" % v.status)
            res = safegit.delete_ref_cas(self.repo, self.remote, NAMESPACE + key, obs.oid, env=self.env)
            if res.ok:
                return Outcome(False, False, "released", lease)
            if res.reason in ("lease_mismatch", "exists"):
                return Outcome(False, False, "lost_race", lease, "the lease changed before it could be released")
            raise LeaseIOError("delete failed (%s): %s" % (res.reason, res.detail[:200]))
        except LeaseIOError as exc:
            return self._error(exc)

    def inspect(self, key: str) -> Verdict:
        """Read-only view of one lease. Raises LeaseIOError when the store cannot be read."""
        check_key(key)
        return self._evaluate(self.observe(key), key, self._now())

    def sweep(self) -> List[Tuple[str, str, bool]]:
        """Delete every expired or reclaimable stray lease. Returns (key, status, deleted) per ref seen."""
        try:
            listed = safegit.ls_remote(self.repo, self.remote, NAMESPACE + "*", env=self.env)
        except RuntimeError as exc:
            raise LeaseIOError(str(exc))
        out: List[Tuple[str, str, bool]] = []
        for ref in sorted(listed):
            key = ref[len(NAMESPACE):]
            try:
                check_key(key)
            except ValueError:
                out.append((key, "unmanageable_name", False))
                continue
            try:
                obs = self.observe(key)
                v = self._evaluate(obs, key, self._now())
                if v.status in ("expired", "stray_reclaimable") and obs.oid:
                    res = safegit.delete_ref_cas(self.repo, self.remote, ref, obs.oid, env=self.env)
                    out.append((key, v.status, res.ok))
                else:
                    out.append((key, v.status, False))
            except LeaseIOError:
                out.append((key, "error", False))
        return out

"""Backend side of the gateway's decision assertions (docs/API.md 2.0.2), mirroring packages/sdk/src/assertion.ts.

The request reached this backend through the PEP, the PDP allowed exactly this subject, action and resource, and the
request is the one decided (method, path with query, body digest, audience). Ed25519 keys come from the PDP's JWKS,
cached and refreshed on an unknown kid; every nonce is accepted once while the assertion lives (per process by default;
a ReplayStore shares that across replicas). Every failure raises GateAssertionError: fail closed."""
from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
import threading
import time
import urllib.request
from typing import Any, Callable, Dict, List, NoReturn, Optional, Protocol, Union
from urllib.parse import urlsplit

from . import ed25519
from .client import build_opener, read_bounded
from .errors import GateAssertionError
from .validation import is_safe_integer, loads

ASSERTION_HEADER = "gate-assertion"
ASSERTION_TYP = "gate-assertion+jwt"
ASSERTION_MAX_TTL_SECONDS = 30
MAX_JWKS_BYTES = 65536
UNKNOWN_KID_REFRESH_SECONDS = 10
_B64 = re.compile(r"^[A-Za-z0-9_-]+$")
CLAIMS = ("sub", "act", "res", "did", "pv", "aud", "htm", "htp", "bsh", "iat", "exp", "nonce")


class ReplayStore(Protocol):
    """Spends a nonce in one atomic check-and-set: True the first time, False when it was already spent. `expires_at`
    (seconds since the epoch) is when the nonce may be forgotten. A store that raises fails the request closed."""

    def spend(self, nonce: str, expires_at: int) -> bool: ...


class MemoryReplayStore:
    """The default store: a dict in this process (thread-safe)."""

    def __init__(self, now: Callable[[], float] = time.time) -> None:
        self._seen: Dict[str, int] = {}
        self._now = now
        self._lock = threading.Lock()

    def spend(self, nonce: str, expires_at: int) -> bool:
        now = math.floor(self._now())
        with self._lock:
            # shortcut: a full scan per request, bounded by one TTL of traffic; index by expiry if that grows past ~100k
            for n in [n for n, until in self._seen.items() if until < now]:
                del self._seen[n]
            if nonce in self._seen:
                return False
            self._seen[nonce] = expires_at
            return True


def _refuse(code: str) -> NoReturn:
    raise GateAssertionError(code, "The decision assertion is not acceptable")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def body_sha256(body: bytes) -> str:
    """base64url SHA-256 of the forwarded body (of b"" when there is none)."""
    return _b64url(hashlib.sha256(body).digest())


def _decode(value: str) -> bytes:
    """One encoding per value: the re-encoded bytes must spell the input, or a second spelling could pass."""
    if not _B64.match(value):
        raise ValueError("not base64url")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if _b64url(raw) != value:
        raise ValueError("not canonical base64url")
    return raw


def _part(value: str) -> Any:
    try:
        return loads(_decode(value).decode("utf-8"))
    except (ValueError, binascii.Error, RecursionError):
        _refuse("assertion_invalid")


def _record(value: Any) -> Dict[str, Any]:
    return value if type(value) is dict else _refuse("assertion_invalid")


def _length(value: str) -> int:
    # JavaScript string length, so limits match the TypeScript verifier; a lone surrogate is one unit there too
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _text(value: Any, max_length: int = 2048) -> str:
    return value if type(value) is str and 0 < _length(value) <= max_length else _refuse("assertion_invalid")


def _exact(o: Dict[str, Any], keys: tuple, optional: tuple = ()) -> None:
    if any(k not in keys and k not in optional for k in o) or any(k not in o for k in keys):
        _refuse("assertion_invalid")


def _claims(value: Any) -> Dict[str, Any]:
    c = _record(value)
    _exact(c, CLAIMS)
    sub = _record(c["sub"])
    _exact(sub, ("type", "id"))
    res = _record(c["res"])
    _exact(res, ("type",), ("id",))
    iat, exp = c["iat"], c["exp"]
    if not is_safe_integer(iat) or not is_safe_integer(exp) or exp <= iat or exp - iat > ASSERTION_MAX_TTL_SECONDS:
        _refuse("assertion_invalid")
    resource = {"type": _text(res["type"], 256)}
    if "id" in res:
        resource["id"] = _text(res["id"], 256)
    return {"sub": {"type": _text(sub["type"], 256), "id": _text(sub["id"], 256)}, "act": _text(c["act"], 256),
            "res": resource, "did": _text(c["did"], 64), "pv": _text(c["pv"], 256), "aud": _text(c["aud"], 256),
            "htm": _text(c["htm"], 16), "htp": _text(c["htp"]), "bsh": _text(c["bsh"], 64),
            "iat": iat, "exp": exp, "nonce": _text(c["nonce"], 64)}


def _origin_of(audience: str) -> Optional[str]:
    try:
        url = urlsplit(audience)
        port = url.port
    except (TypeError, ValueError, AttributeError):
        return None
    if url.scheme not in ("http", "https") or not url.hostname or url.username is not None or url.password is not None:
        return None
    host = f"[{url.hostname}]" if ":" in url.hostname else url.hostname
    default = 80 if url.scheme == "http" else 443
    return f"{url.scheme}://{host}" + ("" if port is None or port == default else f":{port}")


def _keys_of(body: bytes) -> Dict[str, bytes]:
    document = loads(body.decode("utf-8"))
    if type(document) is not dict:
        raise ValueError("JWKS is not an object")
    entries = document.get("keys", [])
    if type(entries) is not list:
        raise ValueError("JWKS keys is not a list")
    keys: Dict[str, bytes] = {}
    for entry in entries:
        k = _record(entry)
        # public Ed25519 signing keys only; a private component or another algorithm is ignored, never trusted
        if (k.get("kty") != "OKP" or k.get("crv") != "Ed25519" or type(k.get("x")) is not str
                or type(k.get("kid")) is not str or "d" in k):
            continue
        if ("alg" in k and k["alg"] != "EdDSA") or ("use" in k and k["use"] != "sig"):
            continue
        public = _decode(k["x"])
        if not ed25519.is_public_key(public):
            raise ValueError("JWKS key is not an Ed25519 public key")
        keys[k["kid"]] = public
    return keys


class AssertionVerifier:
    """`jwks_url` the PDP's /.well-known/jwks.json; `audience` this backend's origin exactly as the gateway's upstream
    names it (e.g. http://10.0.0.5:8080). `now` returns seconds since the epoch (tests)."""

    def __init__(self, jwks_url: str, audience: str, clock_skew_seconds: int = 5, jwks_cache_seconds: int = 300,
                 timeout: float = 5.0, now: Callable[[], float] = time.time, replay_store: Optional[ReplayStore] = None,
                 ca_file: Optional[str] = None, opener: Optional[urllib.request.OpenerDirector] = None) -> None:
        try:
            jwks = urlsplit(jwks_url)
        except (TypeError, ValueError, AttributeError):
            raise TypeError("jwksUrl must be an HTTP(S) URL without credentials") from None
        if jwks.scheme not in ("http", "https") or not jwks.hostname or jwks.username is not None or jwks.password is not None:
            raise TypeError("jwksUrl must be an HTTP(S) URL without credentials")
        if type(audience) is not str or _origin_of(audience) != audience:
            raise TypeError("audience must be an origin (scheme, host, port)")
        if type(clock_skew_seconds) is not int or not 0 <= clock_skew_seconds <= 60:
            raise TypeError("clockSkewSeconds must be an integer in 0..60")
        if type(jwks_cache_seconds) is not int or not 10 <= jwks_cache_seconds <= 86400:
            raise TypeError("jwksCacheSeconds must be an integer in 10..86400")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise TypeError("timeout must be positive")
        self._jwks_url = jwks_url
        self._audience = audience
        self._skew = clock_skew_seconds
        self._cache = jwks_cache_seconds
        self._timeout = float(timeout)
        self._now = now
        self._replay: ReplayStore = replay_store if replay_store is not None else MemoryReplayStore(now)
        self._opener = opener or build_opener(ca_file)
        self._keys: Dict[str, bytes] = {}
        self._fetched_at = -math.inf
        self._lock = threading.Lock()

    def _refresh(self) -> None:
        request = urllib.request.Request(self._jwks_url, headers={"accept": "application/json"})
        deadline = time.monotonic() + self._timeout
        with self._opener.open(request, timeout=self._timeout) as response:
            if not 200 <= response.status < 300:
                raise ValueError("JWKS unavailable")
            body = read_bounded(response, deadline, MAX_JWKS_BYTES)
        # replaced, not merged: a key the PDP retired stops verifying at the next refresh
        self._keys = _keys_of(body)
        self._fetched_at = self._now()

    def _stale(self, kid: str) -> bool:
        age = self._now() - self._fetched_at
        return age >= self._cache or (kid not in self._keys and age >= UNKNOWN_KID_REFRESH_SECONDS)

    def _key(self, kid: str) -> Optional[bytes]:
        if self._stale(kid):
            with self._lock:  # one refresh at a time; the others wait for it, as for the shared promise in TypeScript
                if self._stale(kid):
                    try:
                        self._refresh()
                    except Exception:  # noqa: BLE001 - any JWKS failure fails the request closed (503)
                        _refuse("jwks_unavailable")
        return self._keys.get(kid)

    def verify(self, method: str, path: str, body: bytes, header: Union[str, List[str], None]) -> Dict[str, Any]:
        """The verified claims; raises GateAssertionError otherwise. `path` is the raw request target (path and query
        exactly as received), `header` the gate-assertion header. The nonce is spent only when every check passed."""
        token = header if type(header) is str and len(header) <= 4096 else _refuse("assertion_missing")
        parts = token.split(".")
        if len(parts) != 3 or not all(parts):
            _refuse("assertion_invalid")
        h, p, s = parts
        try:
            signature = _decode(s)
        except (ValueError, binascii.Error):
            _refuse("assertion_invalid")
        header_fields = _record(_part(h))
        _exact(header_fields, ("alg", "typ", "kid"))
        if header_fields["alg"] != "EdDSA" or header_fields["typ"] != ASSERTION_TYP:
            _refuse("assertion_invalid")
        claims = _claims(_part(p))
        key = self._key(_text(header_fields["kid"], 128))
        if key is None:
            _refuse("assertion_key_unknown")
        if not ed25519.verify(key, f"{h}.{p}".encode("ascii"), signature):
            _refuse("assertion_invalid")
        now = math.floor(self._now())
        if claims["iat"] > now + self._skew:
            _refuse("assertion_invalid")
        if claims["exp"] <= now - self._skew:
            _refuse("assertion_expired")
        if (claims["aud"] != self._audience or claims["htm"] != method or claims["htp"] != path
                or claims["bsh"] != body_sha256(bytes(body))):
            _refuse("assertion_mismatch")
        try:
            fresh = self._replay.spend(claims["nonce"], claims["exp"] + self._skew)
        except Exception:  # noqa: BLE001 - a broken store fails closed (503), never open
            _refuse("replay_store_unavailable")
        if fresh is not True:
            _refuse("assertion_replayed")
        return claims


def status_for(error: GateAssertionError) -> int:
    """The HTTP status a backend answers for a refused assertion: 503 when keys or the replay store are unavailable."""
    return 503 if error.code in ("jwks_unavailable", "replay_store_unavailable") else 401

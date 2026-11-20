import base64
import calendar
import hashlib
import io
import json
import unittest
import urllib.error

from qadamar import (
    ASSERTION_TYP, AssertionVerifier, GateAssertionError, MemoryReplayStore, body_sha256, status_for,
)

import signer

T0 = calendar.timegm((2026, 11, 8, 10, 0, 0))
AUDIENCE = "http://127.0.0.1:8080"
K1, K2, ATTACKER = (hashlib.sha256(name).digest() for name in (b"k1", b"k2", b"attacker"))


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwk(secret, kid, **extra):
    return {"kty": "OKP", "crv": "Ed25519", "x": b64(signer.public_key(secret)), "kid": kid, "use": "sig", "alg": "EdDSA", **extra}


class _Response(io.BytesIO):
    status = 200


class FakeJwks:
    """Stands in for the PDP's /.well-known/jwks.json."""

    def __init__(self):
        self.keys = [jwk(K1, "k1")]
        self.up = True
        self.fetches = 0
        self.raw = None

    def open(self, request, timeout):
        self.fetches += 1
        if not self.up:
            raise urllib.error.URLError("down")
        return _Response(self.raw if self.raw is not None else json.dumps({"keys": self.keys}).encode())


class Clock:
    def __init__(self):
        self.now = float(T0)

    def __call__(self):
        return self.now


class Verifier(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.jwks = FakeJwks()
        self.counter = 0
        self.verifier = self.make()

    def make(self, **options):
        return AssertionVerifier("https://pdp.test/.well-known/jwks.json", AUDIENCE, now=self.clock, opener=self.jwks, **options)

    def token(self, key=K1, header=None, **claims):
        self.counter += 1
        iat = int(self.clock.now)
        body = {"sub": {"type": "user", "id": "bob"}, "act": "read", "res": {"type": "case", "id": "CASE-14"},
                "did": f"d-{self.counter}", "pv": "pv1", "aud": AUDIENCE, "htm": "GET", "htp": "/cases/CASE-14",
                "bsh": body_sha256(b""), "iat": iat, "exp": iat + 30, "nonce": f"n-{self.counter}", **claims}
        content = f"{b64(json.dumps({'alg': 'EdDSA', 'typ': ASSERTION_TYP, 'kid': 'k1', **(header or {})}).encode())}.{b64(json.dumps(body).encode())}"
        return f"{content}.{b64(signer.sign(key, content.encode()))}"

    def verify(self, header, method="GET", path="/cases/CASE-14", body=b"", verifier=None):
        return (verifier or self.verifier).verify(method, path, body, header)

    def refused(self, code, header, status=401, **request):
        with self.assertRaises(GateAssertionError) as caught:
            self.verify(header, **request)
        self.assertEqual((caught.exception.code, status_for(caught.exception)), (code, status))

    def test_a_valid_assertion_is_accepted_once_and_carries_who_and_what(self):
        token = self.token()
        claims = self.verify(token)
        self.assertEqual(claims["sub"], {"type": "user", "id": "bob"})
        self.assertEqual(claims["res"], {"type": "case", "id": "CASE-14"})
        self.refused("assertion_replayed", token)
        posted = b'{"status":"approved"}'
        post = self.token(htm="POST", htp="/payments/PAY-3/approve", bsh=body_sha256(posted), act="approve",
                          res={"type": "payment"})
        self.assertEqual(self.verify(post, "POST", "/payments/PAY-3/approve", posted)["res"], {"type": "payment"})

    def test_unsigned_malformed_and_confused_tokens_are_refused(self):
        self.refused("assertion_missing", None)
        self.refused("assertion_missing", ["a", "b"])
        self.refused("assertion_missing", "x" * 4097)
        self.refused("assertion_invalid", "not-a-jws")
        h, p, s = self.token().split(".")
        for bad in (f"{h}.{p}.", f"{h}.{p}", f"{h}.{p}.{s}.x", f"{h}=.{p}.{s}", f"{h}.{p}.{s}=", f"{h}.{p}.{s[:-1]}",
                    f"{h}.{p}.{s[:-1]}{'B' if s[-1] == 'A' else 'A'}"):
            self.refused("assertion_invalid", bad)
        for header in ({"typ": "JWT"}, {"alg": "none"}, {"jku": "https://evil.test"}, {"kid": ""}):
            self.refused("assertion_invalid", self.token(header=header))
        # a lone surrogate (JSON "\\ud800") counts as one UTF-16 unit, as in the TypeScript verifier, never an encoding error
        self.refused("assertion_key_unknown", self.token(header={"kid": "\ud800"}))
        now = int(self.clock.now)
        for claims in ({"extra": 1}, {"sub": {"type": "user"}}, {"exp": now + 300}, {"iat": "1"}, {"exp": now},
                       {"res": {"type": "case", "id": "x", "owner": "y"}}, {"nonce": ""}, {"did": "d" * 65}):
            self.refused("assertion_invalid", self.token(**claims))
        # an unsigned payload swapped under a valid signature
        other = self.token(sub={"type": "user", "id": "admin"}).split(".")[1]
        self.refused("assertion_invalid", f"{h}.{other}.{s}")

    def test_expired_and_future_assertions_are_refused_within_the_skew_they_pass(self):
        now = int(self.clock.now)
        self.refused("assertion_expired", self.token(iat=now - 40, exp=now - 10))
        self.verify(self.token(iat=now - 33, exp=now - 3))
        self.refused("assertion_invalid", self.token(iat=now + 10, exp=now + 40))
        self.verify(self.token(iat=now + 4, exp=now + 34))

    def test_a_request_retargeted_to_another_path_method_body_or_backend_is_refused(self):
        self.refused("assertion_mismatch", self.token(), path="/cases/CASE-7")
        self.refused("assertion_mismatch", self.token(), path="/cases/CASE-14?all=1")
        self.refused("assertion_mismatch", self.token(), method="DELETE")
        self.refused("assertion_mismatch", self.token(htm="POST"), method="POST", body=b"smuggled")
        self.refused("assertion_mismatch", self.token(aud="http://other-backend:8080"))
        token = self.token()
        self.refused("assertion_mismatch", token, path="/cases/CASE-7")
        self.verify(token)  # a refused request does not spend the nonce

    def test_wrong_keys_rotation_through_the_jwks_and_an_unreachable_jwks(self):
        self.refused("assertion_invalid", self.token(key=ATTACKER))
        self.refused("assertion_key_unknown", self.token(key=ATTACKER, header={"kid": "evil"}))
        self.jwks.keys = [jwk(K1, "k1"), jwk(K2, "k2")]
        self.clock.now += 11
        before = self.jwks.fetches
        self.verify(self.token(key=K2, header={"kid": "k2"}))
        self.assertEqual(self.jwks.fetches, before + 1, "an unknown kid refetches the JWKS")
        self.refused("assertion_key_unknown", self.token(key=ATTACKER, header={"kid": "k3"}))
        self.assertEqual(self.jwks.fetches, before + 1, "unknown kids refetch at most every 10 s")
        # k1 retired; an RSA entry and one carrying a private part are ignored, never trusted
        self.jwks.keys = [jwk(K2, "k2"), jwk(ATTACKER, "k1", kty="RSA"), jwk(ATTACKER, "kp", d="private"),
                          jwk(ATTACKER, "ka", alg="RS256"), jwk(ATTACKER, "ku", use="enc")]
        self.clock.now += 301
        self.refused("assertion_key_unknown", self.token())
        for kid in ("kp", "ka", "ku"):
            self.refused("assertion_key_unknown", self.token(key=ATTACKER, header={"kid": kid}))
        self.verify(self.token(key=K2, header={"kid": "k2"}))
        self.jwks.up = False
        self.clock.now += 301
        self.refused("jwks_unavailable", self.token(key=K2, header={"kid": "k2"}), 503)
        self.jwks.up = True
        for raw in (b"not json", b"[]", b'{"keys": {}}', b'{"keys": ["x"]}', b" " * 65537,
                    json.dumps({"keys": [{**jwk(K1, "k1"), "x": "AAAA"}]}).encode()):
            self.jwks.raw = raw
            self.clock.now += 301
            with self.subTest(raw=raw[:20]):
                self.refused("jwks_unavailable", self.token(), 503)

    def test_a_shared_replay_store_refuses_on_every_replica_and_a_failing_store_fails_closed(self):
        shared, calls = {}, []

        class Store:
            def spend(self, nonce, expires_at):
                calls.append((nonce, expires_at))
                if nonce in shared:
                    return False
                shared[nonce] = expires_at
                return True

        a, b = self.make(replay_store=Store()), self.make(replay_store=Store())
        token = self.token()
        self.assertEqual(self.verify(token, verifier=a)["sub"]["id"], "bob")
        with self.assertRaises(GateAssertionError) as caught:
            self.verify(token, verifier=b)
        self.assertEqual(caught.exception.code, "assertion_replayed")
        exp = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))["exp"]
        self.assertEqual(calls[0][1], exp + 5, "expiry plus clock skew")
        alone1, alone2 = self.make(), self.make(replay_store=MemoryReplayStore(self.clock))
        other = self.token()
        self.verify(other, verifier=alone1)
        self.verify(other, verifier=alone2)
        with self.assertRaises(GateAssertionError):
            self.verify(other, verifier=alone2)

        class Broken:
            def spend(self, nonce, expires_at):
                raise ConnectionError("redis down")

        with self.assertRaises(GateAssertionError) as caught:
            self.verify(self.token(), verifier=self.make(replay_store=Broken()))
        self.assertEqual((caught.exception.code, status_for(caught.exception)), ("replay_store_unavailable", 503))

        class Truthy:
            def spend(self, nonce, expires_at):
                return 1  # anything but True is not fresh

        with self.assertRaises(GateAssertionError) as caught:
            self.verify(self.token(), verifier=self.make(replay_store=Truthy()))
        self.assertEqual(caught.exception.code, "assertion_replayed")

    def test_memory_replay_store_forgets_expired_nonces(self):
        store = MemoryReplayStore(self.clock)
        self.assertTrue(store.spend("n", T0 + 35))
        self.assertFalse(store.spend("n", T0 + 35))
        self.clock.now += 36
        self.assertTrue(store.spend("n", T0 + 71))

    def test_verifier_options_are_checked(self):
        base = {"jwks_url": "https://pdp.test/jwks", "audience": "http://backend:8080"}
        for bad in ({"jwks_url": "ftp://pdp.test/jwks"}, {"jwks_url": "https://u:p@pdp.test/jwks"},
                    {"audience": "http://backend:8080/path"}, {"audience": "http://backend:80"}, {"audience": "http://Backend:8080"},
                    {"audience": "http://backend:8080/"}, {"clock_skew_seconds": 61}, {"clock_skew_seconds": 1.5},
                    {"jwks_cache_seconds": 5}, {"timeout": 0}):
            with self.subTest(bad=bad), self.assertRaises(TypeError):
                AssertionVerifier(**{**base, **bad})
        for audience in ("http://backend", "https://10.0.0.5:8443", "http://[::1]:8080"):
            AssertionVerifier(base["jwks_url"], audience)


if __name__ == "__main__":
    unittest.main()

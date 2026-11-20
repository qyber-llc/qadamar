"""Test-only Ed25519 signing (RFC 8032 section 6 reference algorithm) built on the SDK's point arithmetic. The SDK itself
ships no signer: a backend only verifies."""
import hashlib

from qadamar import ed25519 as e


def _compress(P):
    zinv = pow(P[2], e.p - 2, e.p)
    x, y = P[0] * zinv % e.p, P[1] * zinv % e.p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _expand(secret):
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def _hash(data):
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % e.q


def public_key(secret):
    return _compress(e._mul(_expand(secret)[0], e.G))


def sign(secret, message):
    a, prefix = _expand(secret)
    A = _compress(e._mul(a, e.G))
    r = _hash(prefix + message)
    R = _compress(e._mul(r, e.G))
    s = (r + _hash(R + A + message) * a) % e.q
    return R + int.to_bytes(s, 32, "little")

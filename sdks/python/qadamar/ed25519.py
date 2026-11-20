"""Ed25519 signature verification in pure Python: the reference algorithm of RFC 8032 section 6 (verification only).

Not constant-time. That is acceptable here because verification handles public data only (the public key, the signed
message and the signature); no secret ever enters this module. There is no signing function on purpose."""
from __future__ import annotations

import hashlib
from typing import Optional, Tuple

Point = Tuple[int, int, int, int]  # extended homogeneous coordinates (X, Y, Z, T), x = X/Z, y = Y/Z, x*y = T/Z

p = 2**255 - 19
q = 2**252 + 27742317777372353535851937790883648493  # the group order L
d = -121665 * pow(121666, p - 2, p) % p
_SQRT_M1 = pow(2, (p - 1) // 4, p)


def _inv(x: int) -> int:
    return pow(x, p - 2, p)


def _add(P: Point, Q: Point) -> Point:
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % p, G * H % p, F * G % p, E * H % p)


def _mul(s: int, P: Point) -> Point:
    Q: Point = (0, 1, 1, 0)  # the neutral element
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _equal(P: Point, Q: Point) -> bool:
    return (P[0] * Q[2] - Q[0] * P[2]) % p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % p == 0


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= p:
        return None
    x2 = (y * y - 1) * _inv(d * y * y + 1) % p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * _SQRT_M1 % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


_GY = 4 * _inv(5) % p
_GX = _recover_x(_GY, 0)
assert _GX is not None
G: Point = (_GX, _GY, 1, _GX * _GY % p)


def _decompress(s: bytes) -> Optional[Point]:
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % p)


def is_public_key(public: bytes) -> bool:
    """True when `public` encodes a point on the curve (32 bytes)."""
    return _decompress(public) is not None


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _decompress(public)
    if A is None:
        return False
    Rs = signature[:32]
    R = _decompress(Rs)
    if R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= q:
        return False
    h = int.from_bytes(hashlib.sha512(Rs + public + message).digest(), "little") % q
    return _equal(_mul(s, G), _add(R, _mul(h, A)))

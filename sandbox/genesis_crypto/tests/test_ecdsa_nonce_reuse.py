"""Generate two ECDSA signatures with a fixed nonce k, confirm recovery."""
from __future__ import annotations

import hashlib
import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from genesis_crypto import ecdsa_nonce_reuse


# secp256k1 curve params (for manual signing — the cryptography lib doesn't
# expose the nonce k, so we sign by hand with a chosen k).
_SECP256K1_P = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
_SECP256K1_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
_SECP256K1_GX = int("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
_SECP256K1_GY = int("483ADA7726A47D9DBEE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959", 16)


def _modinv(a: int, m: int) -> int:
    return pow(a, -1, m)


def _ec_add(P, Q, p):
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
        return None
    if P == Q:
        m = (3 * P[0] * P[0] * _modinv(2 * P[1], p)) % p
    else:
        m = ((Q[1] - P[1]) * _modinv((Q[0] - P[0]) % p, p)) % p
    x = (m * m - P[0] - Q[0]) % p
    y = (m * (P[0] - x) - P[1]) % p
    return (x, y)


def _ec_mul(k: int, P, p: int):
    R = None
    Q = P
    while k:
        if k & 1:
            R = _ec_add(R, Q, p)
        Q = _ec_add(Q, Q, p)
        k >>= 1
    return R


def _sign_with_k(d: int, msg_bytes: bytes, k: int) -> tuple[int, int]:
    z = int.from_bytes(hashlib.sha256(msg_bytes).digest(), "big")
    # Reduce to curve order
    R = _ec_mul(k, (_SECP256K1_GX, _SECP256K1_GY), _SECP256K1_P)
    assert R is not None
    r = R[0] % _SECP256K1_N
    s = (_modinv(k, _SECP256K1_N) * (z + r * d)) % _SECP256K1_N
    return r, s


def test_ecdsa_nonce_reuse_recovers_private_key():
    d = secrets.randbelow(_SECP256K1_N - 2) + 1
    k = secrets.randbelow(_SECP256K1_N - 2) + 1
    msg1 = b"payload one"
    msg2 = b"entirely different payload two"
    r1, s1 = _sign_with_k(d, msg1, k)
    r2, s2 = _sign_with_k(d, msg2, k)
    assert r1 == r2, "nonce k should produce identical r"

    z1 = hashlib.sha256(msg1).hexdigest()
    z2 = hashlib.sha256(msg2).hexdigest()

    result = ecdsa_nonce_reuse.attack(
        curve="secp256k1",
        r=hex(r1),
        s1=hex(s1),
        s2=hex(s2),
        hash1_hex=z1,
        hash2_hex=z2,
    )
    assert result["ok"] is True, result
    assert int(result["private_key_hex"], 16) == d


def test_ecdsa_nonce_reuse_rejects_equal_s():
    r = ecdsa_nonce_reuse.attack(
        curve="secp256k1",
        r="0x1",
        s1="0x2",
        s2="0x2",
        hash1_hex="ab" * 32,
        hash2_hex="cd" * 32,
    )
    assert r["ok"] is False
    assert "s1 == s2" in r["reason"]


def test_ecdsa_nonce_reuse_rejects_unsupported_curve():
    r = ecdsa_nonce_reuse.attack(
        curve="brainpoolP256r1",
        r="0x1", s1="0x2", s2="0x3",
        hash1_hex="ab" * 32, hash2_hex="cd" * 32,
    )
    assert r["ok"] is False
    assert "unsupported" in r["reason"]

"""RSA low-e attacks — plain cube-root, Håstad broadcast, Franklin-Reiter."""
from __future__ import annotations

import base64
import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from genesis_crypto import rsa_low_e


def _small_e_key(bits: int = 1024):
    return rsa.generate_private_key(public_exponent=3, key_size=bits)


def _encrypt_textbook(m: int, n: int, e: int) -> int:
    return pow(m, e, n)


def test_plain_small_e_cube_root():
    # m^3 < n so there is no modular reduction.
    key = _small_e_key(2048)
    pub = key.public_key().public_numbers()
    n, e = pub.n, pub.e

    m_bytes = b"secret"
    m = int.from_bytes(m_bytes, "big")
    assert pow(m, e) < n
    c = _encrypt_textbook(m, n, e)

    r = rsa_low_e.attack(mode="plain", n=str(n), e=e, ciphertext=str(c))
    assert r["ok"] is True, r
    assert base64.b64decode(r["plaintext_b64"]) == m_bytes


def test_hastad_broadcast_recovers_message():
    e = 3
    keys = [_small_e_key(1024) for _ in range(3)]
    moduli = [k.public_key().public_numbers().n for k in keys]
    # Sort so moduli are stable
    m_bytes = b"cross-broadcast message"
    m = int.from_bytes(m_bytes, "big")

    cts = [_encrypt_textbook(m, n, e) for n in moduli]
    r = rsa_low_e.attack(
        mode="broadcast",
        e=e,
        moduli=[str(n) for n in moduli],
        ciphertexts=[str(c) for c in cts],
    )
    assert r["ok"] is True, r
    assert base64.b64decode(r["plaintext_b64"]) == m_bytes


def test_franklin_reiter_related_messages():
    e = 3
    key = _small_e_key(1024)
    n = key.public_key().public_numbers().n
    # m2 = a*m1 + b
    m1 = int.from_bytes(b"franklin-reiter base", "big")
    a = 2
    b = 7
    m2 = (a * m1 + b) % n
    c1 = _encrypt_textbook(m1, n, e)
    c2 = _encrypt_textbook(m2, n, e)

    r = rsa_low_e.attack(
        mode="franklin_reiter",
        n=str(n),
        e=e,
        c1=str(c1),
        c2=str(c2),
        a=str(a),
        b=str(b),
    )
    assert r["ok"] is True, r
    assert int(r["plaintext_int"]) == m1


def test_rsa_low_e_unknown_mode():
    r = rsa_low_e.attack(mode="wrong")
    assert r["ok"] is False
    assert "unknown mode" in r["reason"]

"""Wiener's attack on RSA with a small private exponent."""
from __future__ import annotations

from genesis_crypto import lattice


def _egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x, y = _egcd(b, a % b)
    return (g, y, x - (a // b) * y)


def _modinv(a, m):
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError("no inverse")
    return x % m


def _build_wiener_key():
    # Two small primes whose product has a small-d RSA key: we pick d small
    # and derive e from it so that d < n^0.25 / 3 with some margin.
    p = 0xE0DFD2C2A288ACEBC705EFAB30E4447541A8C5A47A37185C5A9CB98389CE4DE19
    q = 0xD1A5567DB85B2DC05FB43BC6C28AB531D4B33C4731B20ADAB79F35F33EEBD39D
    n = p * q
    phi = (p - 1) * (q - 1)
    # Choose small d coprime to phi
    d = 3
    while True:
        try:
            e = _modinv(d, phi)
        except ValueError:
            d += 2
            continue
        # Wiener condition: d < n^0.25 / 3 — our n is ~512 bits so n^0.25 is ~128 bits.
        if d.bit_length() < 20:
            return n, e, d
        break  # pragma: no cover


def test_wiener_recovers_small_d():
    n, e, d_true = _build_wiener_key()
    r = lattice.attack(mode="wiener", e=str(e), n=str(n))
    assert r["ok"] is True, r
    assert int(r["private_exponent_d"]) == d_true


def test_lattice_coppersmith_is_gracefully_unavailable():
    r = lattice.attack(mode="coppersmith_stereotyped", n="0", e="0")
    assert r["ok"] is False
    assert r.get("unavailable") is True


def test_lattice_unknown_mode():
    r = lattice.attack(mode="bogus")
    assert r["ok"] is False

"""Recover ECDSA private key from two signatures that reused the nonce ``k``.

Math (nothing novel):
    s1 = k^-1 (z1 + r·d)   mod n
    s2 = k^-1 (z2 + r·d)   mod n

    k = (z1 - z2) · (s1 - s2)^-1   mod n
    d = (s1·k - z1) · r^-1         mod n

Curve params are hard-coded for common curves. Caller supplies raw ``r``, ``s``,
and message-hash bytes for each signature.
"""
from __future__ import annotations

from typing import Any

from ._common import hexd, modinv, safe_result


# (name, n, hash_bits_recommended)
_CURVES: dict[str, tuple[str, int]] = {
    # (curve_n_hex, hash_bits)
    "secp256k1": (
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        256,
    ),
    "P-256": (  # aka prime256v1 / secp256r1
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
        256,
    ),
    "P-384": (
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
        "581A0DB248B0A77AECEC196ACCC52973",
        384,
    ),
    "P-521": (
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E913"
        "8640",
        521,
    ),
}


def _truncate_hash(z: int, n: int) -> int:
    """ECDSA hashes are truncated to bit-length of n."""
    n_bits = n.bit_length()
    z_bits = z.bit_length()
    if z_bits > n_bits:
        z >>= z_bits - n_bits
    return z


def _parse_bigint(v: Any) -> int:
    if isinstance(v, int):
        return v
    s = str(v).strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    try:
        return int(s)
    except ValueError:
        return int(s, 16)


@safe_result
def attack(
    curve: str,
    r: Any,
    s1: Any,
    s2: Any,
    hash1_hex: str,
    hash2_hex: str,
    **_: Any,
) -> dict[str, Any]:
    """Recover k and d given two signatures (r, s1) (r, s2) that share r.

    :param curve: one of secp256k1, P-256, P-384, P-521.
    :param r: shared signature r component (int or hex string).
    :param s1, s2: differing s components (int or hex strings).
    :param hash1_hex, hash2_hex: the two message digests (hex).
    """
    if curve not in _CURVES:
        return {
            "ok": False,
            "reason": f"unsupported curve '{curve}'. Supported: {list(_CURVES)}",
        }
    n_hex, _ = _CURVES[curve]
    n = int(n_hex, 16)

    r_i = _parse_bigint(r) % n
    s1_i = _parse_bigint(s1) % n
    s2_i = _parse_bigint(s2) % n
    z1 = _truncate_hash(int.from_bytes(hexd(hash1_hex), "big"), n)
    z2 = _truncate_hash(int.from_bytes(hexd(hash2_hex), "big"), n)

    if s1_i == s2_i:
        return {"ok": False, "reason": "s1 == s2 — signatures identical"}
    if r_i == 0:
        return {"ok": False, "reason": "r == 0 — malformed signature"}

    k = ((z1 - z2) * modinv(s1_i - s2_i, n)) % n
    d = ((s1_i * k - z1) * modinv(r_i, n)) % n

    if d == 0:
        return {"ok": False, "reason": "recovered d is 0 — inputs inconsistent"}

    return {
        "ok": True,
        "curve": curve,
        "private_key_hex": f"{d:x}".zfill(n.bit_length() // 4),
        "nonce_k_hex": f"{k:x}",
        "note": "Verify by signing a test message and checking against the known public key.",
    }

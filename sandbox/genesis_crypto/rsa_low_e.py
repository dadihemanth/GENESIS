"""Small-e attacks on RSA.

Covers:
  - "plain" small e: if m^e < n, plaintext is the integer e-th root of the
    ciphertext (no modular reduction happened).
  - Håstad broadcast: the same message encrypted to e recipients with coprime
    moduli and public exponent e yields m via CRT + integer e-th root.
  - Franklin–Reiter related-message attack: two messages related by a known
    affine function m2 = a·m1 + b, shared (n, e=3), recover m1 via polynomial
    GCD over Z/nZ (pure-Python implementation for small polynomial degrees).
"""
from __future__ import annotations

from typing import Any

from ._common import b64e, crt, iroot, safe_result


def _pt_to_out(m: int, byte_len: int | None = None) -> dict[str, Any]:
    if m <= 0:
        return {"ok": False, "reason": "recovered integer is non-positive"}
    length = byte_len or ((m.bit_length() + 7) // 8)
    pt = m.to_bytes(length, "big").lstrip(b"\x00")
    return {
        "ok": True,
        "plaintext_int": str(m),
        "plaintext_hex": f"{m:x}",
        "plaintext_b64": b64e(pt),
        "plaintext_utf8_preview": pt[:200].decode("utf-8", errors="replace"),
    }


# Polynomial helpers over Z/nZ for Franklin–Reiter.
def _poly_mod(a: list[int], b: list[int], n: int) -> list[int]:
    """a mod b over Z/nZ. Coefficients low→high. b assumed monic after
    dividing by its leading coefficient's modular inverse."""
    a = [x % n for x in a]
    b = [x % n for x in b]
    while b and b[-1] == 0:
        b.pop()
    if not b:
        raise ZeroDivisionError("polynomial divisor is zero")
    # Make b monic
    from ._common import modinv

    inv = modinv(b[-1], n)
    b = [(x * inv) % n for x in b]
    while len(a) >= len(b):
        if a[-1] == 0:
            a.pop()
            continue
        factor = a[-1]
        shift = len(a) - len(b)
        for i, bi in enumerate(b):
            a[i + shift] = (a[i + shift] - factor * bi) % n
        while a and a[-1] == 0:
            a.pop()
    return a


def _poly_gcd(a: list[int], b: list[int], n: int) -> list[int]:
    a = list(a)
    b = list(b)
    while b and any(x != 0 for x in b):
        a, b = b, _poly_mod(a, b, n)
    while a and a[-1] == 0:
        a.pop()
    return a


@safe_result
def attack(
    mode: str,
    **params: Any,
) -> dict[str, Any]:
    """Dispatch to a specific small-e primitive.

    ``mode`` values:
      - ``"plain"`` — params: n, e, ciphertext (int or hex string).
      - ``"broadcast"`` — params: e, moduli (list), ciphertexts (list).
      - ``"franklin_reiter"`` — params: n, e (== 3), c1, c2, a, b.
    """
    if mode == "plain":
        n = _bigint(params["n"])
        e = int(params.get("e", 3))
        c = _bigint(params["ciphertext"])
        root, exact = iroot(c, e)
        if exact:
            return _pt_to_out(root)
        # Try small k·n + c (plaintext straddled reduction)
        for k in range(1, 8):
            root, exact = iroot(c + k * n, e)
            if exact:
                out = _pt_to_out(root)
                if out.get("ok"):
                    out["reduction_k"] = k
                    return out
        return {"ok": False, "reason": "c was reduced mod n; plain-root attack fails"}

    if mode == "broadcast":
        e = int(params.get("e", 3))
        moduli = [_bigint(x) for x in params["moduli"]]
        cts = [_bigint(x) for x in params["ciphertexts"]]
        if len(moduli) != len(cts):
            return {"ok": False, "reason": "moduli and ciphertexts length mismatch"}
        if len(moduli) < e:
            return {"ok": False, "reason": f"broadcast needs ≥ {e} samples"}
        m_e, _ = crt(cts[:e], moduli[:e])
        root, exact = iroot(m_e, e)
        if not exact:
            return {"ok": False, "reason": "CRT result is not an exact e-th power — inputs may be unpadded differently"}
        return _pt_to_out(root)

    if mode == "franklin_reiter":
        n = _bigint(params["n"])
        e = int(params.get("e", 3))
        if e != 3:
            return {"ok": False, "reason": "franklin_reiter implementation requires e=3"}
        c1 = _bigint(params["c1"])
        c2 = _bigint(params["c2"])
        a = _bigint(params["a"])
        b = _bigint(params["b"])
        # g1(x) = x^3 - c1  (root: m)
        g1 = [(-c1) % n, 0, 0, 1]
        # g2(x) = (a·x + b)^3 - c2  (root: m)
        a3 = pow(a, 3, n)
        a2b3 = (3 * pow(a, 2, n) * b) % n
        ab23 = (3 * a * pow(b, 2, n)) % n
        b3 = pow(b, 3, n)
        g2 = [(b3 - c2) % n, ab23, a2b3, a3]
        gcd = _poly_gcd(g1, g2, n)
        if len(gcd) != 2:
            return {"ok": False, "reason": f"GCD has unexpected degree {len(gcd) - 1}; attack failed"}
        from ._common import modinv

        m = (-gcd[0] * modinv(gcd[1], n)) % n
        return _pt_to_out(m)

    return {"ok": False, "reason": f"unknown mode '{mode}'. Use plain | broadcast | franklin_reiter."}


def _bigint(v: Any) -> int:
    if isinstance(v, int):
        return v
    s = str(v).strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    try:
        return int(s)
    except ValueError:
        return int(s, 16)

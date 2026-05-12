"""Lattice attacks on weak RSA.

This module ships **Wiener's attack** (continued-fraction recovery of a small
``d`` from the public key (e, n)) and a hook for Coppersmith / Boneh-Durfee
stubs that require SageMath or flint/fplll. The Coppersmith modes return a
structured "requires-sage" error so the caller can fall back gracefully.

Wiener works when ``d < n^0.25 / 3``. It's cheap, pure-Python, and the most
common real-world hit.
"""
from __future__ import annotations

from typing import Any

from ._common import iroot, safe_result


def _continued_fraction(num: int, den: int) -> list[int]:
    out: list[int] = []
    while den:
        out.append(num // den)
        num, den = den, num - out[-1] * den
    return out


def _convergents(cf: list[int]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for i in range(len(cf)):
        if i == 0:
            out.append((cf[0], 1))
        elif i == 1:
            out.append((cf[1] * cf[0] + 1, cf[1]))
        else:
            p = cf[i] * out[-1][0] + out[-2][0]
            q = cf[i] * out[-1][1] + out[-2][1]
            out.append((p, q))
    return out


def _wiener(e: int, n: int) -> tuple[int, int, int] | None:
    cf = _continued_fraction(e, n)
    for k, d in _convergents(cf):
        if k == 0:
            continue
        phi = (e * d - 1) // k
        if (e * d - 1) % k != 0:
            continue
        # n = pq, phi = (p-1)(q-1) = n - (p+q) + 1 → p+q = n - phi + 1
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        root, exact = iroot(disc, 2)
        if not exact:
            continue
        if (s + root) % 2 != 0:
            continue
        p = (s + root) // 2
        q = (s - root) // 2
        if p * q == n:
            return d, p, q
    return None


@safe_result
def attack(
    mode: str,
    **params: Any,
) -> dict[str, Any]:
    """Dispatch to a lattice-family attack.

    ``mode``:
      - ``"wiener"`` — params: e, n. Recovers d if small.
      - ``"coppersmith_stereotyped"`` — requires SageMath (not available in
        sandbox v1). Returns a structured "unavailable" response.
      - ``"boneh_durfee"`` — same as above.
    """
    if mode == "wiener":
        e = _bigint(params["e"])
        n = _bigint(params["n"])
        got = _wiener(e, n)
        if got is None:
            return {"ok": False, "reason": "Wiener's attack failed — d is likely not small enough"}
        d, p, q = got
        return {
            "ok": True,
            "mode": "wiener",
            "private_exponent_d": str(d),
            "private_exponent_d_hex": f"{d:x}",
            "prime_p_hex": f"{p:x}",
            "prime_q_hex": f"{q:x}",
        }

    if mode in ("coppersmith_stereotyped", "boneh_durfee", "coppersmith_partial_p"):
        return {
            "ok": False,
            "reason": (
                f"mode '{mode}' requires SageMath / fplll. This sandbox ships "
                "pure-Python primitives only. Use sage-docker externally or "
                "request T26-followup for a sage-backed lattice container."
            ),
            "unavailable": True,
        }

    return {"ok": False, "reason": f"unknown mode '{mode}'"}


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

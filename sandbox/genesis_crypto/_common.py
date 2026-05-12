"""Shared helpers for crypto primitives."""
from __future__ import annotations

import base64
import re
from typing import Any, Callable

import requests


class OracleError(RuntimeError):
    pass


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def hexd(s: str) -> bytes:
    return bytes.fromhex(s.replace(":", "").replace(" ", ""))


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"no modular inverse: gcd({a},{m}) = {g}")
    return x % m


def crt(residues: list[int], moduli: list[int]) -> tuple[int, int]:
    """Garner's CRT. Assumes moduli are pairwise coprime. Returns (x, N)."""
    if len(residues) != len(moduli):
        raise ValueError("residues and moduli length mismatch")
    x, N = 0, 1
    for r, m in zip(residues, moduli):
        g, p, _ = egcd(N, m)
        if g != 1:
            raise ValueError(f"moduli not coprime: gcd={g}")
        x = (x + N * p * (r - x)) % (N * m)
        N *= m
    return x, N


def iroot(n: int, k: int) -> tuple[int, bool]:
    """Integer k-th root via binary search. Returns (root, exact)."""
    if n < 0:
        raise ValueError("negative")
    if n < 2:
        return n, True
    lo, hi = 1, 1 << ((n.bit_length() + k - 1) // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid**k <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo, lo**k == n


def build_oracle(
    url: str,
    success_regex: str | None,
    success_status: int | None,
    method: str = "POST",
    body_template: str = "{ciphertext_hex}",
    content_type: str = "application/x-www-form-urlencoded",
    timeout_s: float = 8.0,
) -> Callable[[bytes], bool]:
    """Return a callable ``(ciphertext_bytes) -> padding_ok_bool``.

    The oracle substitutes ``{ciphertext_hex}`` / ``{ciphertext_b64}`` in
    ``body_template`` with the candidate ciphertext. Success is determined by
    status code (if ``success_status`` given) OR by matching ``success_regex``
    against the response body.
    """
    if not success_regex and success_status is None:
        raise ValueError("oracle needs success_regex or success_status")

    regex = re.compile(success_regex, re.DOTALL) if success_regex else None

    def oracle(ct: bytes) -> bool:
        payload = body_template.format(
            ciphertext_hex=ct.hex(),
            ciphertext_b64=b64e(ct),
        )
        try:
            if method.upper() == "GET":
                r = requests.get(
                    url,
                    params={"q": payload} if "{" not in url else None,
                    timeout=timeout_s,
                )
            else:
                r = requests.post(
                    url,
                    data=payload.encode() if content_type != "application/json" else None,
                    json=(
                        {"ciphertext": b64e(ct)}
                        if content_type == "application/json"
                        else None
                    ),
                    headers={"Content-Type": content_type},
                    timeout=timeout_s,
                )
        except requests.RequestException as exc:
            raise OracleError(f"oracle unreachable: {exc}") from exc

        if success_status is not None and r.status_code == success_status:
            return True
        if regex and regex.search(r.text):
            return True
        return False

    return oracle


def safe_result(fn: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
    """Decorator: catch primitive exceptions and return ``{"ok": False, ...}``."""

    def wrapper(**kwargs: Any) -> dict[str, Any]:
        try:
            return fn(**kwargs)
        except (ValueError, OracleError, requests.RequestException) as exc:
            return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "reason": f"unexpected {type(exc).__name__}: {exc}"}

    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper

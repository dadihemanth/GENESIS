"""Length-extension attack on Merkle-Damgård hashes (MD5, SHA-1, SHA-256).

Given ``H(key || message)`` and the lengths of ``key`` and ``message``, forge
``H(key || message || glue_pad || append)`` without knowing ``key``.

Implements MD5 / SHA-1 / SHA-256 hash-state continuation in pure Python —
avoids depending on third-party hashpumpy.
"""
from __future__ import annotations

import struct
from typing import Any

from ._common import hexd, safe_result


# ── MD5 ────────────────────────────────────────────────────────────────────
_MD5_K = [int(abs(__import__("math").sin(i + 1)) * (1 << 32)) & 0xFFFFFFFF for i in range(64)]
_MD5_S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
]


def _md5_compress(state: list[int], block: bytes) -> list[int]:
    a, b, c, d = state
    M = list(struct.unpack("<16I", block))
    A, B, C, D = a, b, c, d
    for i in range(64):
        if i < 16:
            F = (B & C) | ((~B) & D)
            g = i
        elif i < 32:
            F = (D & B) | ((~D) & C)
            g = (5 * i + 1) % 16
        elif i < 48:
            F = B ^ C ^ D
            g = (3 * i + 5) % 16
        else:
            F = C ^ (B | (~D))
            g = (7 * i) % 16
        F = (F + A + _MD5_K[i] + M[g]) & 0xFFFFFFFF
        A = D
        D = C
        C = B
        B = (B + (((F << _MD5_S[i]) | (F >> (32 - _MD5_S[i]))) & 0xFFFFFFFF)) & 0xFFFFFFFF
    return [(a + A) & 0xFFFFFFFF, (b + B) & 0xFFFFFFFF, (c + C) & 0xFFFFFFFF, (d + D) & 0xFFFFFFFF]


def _md5_pad(msg_len: int) -> bytes:
    bit_len = msg_len * 8
    pad = b"\x80" + b"\x00" * ((56 - (msg_len + 1) % 64) % 64)
    return pad + struct.pack("<Q", bit_len)


def _md5_extend(known_digest: bytes, known_len: int, append: bytes) -> tuple[bytes, bytes]:
    state = list(struct.unpack("<4I", known_digest))
    glue = _md5_pad(known_len)
    total_prefix = known_len + len(glue)

    # Process append in 64-byte blocks — pad again at the end relative to
    # (total_prefix + len(append)).
    data = append + _md5_pad(total_prefix + len(append))
    for i in range(0, len(data), 64):
        state = _md5_compress(state, data[i : i + 64])
    new_digest = struct.pack("<4I", *state)
    new_message = glue + append
    return new_digest, new_message


# ── SHA-1 / SHA-256 (big-endian cousins) ──────────────────────────────────
def _rotr(x: int, n: int, bits: int = 32) -> int:
    return ((x >> n) | (x << (bits - n))) & ((1 << bits) - 1)


def _rotl(x: int, n: int, bits: int = 32) -> int:
    return ((x << n) | (x >> (bits - n))) & ((1 << bits) - 1)


def _sha1_compress(state: list[int], block: bytes) -> list[int]:
    W = list(struct.unpack(">16I", block)) + [0] * 64
    for i in range(16, 80):
        W[i] = _rotl(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1)
    a, b, c, d, e = state
    for i in range(80):
        if i < 20:
            f = (b & c) | ((~b) & d)
            k = 0x5A827999
        elif i < 40:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif i < 60:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            k = 0xCA62C1D6
        temp = (_rotl(a, 5) + f + e + k + W[i]) & 0xFFFFFFFF
        e, d, c, b, a = d, c, _rotl(b, 30), a, temp
    return [(x + y) & 0xFFFFFFFF for x, y in zip(state, [a, b, c, d, e])]


def _be_pad(msg_len: int) -> bytes:
    bit_len = msg_len * 8
    pad = b"\x80" + b"\x00" * ((56 - (msg_len + 1) % 64) % 64)
    return pad + struct.pack(">Q", bit_len)


def _sha1_extend(known_digest: bytes, known_len: int, append: bytes) -> tuple[bytes, bytes]:
    state = list(struct.unpack(">5I", known_digest))
    glue = _be_pad(known_len)
    total_prefix = known_len + len(glue)
    data = append + _be_pad(total_prefix + len(append))
    for i in range(0, len(data), 64):
        state = _sha1_compress(state, data[i : i + 64])
    return struct.pack(">5I", *state), glue + append


_SHA256_K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]


def _sha256_compress(state: list[int], block: bytes) -> list[int]:
    W = list(struct.unpack(">16I", block)) + [0] * 48
    for i in range(16, 64):
        s0 = _rotr(W[i - 15], 7) ^ _rotr(W[i - 15], 18) ^ (W[i - 15] >> 3)
        s1 = _rotr(W[i - 2], 17) ^ _rotr(W[i - 2], 19) ^ (W[i - 2] >> 10)
        W[i] = (W[i - 16] + s0 + W[i - 7] + s1) & 0xFFFFFFFF
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ ((~e) & g)
        temp1 = (h + S1 + ch + _SHA256_K[i] + W[i]) & 0xFFFFFFFF
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        mj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + mj) & 0xFFFFFFFF
        h, g, f = g, f, e
        e = (d + temp1) & 0xFFFFFFFF
        d, c, b = c, b, a
        a = (temp1 + temp2) & 0xFFFFFFFF
    return [(x + y) & 0xFFFFFFFF for x, y in zip(state, [a, b, c, d, e, f, g, h])]


def _sha256_extend(known_digest: bytes, known_len: int, append: bytes) -> tuple[bytes, bytes]:
    state = list(struct.unpack(">8I", known_digest))
    glue = _be_pad(known_len)
    total_prefix = known_len + len(glue)
    data = append + _be_pad(total_prefix + len(append))
    for i in range(0, len(data), 64):
        state = _sha256_compress(state, data[i : i + 64])
    return struct.pack(">8I", *state), glue + append


_IMPLS = {
    "md5": (_md5_extend, 16),
    "sha1": (_sha1_extend, 20),
    "sha256": (_sha256_extend, 32),
}


@safe_result
def attack(
    algorithm: str,
    known_hash_hex: str,
    known_data: str,
    append_data: str,
    key_length: int,
    **_: Any,
) -> dict[str, Any]:
    """Produce ``H(key||known||glue||append)`` and the forged message body.

    :param algorithm: md5 | sha1 | sha256.
    :param known_hash_hex: the observed ``H(key || known_data)``.
    :param known_data: the known message (str — sent in as-is bytes via UTF-8).
        Pass the exact bytes the server hashed.
    :param append_data: the bytes to append after the glue padding.
    :param key_length: length of the unknown key prefix in bytes.
    """
    algo = algorithm.lower()
    if algo not in _IMPLS:
        return {"ok": False, "reason": f"unsupported algorithm '{algorithm}'"}

    impl, digest_len = _IMPLS[algo]
    known_bytes = known_data.encode("utf-8") if isinstance(known_data, str) else known_data
    append_bytes = append_data.encode("utf-8") if isinstance(append_data, str) else append_data
    known_digest = hexd(known_hash_hex)
    if len(known_digest) != digest_len:
        return {
            "ok": False,
            "reason": f"{algo} digest must be {digest_len} bytes (got {len(known_digest)})",
        }

    new_digest, new_suffix = impl(known_digest, key_length + len(known_bytes), append_bytes)
    forged_message = known_bytes + new_suffix
    return {
        "ok": True,
        "algorithm": algo,
        "new_hash_hex": new_digest.hex(),
        "new_message_hex": forged_message.hex(),
        "new_message_b64": __import__("base64").b64encode(forged_message).decode("ascii"),
        "glue_padding_hex": new_suffix[: len(new_suffix) - len(append_bytes)].hex(),
    }

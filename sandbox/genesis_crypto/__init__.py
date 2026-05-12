"""GENESIS crypto primitives — well-known attacks as library calls.

Each submodule exposes an ``attack(**params)`` function that returns a dict with
at minimum ``{"ok": bool, "reason": str}``. Successful attacks add their
recovered artefact (plaintext, private key, forged token, etc.).

These primitives are intended to be called from short driver scripts dispatched
to the forge_sandbox ``/run`` endpoint. They do NOT call out to any network
service on their own — when an oracle is required, the caller supplies
``oracle_url`` and the primitive issues HTTP requests to that URL only.
"""

from . import (
    padding_oracle,
    bleichenbacher,
    ecdsa_nonce_reuse,
    length_extension,
    rsa_low_e,
    lattice,
    jwt_confusion,
)

__all__ = [
    "padding_oracle",
    "bleichenbacher",
    "ecdsa_nonce_reuse",
    "length_extension",
    "rsa_low_e",
    "lattice",
    "jwt_confusion",
]

__version__ = "0.1.0"

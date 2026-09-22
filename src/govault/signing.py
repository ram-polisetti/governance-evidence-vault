"""HMAC-SHA256 signing of the attestation.

Integrity model (documented honestly in docs/LIMITATIONS.md):
- The attestation is signed with an operator-held symmetric key via
  HMAC-SHA256. This proves the bundle was assembled by someone holding
  the key, and that the attestation was not altered afterwards.
- It is NOT a PKI/X.509 signature: there is no certificate chain and no
  public-key verification. An external auditor WITHOUT the key can still
  independently verify every artifact hash and the vault hash chain —
  the signature only adds origin assurance for parties that share the key.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from .hashchain import canonical

ALG = "HMAC-SHA256"


def sign_attestation(attestation: dict, key: bytes) -> dict:
    sig = hmac.new(key, canonical(attestation), hashlib.sha256).hexdigest()
    return {
        "alg": ALG,
        "attestation_sha256": hashlib.sha256(
            canonical(attestation)).hexdigest(),
        "signature": sig,
    }


def verify_signature(attestation: dict, signature: dict, key: bytes) -> bool:
    if signature.get("alg") != ALG:
        return False
    want = hmac.new(key, canonical(attestation), hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, signature.get("signature", ""))


def load_key(path: Path) -> bytes:
    key = Path(path).read_bytes().strip()
    if len(key) < 16:
        raise ValueError(f"{path}: key too short (need >= 16 bytes)")
    return key

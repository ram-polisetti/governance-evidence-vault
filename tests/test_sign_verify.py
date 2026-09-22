"""Signing + verification tests."""
import json
import os

import pytest

from govault.bundle import (PREDICATE_TYPE, STATEMENT_TYPE, build_attestation)
from govault.signing import load_key, sign_attestation, verify_signature
from govault.verify import verify_bundle


def attest():
    return build_attestation(
        "vault-test",
        {"name": "demo-sys", "version": "1.0"},
        [{"slot": "a", "file": "evidence/a/f.txt",
          "sha256": "x" * 64, "bytes": 3}],
        {"inputs": []})


def test_sign_verify_round_trip():
    a = attest()
    key = b"0" * 32
    sig = sign_attestation(a, key)
    assert sig["alg"] == "HMAC-SHA256"
    assert verify_signature(a, sig, key)


def test_sign_wrong_key_rejected():
    a = attest()
    sig = sign_attestation(a, b"0" * 32)
    assert not verify_signature(a, sig, b"1" * 32)


def test_sign_tampered_attestation_rejected():
    a = attest()
    sig = sign_attestation(a, b"0" * 32)
    a["predicate"]["evidence"].append({"slot": "forged"})
    assert not verify_signature(a, sig, b"0" * 32)


def test_load_key_too_short(tmp_path):
    p = tmp_path / "k"
    p.write_bytes(b"short")
    with pytest.raises(ValueError):
        load_key(p)


def _write_bundle(tmp_path, tamper=None, drop=None):
    bundle = tmp_path / "bundle"
    ev = bundle / "evidence" / "a"
    ev.mkdir(parents=True)
    f = ev / "f.txt"
    f.write_bytes(b"abc")
    import hashlib
    digest = hashlib.sha256(b"abc").hexdigest()
    a = build_attestation(
        "vault-test", {"name": "demo-sys", "version": "1.0"},
        [{"slot": "a", "kind": "eval-report", "file": "evidence/a/f.txt",
          "sha256": digest, "bytes": 3, "source": "rag-redteam",
          "source_sha": "169e4c8"}],
        {"inputs": []})
    (bundle / "attestation.json").write_text(json.dumps(a, indent=2))
    sig = sign_attestation(a, b"k" * 32)
    (bundle / "signature.json").write_text(json.dumps(sig))
    if tamper == "file":
        f.write_bytes(b"abd")
    if tamper == "attestation":
        a["predicate"]["evidence"][0]["sha256"] = "0" * 64
        (bundle / "attestation.json").write_text(json.dumps(a, indent=2))
    if drop == "file":
        f.unlink()
    return bundle


def test_verify_good_bundle(tmp_path):
    report = verify_bundle(_write_bundle(tmp_path), key=b"k" * 32)
    assert report["ok"], report
    assert any(c["check"] == "signature" and c["ok"]
               for c in report["checks"])


def test_verify_detects_file_tamper(tmp_path):
    report = verify_bundle(_write_bundle(tmp_path, tamper="file"))
    assert not report["ok"]
    assert any("hash mismatch" in c["detail"]
               for c in report["checks"] if not c["ok"])


def test_verify_detects_missing_file(tmp_path):
    report = verify_bundle(_write_bundle(tmp_path, drop="file"))
    assert not report["ok"]


def test_verify_detects_attestation_tamper_with_key(tmp_path):
    # attestation rewritten after signing -> signature invalid
    report = verify_bundle(_write_bundle(tmp_path, tamper="attestation"),
                           key=b"k" * 32)
    assert not report["ok"]
    assert any(c["check"] == "signature" and not c["ok"]
               for c in report["checks"])


def test_verify_no_key_skips_signature_check(tmp_path):
    report = verify_bundle(_write_bundle(tmp_path))
    assert report["ok"]
    assert any("no key given" in c["detail"]
               for c in report["checks"] if c["check"] == "signature")


def test_verify_rejects_wrong_statement_type(tmp_path):
    bundle = _write_bundle(tmp_path)
    a = json.loads((bundle / "attestation.json").read_text())
    a["_type"] = "https://evil.example/Statement/v9"
    (bundle / "attestation.json").write_text(json.dumps(a))
    report = verify_bundle(bundle)
    assert not report["ok"]

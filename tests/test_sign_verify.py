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


@pytest.mark.parametrize('relative', ['../outside.txt', '/tmp/outside.txt', '', 42])
def test_verify_rejects_unsafe_evidence_path(tmp_path, relative):
    bundle = _write_bundle(tmp_path)
    a = json.loads((bundle / 'attestation.json').read_text())
    a['predicate']['evidence'][0]['file'] = relative
    (bundle / 'attestation.json').write_text(json.dumps(a))
    assert not verify_bundle(bundle)['ok']


def test_verify_rejects_symlink_evidence(tmp_path):
    bundle = _write_bundle(tmp_path)
    outside = tmp_path / 'outside.txt'
    outside.write_bytes(b'abc')
    evidence = bundle / 'evidence/a/f.txt'
    evidence.unlink()
    evidence.symlink_to(outside)
    assert not verify_bundle(bundle)['ok']


def test_verify_rejects_directory_evidence(tmp_path):
    bundle = _write_bundle(tmp_path)
    evidence = bundle / 'evidence/a/f.txt'
    evidence.unlink()
    evidence.mkdir()
    assert not verify_bundle(bundle)['ok']


def test_verify_rejects_nul_path_without_aborting(tmp_path):
    bundle = _write_bundle(tmp_path)
    att = json.loads((bundle / 'attestation.json').read_text())
    att['predicate']['evidence'][0]['file'] = 'bad\0path'
    (bundle / 'attestation.json').write_text(json.dumps(att))
    assert not verify_bundle(bundle)['ok']


def test_verify_rejects_symlink_replacement_at_open(tmp_path, monkeypatch):
    import govault.verify as verifier
    bundle = _write_bundle(tmp_path)
    outside = tmp_path / 'outside.txt'
    outside.write_bytes(b'abc')
    evidence = bundle / 'evidence/a/f.txt'
    original_open = os.open

    def replace_then_open(path, flags, *args, **kwargs):
        if path == 'f.txt':
            evidence.unlink()
            evidence.symlink_to(outside)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, 'open', replace_then_open)
    monkeypatch.setattr(os, 'supports_dir_fd', {replace_then_open})
    assert not verifier.verify_bundle(bundle)['ok']


def test_verify_rejects_ancestor_symlink_at_open(tmp_path, monkeypatch):
    bundle = _write_bundle(tmp_path)
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'f.txt').write_bytes(b'abc')
    ancestor = bundle / 'evidence/a'
    original_open = os.open

    def replace_then_open(path, flags, *args, **kwargs):
        if path == 'a':
            ancestor.rename(bundle / 'evidence/original-a')
            ancestor.symlink_to(outside, target_is_directory=True)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, 'open', replace_then_open)
    monkeypatch.setattr(os, 'supports_dir_fd', {replace_then_open})
    assert not verify_bundle(bundle)['ok']


def test_verify_rejects_fifo_without_blocking(tmp_path):
    bundle = _write_bundle(tmp_path)
    evidence = bundle / 'evidence/a/f.txt'
    evidence.unlink()
    os.mkfifo(evidence)
    assert not verify_bundle(bundle)['ok']


def test_verify_fails_closed_without_safe_open_support(tmp_path, monkeypatch):
    bundle = _write_bundle(tmp_path)
    monkeypatch.setattr(os, 'supports_dir_fd', set())
    report = verify_bundle(bundle)
    assert not report['ok']
    assert any('unsupported' in c['detail'] for c in report['checks'])

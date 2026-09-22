"""Tests for the hash-chain helpers."""
import pytest

from govault.hashchain import (canonical, chain_record, sha256_bytes,
                               sha256_file, verify_chain)


def test_canonical_is_deterministic():
    assert canonical({"b": 1, "a": 2}) == canonical({"a": 2, "b": 1})


def test_chain_round_trip():
    recs = []
    prev = "GENESIS"
    for i in range(3):
        r = chain_record(prev, {"event": "e", "i": i})
        recs.append(r)
        prev = r["record_hash"]
    ok, msg = verify_chain(recs)
    assert ok, msg
    assert "3 record" in msg


def test_chain_detects_tamper():
    recs = [chain_record("GENESIS", {"event": "e"})]
    recs[0]["event"] = "forged"
    ok, msg = verify_chain(recs)
    assert not ok and "tampered" in msg


def test_chain_detects_broken_link():
    r1 = chain_record("GENESIS", {"event": "a"})
    r2 = chain_record("WRONG", {"event": "b"})
    ok, msg = verify_chain([r1, r2])
    assert not ok and "broken" in msg


def test_sha256_file(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"hello")
    digest, size = sha256_file(p)
    assert size == 5
    assert digest == sha256_bytes(b"hello")

"""Shared hashing helpers: canonical JSON, SHA-256, hash chains."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def chain_record(prev_hash: str, body: dict) -> dict:
    """Return a hash-chained record: body + prev_hash + record hash."""
    record = {"prev_hash": prev_hash}
    record.update(body)
    record["record_hash"] = sha256_bytes(canonical(
        {k: v for k, v in record.items() if k != "record_hash"}))
    return record


def verify_chain(records: list[dict]) -> tuple[bool, str]:
    prev = "GENESIS"
    for i, rec in enumerate(records):
        if rec.get("prev_hash") != prev:
            return False, f"record {i}: prev_hash mismatch (chain broken)"
        want = sha256_bytes(canonical(
            {k: v for k, v in rec.items() if k != "record_hash"}))
        if rec.get("record_hash") != want:
            return False, f"record {i}: record_hash mismatch (tampered)"
        prev = rec["record_hash"]
    return True, f"{len(records)} record(s), chain intact"

"""The vault's own hash-chained audit log.

Every build and every verification run is appended here, chained to the
previous record. `verify` on the store detects edits, deletions, or
reorders — the same tamper-evidence model as the sibling tools.
"""
from __future__ import annotations

import json
from pathlib import Path

from .hashchain import chain_record, utcnow, verify_chain


class VaultStore:
    def __init__(self, store_dir: str | Path):
        self.dir = Path(store_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.dir / "vault.jsonl"
        self._prev = "GENESIS"
        if self.log_path.exists():
            for line in self.log_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    self._prev = json.loads(line)["record_hash"]

    def append(self, event: str, payload: dict) -> dict:
        record = chain_record(self._prev, {
            "event": event, "at": utcnow(), **payload})
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=True) + "\n")
        self._prev = record["record_hash"]
        return record

    def verify(self) -> tuple[bool, str]:
        records = []
        if self.log_path.exists():
            for line in self.log_path.read_text(
                    encoding="utf-8").splitlines():
                if line.strip():
                    records.append(json.loads(line))
        return verify_chain(records)

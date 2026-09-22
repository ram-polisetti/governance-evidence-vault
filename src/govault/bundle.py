"""Bundle assembly: copy artifacts verbatim, hash everything, write attestation."""
from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path

from . import SIBLING_SHAS, __version__
from .hashchain import canonical, sha256_bytes, sha256_file, utcnow

PREDICATE_TYPE = "https://ram-polisetti.dev/governance-evidence-bundle/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"


def _slot_dir(bundle: Path, slot: str) -> Path:
    d = bundle / "evidence" / slot
    d.mkdir(parents=True, exist_ok=True)
    return d


def add_file_evidence(bundle: Path, slot: str, src: Path,
                      entries: list) -> dict:
    """Copy one artifact into the bundle, hash it, append an entry."""
    dest = _slot_dir(bundle, slot) / src.name
    shutil.copy2(src, dest)
    digest, size = sha256_file(dest)
    entry = {
        "slot": slot,
        "file": f"evidence/{slot}/{src.name}",
        "sha256": digest,
        "bytes": size,
    }
    entries.append(entry)
    return entry


def add_text_evidence(bundle: Path, slot: str, name: str, text: str,
                      entries: list) -> dict:
    dest = _slot_dir(bundle, slot)
    path = dest / name
    path.write_text(text, encoding="utf-8")
    digest, size = sha256_file(path)
    entry = {"slot": slot, "file": f"evidence/{slot}/{name}",
             "sha256": digest, "bytes": size}
    entries.append(entry)
    return entry


def build_attestation(bundle_id: str, system: dict, entries: list,
                      annotations: dict) -> dict:
    """SLSA-style statement describing exactly what backs the deployment."""
    predicate = {
        "system": system,
        "built_utc": utcnow(),
        "tool": "governance-evidence-vault",
        "tool_version": __version__,
        "bundle_id": bundle_id,
        "sibling_shas": dict(SIBLING_SHAS),
        "evidence": entries,
        "annotations": annotations,
    }
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{
            "name": system.get("name", "unknown"),
            "digest": {"sha256": sha256_bytes(canonical(
                {"name": system.get("name"), "version": system.get("version")}))},
        }],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def write_attestation(bundle: Path, attestation: dict) -> Path:
    path = bundle / "attestation.json"
    path.write_text(json.dumps(attestation, indent=2) + "\n", encoding="utf-8")
    return path

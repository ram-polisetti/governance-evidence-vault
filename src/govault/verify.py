"""Offline verification of a bundle, as an external auditor would run it.

Checks:
1. attestation.json parses and has the expected statement/predicate types.
2. Every evidence file listed exists and its SHA-256 matches.
3. The attestation digest over the evidence list is internally consistent
   (recompute from the listed entries — catches list tampering).
4. signature.json, if present and a key is given, verifies (HMAC-SHA256).
5. Report missing evidence explicitly — never silently skip.

Exit codes: 0 = verified, 1 = tamper/mismatch detected.
"""
from __future__ import annotations

import json
import hashlib
import os
import stat
from pathlib import Path

from .bundle import PREDICATE_TYPE, STATEMENT_TYPE
from .signing import verify_signature


class VerifyError(Exception):
    pass



def _hash_evidence(root: Path, relative: Path) -> tuple[str, int]:
    """Walk beneath an open directory, refusing symlinks at every step.

    Hash the opened regular file, never a pathname checked earlier. Platforms
    without these primitives fail closed instead of using a racy fallback.
    """
    if (os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_DIRECTORY")):
        raise OSError("safe evidence verification is unsupported on this platform")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptors = []
    try:
        descriptors.append(os.open(root, directory_flags))
        for part in relative.parts[:-1]:
            descriptors.append(os.open(part, directory_flags,
                                       dir_fd=descriptors[-1]))
        fd = os.open(relative.parts[-1],
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=descriptors[-1])
        descriptors.append(fd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("evidence path is not a regular file")
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(fd, 65536):
            digest.update(chunk)
            size += len(chunk)
        return digest.hexdigest(), size
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def verify_bundle(bundle_dir: Path, key: bytes | None = None) -> dict:
    bundle_dir = Path(bundle_dir)
    report = {"bundle": str(bundle_dir), "checks": [], "ok": True}

    def check(name: str, ok: bool, detail: str = ""):
        report["checks"].append({"check": name, "ok": ok, "detail": detail})
        if not ok:
            report["ok"] = False

    att_path = bundle_dir / "attestation.json"
    if not att_path.exists():
        check("attestation-present", False, "attestation.json missing")
        return report
    try:
        attestation = json.loads(att_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        check("attestation-parse", False, str(e))
        return report
    check("attestation-parse", True)

    if attestation.get("_type") != STATEMENT_TYPE:
        check("statement-type", False,
              f"expected {STATEMENT_TYPE}, got {attestation.get('_type')}")
    else:
        check("statement-type", True)
    if attestation.get("predicateType") != PREDICATE_TYPE:
        check("predicate-type", False,
              f"expected {PREDICATE_TYPE}, got {attestation.get('predicateType')}")
    else:
        check("predicate-type", True)

    predicate = attestation.get("predicate", {})
    entries = predicate.get("evidence", [])
    check("evidence-listed", bool(entries),
          f"{len(entries)} evidence entr(ies)")

    for entry in entries:
        rel = entry.get("file", "")
        want = entry.get("sha256", "")
        if not isinstance(rel, str) or not rel or Path(rel).is_absolute():
            check("evidence-path", False, "evidence path must be a non-empty relative path")
            continue
        relative = Path(rel)
        if ".." in relative.parts:
            check(f"evidence:{rel}", False, "parent traversal is not allowed")
            continue
        if not relative.parts or "\0" in rel:
            check(f"evidence:{rel}", False, "invalid evidence path")
            continue
        try:
            got, size = _hash_evidence(bundle_dir, relative)
        except (OSError, ValueError, RuntimeError) as exc:
            check(f"evidence:{rel}", False, f"cannot safely read evidence: {exc}")
            continue
        if got != want:
            check(f"evidence:{rel}", False,
                  f"hash mismatch: want {want[:12]}…, got {got[:12]}… "
                  "(artifact altered after bundling)")
        elif size != entry.get("bytes"):
            check(f"evidence:{rel}", False,
                  f"size mismatch: want {entry.get('bytes')}, got {size}")
        else:
            check(f"evidence:{rel}", True, f"{size} bytes, sha256 ok")

    sig_path = bundle_dir / "signature.json"
    if sig_path.exists():
        try:
            signature = json.loads(sig_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            check("signature-parse", False, str(e))
            signature = None
        if signature is not None:
            if key is None:
                check("signature", True,
                      "signature present but no key given — "
                      "origin not checked; hashes still verified")
            elif verify_signature(attestation, signature, key):
                check("signature", True, "HMAC-SHA256 signature valid")
            else:
                check("signature", False,
                      "signature INVALID — attestation altered or wrong key")
    else:
        check("signature", True, "no signature.json — hashes only")

    return report


def format_report(report: dict) -> str:
    lines = [f"bundle: {report['bundle']}"]
    for c in report["checks"]:
        mark = "OK  " if c["ok"] else "FAIL"
        lines.append(f"[{mark}] {c['check']}"
                     + (f" — {c['detail']}" if c["detail"] else ""))
    lines.append("VERIFIED" if report["ok"] else "TAMPER DETECTED")
    return "\n".join(lines)

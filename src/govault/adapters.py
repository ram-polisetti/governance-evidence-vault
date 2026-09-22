"""Adapters: read the REAL formats of the sibling governance tools.

Nothing is reimplemented. Each adapter parses an artifact produced by the
sibling's own code and returns a normalized summary plus the verbatim
bytes for inclusion in the bundle. Source SHAs are recorded per artifact.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from . import SIBLING_SHAS


class AdapterError(Exception):
    pass


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise AdapterError(f"{path}: cannot parse JSON: {e}")


# ---------------------------------------------------------------- pack

def read_conformance_pack(pack_dir: Path) -> dict:
    """Parse a real conformance-pack directory (pack.json + evidence/)."""
    pack_dir = Path(pack_dir)
    manifest_path = pack_dir / "pack.json"
    if not manifest_path.exists():
        raise AdapterError(f"{pack_dir}: no pack.json (not a conformance pack)")
    manifest = _read_json(manifest_path)
    evidence_files = []
    for entry in manifest.get("evidence", []):
        rel = entry.get("file", "")
        src = pack_dir / rel
        if not src.exists():
            raise AdapterError(f"{pack_dir}: pack manifest lists {rel} but it is missing")
        evidence_files.append((entry.get("slot", "unknown"), src))
    summary = {
        "kind": "conformance-pack",
        "source": "conformance-pack",
        "source_sha": SIBLING_SHAS["conformance-pack"],
        "pack_id": manifest.get("pack_id"),
        "system": manifest.get("system", {}),
        "recommendation": manifest.get("recommendation"),
        "reasons": manifest.get("reasons", []),
        "fairness_gate": manifest.get("fairness_gate"),
        "ai_act_tier": manifest.get("ai_act_tier"),
        "n_evidence": len(evidence_files),
        "files": evidence_files,  # list of (slot, Path)
        "manifest_path": manifest_path,
    }
    return summary


# ------------------------------------------------------------- registry

_REGISTRY_TABLES = ("models", "model_cards", "risk_assessments",
                    "approvals", "evidence")


def read_registry_db(db_path: Path, system_name: str) -> dict:
    """Export registry rows for one system from a real mgreg sqlite DB."""
    db_path = Path(db_path)
    if not db_path.exists():
        raise AdapterError(f"{db_path}: registry DB not found")
    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    try:
        tables = {r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        missing = [t for t in _REGISTRY_TABLES if t not in tables]
        if missing:
            raise AdapterError(f"{db_path}: not an mgreg DB, missing {missing}")
        row = con.execute(
            "SELECT * FROM models WHERE name = ?", (system_name,)).fetchone()
        if row is None:
            names = [r[0] for r in con.execute("SELECT name FROM models")]
            raise AdapterError(
                f"{db_path}: no model named {system_name!r} (have: {names})")
        model = dict(row)
        model_id = model["id"]

        def rows(table, order="created_at"):
            return [dict(r) for r in con.execute(
                f"SELECT * FROM {table} WHERE model_id = ? ORDER BY {order}",
                (model_id,))]

        cards = rows("model_cards")
        risks = rows("risk_assessments")
        approvals = rows("approvals")
        evidence = rows("evidence")
    finally:
        con.close()
    latest_card = cards[-1]["content"] if cards else None
    latest_risk = risks[-1]["content"] if risks else None
    return {
        "kind": "registry",
        "source": "model-governance-registry",
        "source_sha": SIBLING_SHAS["model-governance-registry"],
        "model": {k: model[k] for k in ("id", "name", "slug", "owner", "status")},
        "card_versions": len(cards),
        "risk_versions": len(risks),
        "latest_card": latest_card,      # JSON text or None
        "latest_risk": latest_risk,      # JSON text or None
        "overall_risk": risks[-1]["overall_risk"] if risks else None,
        "approvals": approvals,          # list of dicts
        "evidence_rows": evidence,
        "db_path": db_path,
    }


# ------------------------------------------------------------- incidents

def read_incident_store(store_dir: Path, system: str) -> dict:
    """Read closed incidents for a system from a real incidentrun store."""
    store_dir = Path(store_dir)
    log_path = store_dir / "incidents.jsonl"
    if not log_path.exists():
        raise AdapterError(f"{store_dir}: no incidents.jsonl")
    incidents_dir = store_dir / "incidents"
    records = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            raise AdapterError(f"{log_path}: corrupt JSONL line")
    # incident dirs carry incident.json; match by affected system when known
    matched = []
    if incidents_dir.exists():
        for inc_json in incidents_dir.glob("*/incident.json"):
            try:
                inc = json.loads(inc_json.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            sysname = (inc.get("system") or inc.get("affected_system") or "")
            if system and sysname and sysname != system:
                continue
            events = [r for r in records
                      if r.get("incident_id") == inc.get("id")]
            matched.append({
                "incident": inc,
                "events": events,
                "dir": inc_json.parent,
            })
    return {
        "kind": "incidents",
        "source": "ai-incident-runbook",
        "source_sha": SIBLING_SHAS["ai-incident-runbook"],
        "n_log_records": len(records),
        "incidents": matched,
        "store_dir": store_dir,
    }


# ------------------------------------------------------------- alerts

def read_alert_file(path: Path, source: str) -> dict:
    """Parse one alert JSON from disparity-monitor or rag-eval-drift outbox."""
    path = Path(path)
    data = _read_json(path)
    if source == "disparity-monitor":
        sha = SIBLING_SHAS["disparity-monitor"]
        summary = {
            "model": data.get("model"), "status": data.get("status"),
            "run_id": data.get("run_id"), "owner": data.get("owner"),
            "metrics": data.get("metrics", []),
        }
    elif source == "rag-eval-drift":
        sha = SIBLING_SHAS["rag-eval-drift"]
        summary = {
            "metric": data.get("metric"), "rule": data.get("rule"),
            "run_id": data.get("run_id"),
            "detail": {k: v for k, v in data.items()
                       if k not in ("metric", "rule", "run_id")},
        }
    else:
        raise AdapterError(f"unknown alert source {source!r}")
    return {
        "kind": "alert", "alert_source": source,
        "source": source, "source_sha": sha,
        "summary": summary, "path": path,
    }


# ------------------------------------------------------------- evals

def read_eval_report(path: Path, source: str) -> dict:
    """Parse an eval/redteam/audit report JSON from a sibling harness."""
    path = Path(path)
    data = _read_json(path)
    known = {
        "rag-redteam": SIBLING_SHAS["rag-redteam"],
        "rag-governance-demo": SIBLING_SHAS["rag-governance-demo"],
        "opsaudit": SIBLING_SHAS["opsaudit"],
        "rag-eval-drift": SIBLING_SHAS["rag-eval-drift"],
        "eval-judge-calibration": None,  # not a declared input; kept for errors
    }
    if source not in known or known[source] is None:
        raise AdapterError(f"unknown eval source {source!r}")
    summary = {}
    for key in ("pass_rate", "attack_pass_rate", "overall", "summary",
                "n_cases", "n_records", "verdict", "status"):
        if key in data:
            summary[key] = data[key]
    if not summary:
        summary = {"keys": sorted(data.keys())[:10]}
    return {
        "kind": "eval-report", "eval_source": source,
        "source": source, "source_sha": known[source],
        "summary": summary, "path": path,
    }


def read_audit_jsonl(path: Path, source: str) -> dict:
    """Count + spot-check a hash-chained audit JSONL from a sibling."""
    path = Path(path)
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines()
             if ln.strip()]
    for ln in lines[:3]:
        json.loads(ln)  # raises on corruption
    sha = {
        "rag-redteam": SIBLING_SHAS["rag-redteam"],
        "rag-governance-demo": SIBLING_SHAS["rag-governance-demo"],
        "rag-eval-drift": SIBLING_SHAS["rag-eval-drift"],
        "ai-incident-runbook": SIBLING_SHAS["ai-incident-runbook"],
    }.get(source)
    if sha is None:
        raise AdapterError(f"unknown audit source {source!r}")
    return {
        "kind": "audit-log", "audit_source": source,
        "source": source, "source_sha": sha,
        "summary": {"n_records": len(lines)},
        "path": path,
    }

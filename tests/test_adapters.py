"""Adapter tests against REAL sibling formats.

The registry test uses the sibling's actual mgreg.store.Registry class;
the alert tests use real fixture files shipped with ai-incident-runbook.
"""
import json
import sys
from pathlib import Path

import pytest

SIB = Path(__file__).resolve().parent.parent.parent
MGREG_SRC = SIB / "model-governance-registry" / "src"
if str(MGREG_SRC) not in sys.path:
    sys.path.insert(0, str(MGREG_SRC))


def _require_mgreg():
    if not (MGREG_SRC / "mgreg" / "store.py").exists():
        pytest.skip("sibling checkout model-governance-registry not present "
                    "next to this repo (see README)")

from govault.adapters import (AdapterError, read_alert_file, read_audit_jsonl,
                              read_conformance_pack, read_eval_report,
                              read_incident_store, read_registry_db)  # noqa: E402


def make_pack(tmp_path: Path) -> Path:
    pack = tmp_path / "pack"
    ev = pack / "evidence" / "fairness"
    ev.mkdir(parents=True)
    (ev / "audit.json").write_text(json.dumps({"gate": "pass"}))
    manifest = {
        "pack_id": "pack-1",
        "system": {"name": "demo-sys", "version": "1.0", "purpose": "demo"},
        "evidence": [{"slot": "fairness", "file": "evidence/fairness/audit.json",
                      "sha256": "x", "bytes": 1}],
        "recommendation": "go", "reasons": [],
        "fairness_gate": "pass", "ai_act_tier": "minimal-risk",
    }
    (pack / "pack.json").write_text(json.dumps(manifest))
    return pack


def test_read_conformance_pack(tmp_path):
    pack = make_pack(tmp_path)
    got = read_conformance_pack(pack)
    assert got["recommendation"] == "go"
    assert got["source_sha"] == "eb3fcce"
    assert len(got["files"]) == 1


def test_read_conformance_pack_missing(tmp_path):
    with pytest.raises(AdapterError):
        read_conformance_pack(tmp_path / "nope")


def test_read_conformance_pack_missing_evidence(tmp_path):
    pack = make_pack(tmp_path)
    (pack / "evidence" / "fairness" / "audit.json").unlink()
    with pytest.raises(AdapterError):
        read_conformance_pack(pack)


CARD = {"purpose": "p", "intended_use": "u", "training_data": "t",
        "evaluation": "e", "limitations": "l"}
RISK = {"govern": "g", "map": "m", "measure": "m2", "manage": "mg"}


def test_read_registry_db(tmp_path):
    _require_mgreg()
    from mgreg.store import Registry
    db = tmp_path / "reg.sqlite"
    reg = Registry(str(db))
    reg.register("demo-sys", "owner", actor="tester")
    reg.set_status("demo-sys", "under_review", actor="tester")
    reg.add_card("demo-sys", CARD, created_by="tester", actor="tester")
    reg.add_risk("demo-sys", RISK, overall_risk="low", created_by="tester", actor="tester")
    reg.record_approval("demo-sys", "approver", "approved",
                        "evidence reviewed", evidence_ids=[], actor="approver")
    got = read_registry_db(db, "demo-sys")
    assert got["source_sha"] == "a8a8a23"
    assert len(got["approvals"]) == 1
    assert got["approvals"][0]["decision"] == "approved"
    assert got["overall_risk"] == "low"
    assert json.loads(got["latest_card"])["purpose"] == "p"


def test_read_registry_db_unknown_system(tmp_path):
    _require_mgreg()
    from mgreg.store import Registry
    db = tmp_path / "reg.sqlite"
    Registry(str(db))
    with pytest.raises(AdapterError):
        read_registry_db(db, "ghost")


def test_read_registry_db_not_a_db(tmp_path):
    db = tmp_path / "empty.sqlite"
    import sqlite3
    sqlite3.connect(db).close()
    with pytest.raises(AdapterError):
        read_registry_db(db, "demo-sys")


def test_read_disparity_alert():
    p = SIB / "ai-incident-runbook" / "examples" / "fixtures" / "disparity-red.json"
    got = read_alert_file(p, "disparity-monitor")
    assert got["summary"]["status"] == "red"
    assert got["source_sha"] == "e5426ff"


def test_read_drift_alert():
    p = SIB / "ai-incident-runbook" / "examples" / "fixtures" / "drift-threshold.json"
    got = read_alert_file(p, "rag-eval-drift")
    assert got["summary"]["rule"] == "threshold"
    assert got["source_sha"] == "836bc85"


def test_read_alert_bad_source(tmp_path):
    p = tmp_path / "a.json"
    p.write_text("{}")
    with pytest.raises(AdapterError):
        read_alert_file(p, "nope")


def test_read_eval_report(tmp_path):
    p = tmp_path / "eval.json"
    p.write_text(json.dumps({"pass_rate": 0.97, "n_cases": 37}))
    got = read_eval_report(p, "rag-governance-demo")
    assert got["summary"]["pass_rate"] == 0.97
    assert got["source_sha"] == "c339ae1"


def test_read_audit_jsonl(tmp_path):
    p = tmp_path / "audit.jsonl"
    p.write_text('{"seq": 0}\n{"seq": 1}\n')
    got = read_audit_jsonl(p, "rag-redteam")
    assert got["summary"]["n_records"] == 2


def test_read_incident_store(tmp_path):
    store = tmp_path / "store"
    (store / "incidents" / "INC-1").mkdir(parents=True)
    (store / "incidents.jsonl").write_text(
        '{"incident_id": "INC-1", "event": "opened"}\n')
    (store / "incidents" / "INC-1" / "incident.json").write_text(
        json.dumps({"id": "INC-1", "system": "demo-sys",
                    "severity": "sev2", "status": "closed"}))
    (store / "incidents" / "INC-1" / "postmortem.json").write_text("{}")
    got = read_incident_store(store, "demo-sys")
    assert len(got["incidents"]) == 1
    assert got["incidents"][0]["incident"]["severity"] == "sev2"


def test_read_incident_store_missing(tmp_path):
    with pytest.raises(AdapterError):
        read_incident_store(tmp_path / "missing", "demo-sys")

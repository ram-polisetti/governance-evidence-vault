"""End-to-end CLI lifecycle: build -> show -> verify -> tamper -> verify fails."""
import json
import sys
from pathlib import Path

SIB = Path(__file__).resolve().parent.parent.parent
MGREG_SRC = SIB / "model-governance-registry" / "src"
if str(MGREG_SRC) not in sys.path:
    sys.path.insert(0, str(MGREG_SRC))


def _require_mgreg():
    if not (MGREG_SRC / "mgreg" / "store.py").exists():
        pytest.skip("sibling checkout model-governance-registry not present "
                    "next to this repo (see README)")

from govault.cli import main  # noqa: E402


def _fixtures(tmp_path):
    # conformance pack
    pack = tmp_path / "pack"
    ev = pack / "evidence" / "fairness"
    ev.mkdir(parents=True)
    (ev / "audit.json").write_text(json.dumps({"gate": "pass"}))
    (pack / "pack.json").write_text(json.dumps({
        "pack_id": "pack-1",
        "system": {"name": "demo-sys", "version": "2.0", "purpose": "demo"},
        "evidence": [{"slot": "fairness", "file": "evidence/fairness/audit.json",
                      "sha256": "x", "bytes": 1}],
        "recommendation": "conditional", "reasons": ["high-risk tier"],
        "fairness_gate": "pass", "ai_act_tier": "high-risk"}))
    # registry
    _require_mgreg()
    from mgreg.store import Registry
    db = tmp_path / "reg.sqlite"
    reg = Registry(str(db))
    reg.register("demo-sys", "owner", actor="t")
    reg.set_status("demo-sys", "under_review", actor="t")
    reg.add_card("demo-sys",
                 {"purpose": "p", "intended_use": "u", "training_data": "t",
                  "evaluation": "e", "limitations": "l"},
                 created_by="t", actor="t")
    reg.add_risk("demo-sys",
                 {"govern": "g", "map": "m", "measure": "m2", "manage": "mg"},
                 overall_risk="medium", created_by="t", actor="t")
    reg.record_approval("demo-sys", "approver", "approved", "ok",
                        evidence_ids=[], actor="a")
    # incident store
    store = tmp_path / "incstore"
    (store / "incidents" / "INC-9").mkdir(parents=True)
    (store / "incidents.jsonl").write_text(
        '{"incident_id": "INC-9", "event": "closed"}\n')
    (store / "incidents" / "INC-9" / "incident.json").write_text(
        json.dumps({"id": "INC-9", "system": "demo-sys",
                    "severity": "sev3", "status": "closed"}))
    # alert + eval fixtures
    alert = tmp_path / "alert.json"
    alert.write_text(json.dumps(
        {"model": "demo-sys", "status": "AMBER", "run_id": "r1",
         "owner": "o", "metrics": []}))
    evrep = tmp_path / "eval.json"
    evrep.write_text(json.dumps({"pass_rate": 0.95}))
    key = tmp_path / "key.bin"
    key.write_bytes(b"secret-key-0123456789")
    return pack, db, store, alert, evrep, key


def test_full_lifecycle(tmp_path):
    pack, db, store, alert, evrep, key = _fixtures(tmp_path)
    out = tmp_path / "bundle"
    vstore = tmp_path / "vstore"
    rc = main(["--store", str(vstore), "build",
               "--system", "demo-sys", "--pack", str(pack),
               "--registry", str(db), "--incident-store", str(store),
               "--alert", f"disparity-monitor:{alert}",
               "--eval", f"rag-governance-demo:{evrep}",
               "--out", str(out), "--key", str(key)])
    assert rc == 0
    assert (out / "attestation.json").exists()
    assert (out / "signature.json").exists()

    assert main(["--store", str(vstore), "show", "--bundle", str(out)]) == 0
    assert main(["--store", str(vstore), "verify",
                 "--bundle", str(out), "--key", str(key)]) == 0
    # vault log records build + verify, chain intact
    assert main(["--store", str(vstore), "log", "--verify"]) == 0

    # tamper with an artifact -> verify fails
    (out / "evidence" / "registry" / "model-card.json").write_text("{}")
    assert main(["--store", str(vstore), "verify",
                 "--bundle", str(out), "--key", str(key)]) == 1


def test_build_missing_pack(tmp_path):
    rc = main(["--store", str(tmp_path / "vs"), "build",
               "--system", "x", "--pack", str(tmp_path / "nope"),
               "--out", str(tmp_path / "b")])
    assert rc == 2


def test_build_refuses_nonempty_out(tmp_path):
    out = tmp_path / "b"
    out.mkdir()
    (out / "junk").write_text("x")
    rc = main(["--store", str(tmp_path / "vs"), "build",
               "--system", "x", "--pack", str(tmp_path),
               "--out", str(out)])
    assert rc == 2

"""End-to-end demo: a governance evidence vault bundle for a real system.

Pipeline (all artifacts produced by the siblings' REAL code):
1. conformance-pack --collect  -> real opsaudit + act-checker runs (CONDITIONAL)
2. mgreg Registry               -> real registry DB: card + risk + approval
3. incidentrun CLI               -> real incident store: open/triage/close
4. vault build --key            -> signed bundle with SLSA-style attestation
5. auditor mode                 -> copy the bundle to a fresh directory and
                                   verify it there as an external auditor would
                                   (hashes + signature + tamper demo)

Usage: python3 examples/demo.py
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # govvault repo root
SIB = ROOT.parent                                       # ~/workspace/p18
VAULT_SRC = ROOT / "src"
DEMO = Path("/tmp/govault-demo")
SYSTEM = "demohire-cv-ranker"


def banner(msg: str):
    print("\n" + "=" * 70)
    print(msg)
    print("=" * 70)


def sh(args, env_extra=None, cwd=None):
    env = dict(os.environ)
    env.update(env_extra or {})
    r = subprocess.run(args, capture_output=True, text=True,
                       env=env, cwd=cwd or SIB)
    if r.returncode != 0:
        print(r.stdout[-3000:])
        print(r.stderr[-3000:], file=sys.stderr)
        raise SystemExit(f"command failed: {' '.join(args)}")
    return r


def main() -> int:
    if DEMO.exists():
        shutil.rmtree(DEMO)
    DEMO.mkdir(parents=True)
    vault_pp = {"PYTHONPATH": str(VAULT_SRC)}

    # ------------------------------------------------- 1. conformance pack
    banner("1. Real conformance pack (opsaudit + act-checker, --collect)")
    descriptor = {
        "name": SYSTEM, "version": "1.0",
        "purpose": "Rank CVs for hiring shortlists",
        "intended_use": "Decision support only; a human makes the final call.",
        "deployment_context": "Internal HR screening pilot.",
        "use_case_tags": ["employment", "cv-screening"],
        "interacts_with_persons": True, "provider_role": "provider",
        "demo_fairness_bias": 0.0,
    }
    desc_path = DEMO / "descriptor.json"
    desc_path.write_text(json.dumps(descriptor, indent=2))
    card_path = DEMO / "card.json"
    card_path.write_text(json.dumps({
        "purpose": "Rank CVs for hiring shortlists.",
        "intended_use": "Decision support only; a human makes the final call.",
        "training_data": "Historical hiring decisions, 2019-2024.",
        "evaluation": "opsaudit fairness audit on holdout; conformance pack.",
        "limitations": "Not validated outside the documented HR pilot context."},
        indent=2))
    risk_path = DEMO / "risk.json"
    risk_path.write_text(json.dumps({
        "govern": "HR governance board owns the deployment decision.",
        "map": "Employment context; CV-screening use case; high-risk per AI Act.",
        "measure": "Disparate impact ratio 0.97 on holdout; drift monitored weekly.",
        "manage": "Human-in-the-loop; rollback plan documented.",
        "overall_risk": "medium"}, indent=2))
    pack_dir = DEMO / "pack"
    sh([sys.executable, "-m", "conformpack", "build",
        "--descriptor", str(desc_path), "--collect",
        "--card", str(card_path), "--assessment", str(risk_path),
        "--out", str(pack_dir)],
       env_extra={"PYTHONPATH": str(SIB / "conformance-pack" / "src"),
                  "CONFORM_AICHECKER_DIR": str(SIB / "ai-act-checker"),
                  "CONFORM_OPSAUDIT_DIR": str(SIB / "opsaudit")})
    sh([sys.executable, "-m", "conformpack", "verify",
        "--pack", str(pack_dir)],
       env_extra={"PYTHONPATH": str(SIB / "conformance-pack" / "src")})

    # ------------------------------------------------- 2. registry
    banner("2. Real registry DB (card + risk + approval)")
    reg_pp = {"PYTHONPATH": str(SIB / "model-governance-registry" / "src")}
    db = DEMO / "registry.sqlite"
    sh([sys.executable, "-c", f"""
from mgreg.store import Registry
reg = Registry({str(db)!r})
reg.register({SYSTEM!r}, "hr-platform-team", actor="demo")
reg.set_status({SYSTEM!r}, "under_review", actor="demo")
reg.add_card({SYSTEM!r}, {json.dumps({
    "purpose": "Rank CVs for hiring shortlists.",
    "intended_use": "Decision support only; a human makes the final call.",
    "training_data": "Historical hiring decisions, 2019-2024.",
    "evaluation": "opsaudit fairness audit on holdout; conformance pack CONDITIONAL.",
    "limitations": "Not validated outside the documented HR pilot context."})},
    created_by="demo", actor="demo")
reg.add_risk({SYSTEM!r}, {json.dumps({
    "govern": "HR governance board owns the deployment decision.",
    "map": "Employment context; CV-screening use case; high-risk per AI Act.",
    "measure": "Disparate impact ratio 0.97 on holdout; drift monitored weekly.",
    "manage": "Human-in-the-loop; rollback plan documented."})},
    overall_risk="medium", created_by="demo", actor="demo")
reg.record_approval({SYSTEM!r}, "governance-board", "approved",
    "Evidence reviewed: conformance pack CONDITIONAL (high-risk tier), "
    "fairness gate pass, human-in-the-loop confirmed.",
    evidence_ids=[], actor="governance-board")
print("registry seeded")
"""], env_extra=reg_pp)

    # ------------------------------------------------- 3. incident store
    banner("3. Real incident store (open -> triage -> close)")
    inc_pp = {"PYTHONPATH": str(SIB / "ai-incident-runbook" / "src")}
    istore = DEMO / "incidents"
    istore.mkdir()
    alert = (SIB / "ai-incident-runbook" / "examples" / "fixtures"
             / "drift-threshold.json")
    r = sh([sys.executable, "-m", "incidentrun", "--store", str(istore),
            "open", "--alert", str(alert), "--system", SYSTEM],
           env_extra=inc_pp)
    inc_id = r.stdout.strip().split()[1]
    sh([sys.executable, "-m", "incidentrun", "--store", str(istore),
        "triage", "--incident", inc_id], env_extra=inc_pp)
    pm = DEMO / "postmortem.json"
    pm.write_text(json.dumps({
        "timeline": ["drift alert fired on groundedness metric",
                     "corpus diff showed two policy docs removed",
                     "docs restored, evals re-run green"],
        "root_cause": "bad corpus update removed two policy documents",
        "fixes": ["restore removed documents", "add corpus checksum gate"],
        "follow_ups": ["weekly drift review with corpus owner"]}, indent=2))
    sh([sys.executable, "-m", "incidentrun", "--store", str(istore),
        "close", "--incident", inc_id, "--postmortem", str(pm)],
       env_extra=inc_pp)

    # ------------------------------------------------- 4. vault build
    banner("4. vault build (signed bundle)")
    key = DEMO / "vault.key"
    key.write_bytes(os.urandom(32))
    bundle = DEMO / "bundle"
    vstore = DEMO / "vstore"
    drift_alert = (SIB / "ai-incident-runbook" / "examples" / "fixtures"
                   / "disparity-red.json")
    sh([sys.executable, "-m", "govault", "--store", str(vstore), "build",
        "--system", SYSTEM, "--system-version", "1.0",
        "--pack", str(pack_dir),
        "--registry", str(db),
        "--incident-store", str(istore),
        "--alert", f"disparity-monitor:{drift_alert}",
        "--out", str(bundle), "--key", str(key)], env_extra=vault_pp)
    sh([sys.executable, "-m", "govault", "--store", str(vstore),
        "show", "--bundle", str(bundle)], env_extra=vault_pp)

    # ------------------------------------------------- 5. auditor mode
    banner("5. External auditor: verify from a fresh directory")
    auditor = DEMO / "auditor-copy"
    shutil.copytree(bundle, auditor)
    r = sh([sys.executable, "-m", "govault",
            "--store", str(DEMO / "auditor-store"),
            "verify", "--bundle", str(auditor), "--key", str(key)],
           env_extra=vault_pp)
    print(r.stdout)
    assert "VERIFIED" in r.stdout

    banner("6. Tamper demo: alter one artifact, verify must fail")
    victim = next((auditor / "evidence").rglob("model-card.json"))
    victim.write_text(victim.read_text() + " ")
    r = subprocess.run(
        [sys.executable, "-m", "govault", "verify",
         "--bundle", str(auditor), "--key", str(key)],
        capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": str(VAULT_SRC)})
    print(r.stdout)
    assert r.returncode == 1 and "TAMPER DETECTED" in r.stdout

    sh([sys.executable, "-m", "govault",
        "--store", str(vstore), "log", "--verify"], env_extra=vault_pp)
    banner(f"DEMO PASSED — bundle at {bundle}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

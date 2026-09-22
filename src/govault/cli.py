"""CLI: vault build / verify / show / log."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .adapters import (AdapterError, read_alert_file, read_audit_jsonl,
                       read_conformance_pack, read_eval_report,
                       read_incident_store, read_registry_db)
from .bundle import (add_file_evidence, add_text_evidence, build_attestation,
                     write_attestation)
from .hashchain import sha256_file, utcnow
from .signing import load_key, sign_attestation
from .store import VaultStore
from .verify import format_report, verify_bundle


def _kv_pair(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise argparse.ArgumentTypeError(
            f"{value!r}: expected SRC:PATH (e.g. disparity-monitor:alert.json)")
    src, path = value.split(":", 1)
    return src.strip(), path.strip()


def build_cmd(args) -> int:
    from . import SIBLING_SHAS
    store = VaultStore(args.store or default_store())
    bundle = Path(args.out)
    if bundle.exists() and any(bundle.iterdir()):
        print(f"error: {bundle} exists and is not empty", file=sys.stderr)
        return 2
    entries: list = []
    annotations: dict = {"inputs": []}
    system = {"name": args.system, "version": args.system_version or ""}

    def note(kind: str, detail: str):
        annotations["inputs"].append({"kind": kind, "detail": detail})

    try:
        # 1. conformance pack (the core evidence assembly)
        pack = read_conformance_pack(Path(args.pack))
        system = {**pack["system"], "name": args.system or pack["system"].get("name")}
        pack_slot = "conformance-pack"
        for slot, src in pack["files"]:
            e = add_file_evidence(bundle, f"{pack_slot}/{slot}", src, entries)
            e["kind"] = "pack-evidence"; e["source"] = pack["source"]
            e["source_sha"] = pack["source_sha"]
        e = add_file_evidence(bundle, pack_slot, pack["manifest_path"], entries)
        e["kind"] = "pack-manifest"; e["source"] = pack["source"]
        e["source_sha"] = pack["source_sha"]
        annotations["recommendation"] = pack["recommendation"]
        annotations["recommendation_reasons"] = pack["reasons"]
        annotations["fairness_gate"] = pack["fairness_gate"]
        annotations["ai_act_tier"] = pack["ai_act_tier"]
        note("conformance-pack",
             f"pack {pack['pack_id']}: {pack['recommendation']} "
             f"({pack['n_evidence']} evidence files)")

        # 2. registry: approvals + card + risk
        if args.registry:
            reg = read_registry_db(Path(args.registry), system["name"])
            if reg["latest_card"]:
                e = add_text_evidence(bundle, "registry", "model-card.json",
                                      reg["latest_card"], entries)
                e["kind"] = "model-card"; e["source"] = reg["source"]
                e["source_sha"] = reg["source_sha"]
            if reg["latest_risk"]:
                e = add_text_evidence(bundle, "registry", "risk-assessment.json",
                                      reg["latest_risk"], entries)
                e["kind"] = "risk-assessment"; e["source"] = reg["source"]
                e["source_sha"] = reg["source_sha"]
            approvals = []
            for a in reg["approvals"]:
                approvals.append({
                    "approver": a.get("approver"),
                    "decision": a.get("decision"),
                    "rationale": a.get("rationale"),
                    "version": a.get("version"),
                    "at": a.get("created_at"),
                })
            annotations["approvals"] = approvals
            annotations["overall_risk"] = reg["overall_risk"]
            note("registry",
                 f"{len(approvals)} approval(s), card v{reg['card_versions']}, "
                 f"risk v{reg['risk_versions']}")

        # 3. incidents
        if args.incident_store:
            inc = read_incident_store(Path(args.incident_store), system["name"])
            closed = []
            for m in inc["incidents"]:
                i = m["incident"]
                e = add_file_evidence(
                    bundle, "incidents", m["dir"] / "incident.json", entries)
                e["kind"] = "incident-record"; e["source"] = inc["source"]
                e["source_sha"] = inc["source_sha"]
                pm = m["dir"] / "postmortem.json"
                if pm.exists():
                    e2 = add_file_evidence(bundle, "incidents", pm, entries)
                    e2["kind"] = "postmortem"; e2["source"] = inc["source"]
                    e2["source_sha"] = inc["source_sha"]
                closed.append({
                    "id": i.get("id"), "severity": i.get("severity"),
                    "status": i.get("status"),
                    "n_events": len(m["events"]),
                })
            annotations["incidents"] = closed
            note("incidents", f"{len(closed)} incident(s) in bundle")

        # 4. alerts / eval reports / audit logs / extras
        for src, path in args.alert or []:
            a = read_alert_file(Path(path), src)
            e = add_file_evidence(bundle, f"alerts/{src}",
                                  a["path"], entries)
            e["kind"] = "alert"; e["source"] = a["source"]
            e["source_sha"] = a["source_sha"]
            note("alert", f"{src}: {json.dumps(a['summary'])[:120]}")
        for src, path in args.eval or []:
            r = read_eval_report(Path(path), src)
            e = add_file_evidence(bundle, f"evals/{src}", r["path"], entries)
            e["kind"] = "eval-report"; e["source"] = r["source"]
            e["source_sha"] = r["source_sha"]
            note("eval-report", f"{src}: {json.dumps(r['summary'])[:120]}")
        for src, path in args.audit or []:
            r = read_audit_jsonl(Path(path), src)
            e = add_file_evidence(bundle, f"audit-logs/{src}", r["path"],
                                  entries)
            e["kind"] = "audit-log"; e["source"] = r["source"]
            e["source_sha"] = r["source_sha"]
            note("audit-log", f"{src}: {r['summary']['n_records']} records")
        for kind, path in args.extra or []:
            p = Path(path)
            if not p.exists():
                raise AdapterError(f"extra {kind}: {p} not found")
            e = add_file_evidence(bundle, f"extra/{kind}", p, entries)
            e["kind"] = kind; e["source"] = "operator-supplied"
            e["source_sha"] = None
            note("extra", f"{kind}: {p.name}")
    except AdapterError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    bundle_id = f"vault-{utcnow().replace(':', '').replace('+', 'Z')}"
    attestation = build_attestation(bundle_id, system, entries, annotations)
    att_path = write_attestation(bundle, attestation)
    att_digest, _ = sha256_file(att_path)

    signed = None
    if args.key:
        try:
            key = load_key(Path(args.key))
        except (OSError, ValueError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        signed = sign_attestation(attestation, key)
        (bundle / "signature.json").write_text(
            json.dumps(signed, indent=2) + "\n", encoding="utf-8")

    store.append("bundle-built", {
        "bundle_id": bundle_id,
        "system": system["name"],
        "attestation_sha256": att_digest,
        "n_evidence": len(entries),
        "signed": signed is not None,
        "bundle_dir": str(bundle),
    })
    print(f"bundle {bundle_id} written to {bundle}")
    print(f"  evidence files: {len(entries)}")
    print(f"  attestation:    {att_digest[:16]}…")
    print(f"  signed:         {'yes (HMAC-SHA256)' if signed else 'no — pass --key to sign'}")
    return 0


def verify_cmd(args) -> int:
    store = VaultStore(args.store or default_store())
    key = load_key(Path(args.key)) if args.key else None
    try:
        report = verify_bundle(Path(args.bundle), key)
    except Exception as e:  # noqa: BLE001 — report, don't crash
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(format_report(report))
    store.append("bundle-verified", {
        "bundle": str(args.bundle),
        "ok": report["ok"],
        "n_checks": len(report["checks"]),
    })
    return 0 if report["ok"] else 1


def show_cmd(args) -> int:
    att_path = Path(args.bundle) / "attestation.json"
    try:
        att = json.loads(att_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    p = att["predicate"]
    print(f"system:        {p['system'].get('name')} "
          f"v{p['system'].get('version')}")
    print(f"bundle_id:     {p['bundle_id']}")
    print(f"built_utc:     {p['built_utc']}")
    print(f"recommendation:{p['annotations'].get('recommendation')}")
    print(f"approvals:     {len(p['annotations'].get('approvals', []))}")
    print(f"incidents:     {len(p['annotations'].get('incidents', []))}")
    print("evidence:")
    for e in p["evidence"]:
        print(f"  [{e.get('kind', '?')}] {e['file']} "
              f"({e['bytes']} bytes, {e['sha256'][:12]}…)")
    return 0


def log_cmd(args) -> int:
    store = VaultStore(args.store or default_store())
    if args.verify:
        ok, msg = store.verify()
        print(f"vault log: {msg}")
        return 0 if ok else 1
    if store.log_path.exists():
        for line in store.log_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                print(f"{r['at']} {r['event']} "
                      f"{r.get('bundle_id', r.get('bundle', ''))}")
    else:
        print("vault log is empty")
    return 0


def default_store() -> str:
    return str(Path.home() / ".local" / "share" / "govault")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vault",
                                 description="Governance evidence vault")
    ap.add_argument("--version", action="version",
                    version=f"%(prog)s {__version__}")
    ap.add_argument("--store", help="vault audit-log directory "
                    f"(default {default_store()})")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="assemble a governance bundle")
    b.add_argument("--system", required=True,
                   help="system name (must match registry + pack)")
    b.add_argument("--system-version", default="")
    b.add_argument("--pack", required=True,
                   help="conformance-pack directory")
    b.add_argument("--registry", help="mgreg registry sqlite DB")
    b.add_argument("--incident-store", help="incidentrun store directory")
    b.add_argument("--alert", action="append", type=_kv_pair, default=[],
                   metavar="SRC:PATH",
                   help="alert JSON (disparity-monitor|rag-eval-drift)")
    b.add_argument("--eval", action="append", type=_kv_pair, default=[],
                   metavar="SRC:PATH",
                   help="eval report JSON (rag-redteam|rag-governance-demo|"
                   "opsaudit|rag-eval-drift)")
    b.add_argument("--audit", action="append", type=_kv_pair, default=[],
                   metavar="SRC:PATH",
                   help="sibling audit JSONL (rag-redteam|rag-governance-demo|"
                   "rag-eval-drift|ai-incident-runbook)")
    b.add_argument("--extra", action="append", type=_kv_pair, default=[],
                   metavar="KIND:PATH", help="any extra file with a kind label")
    b.add_argument("--out", required=True, help="bundle output directory")
    b.add_argument("--key", help="HMAC key file for signing the attestation")
    b.set_defaults(func=build_cmd)

    v = sub.add_parser("verify",
                       help="verify a bundle offline (auditor mode)")
    v.add_argument("--bundle", required=True)
    v.add_argument("--key", help="HMAC key file to check the signature")
    v.set_defaults(func=verify_cmd)

    s = sub.add_parser("show", help="summarize a bundle's attestation")
    s.add_argument("--bundle", required=True)
    s.set_defaults(func=show_cmd)

    lg = sub.add_parser("log", help="inspect the vault audit log")
    lg.add_argument("--verify", action="store_true",
                    help="verify the log's hash chain")
    lg.set_defaults(func=log_cmd)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

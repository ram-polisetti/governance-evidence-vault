# Bundle format

## Directory layout

```
<bundle>/
  attestation.json
  signature.json            # present only when built with --key
  evidence/
    conformance-pack/<slot>/<file>...
    conformance-pack/pack.json
    registry/model-card.json
    registry/risk-assessment.json
    incidents/incident.json ...
    incidents/postmortem.json ...
    alerts/<source>/<file>...
    evals/<source>/<file>...
    audit-logs/<source>/<file>...
    extra/<kind>/<file>...
```

## attestation.json

An [in-toto statement](https://in-toto.io/)-shaped JSON document:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {"name": "<system name>",
     "digest": {"sha256": "<sha256 of {name, version}>"}}
  ],
  "predicateType": "https://ram-polisetti.dev/governance-evidence-bundle/v1",
  "predicate": {
    "system": {"name": "...", "version": "...", "purpose": "..."},
    "built_utc": "<ISO-8601>",
    "tool": "governance-evidence-vault",
    "tool_version": "0.1.0",
    "bundle_id": "vault-...",
    "sibling_shas": {"conformance-pack": "eb3fcce", ...},
    "evidence": [
      {"slot": "conformance-pack/opsaudit-report",
       "kind": "pack-evidence",
       "file": "evidence/conformance-pack/opsaudit-report/opsaudit-report.json",
       "sha256": "<64 hex>",
       "bytes": 3442,
       "source": "conformance-pack",
       "source_sha": "eb3fcce"}
    ],
    "annotations": {
      "recommendation": "conditional | go | no-go",
      "recommendation_reasons": ["..."],
      "fairness_gate": "pass | fail | review",
      "ai_act_tier": "minimal-risk | ...",
      "approvals": [{"approver": "...", "decision": "approved",
                     "rationale": "...", "version": 1, "at": "..."}],
      "overall_risk": "low | medium | high",
      "incidents": [{"id": "INC-...", "severity": "sev2",
                     "status": "closed", "n_events": 5}],
      "inputs": [{"kind": "...", "detail": "..."}]
    }
  }
}
```

## signature.json

```json
{"alg": "HMAC-SHA256",
 "attestation_sha256": "<sha256 of canonical attestation>",
 "signature": "<hmac hex>"}
```

The HMAC is computed over the canonical JSON of `attestation.json`
(sorted keys, no whitespace). Verification recomputes it with the
operator key passed via `--key`.

## Vault audit log

`vault.jsonl` in the vault store directory (`--store`, default
`~/.local/share/govault`): one hash-chained JSON record per
`bundle-built` / `bundle-verified` event, with `prev_hash` linking each
record to the last. `vault log --verify` recomputes the chain.

# Sources

Adapters parse the real output formats of these sibling repos. Every
bundle records these SHAs so an auditor knows exactly which code version
produced each artifact.

| Repo | Pinned SHA | Formats read |
|---|---|---|
| ram-polisetti/conformance-pack | `eb3fcce` | `pack.json` manifest + `evidence/` dir |
| ram-polisetti/model-governance-registry | `a8a8a23` | sqlite schema: models, model_cards, risk_assessments, approvals, evidence |
| ram-polisetti/ai-incident-runbook | `7c28259` | `incidents.jsonl`, `incidents/<id>/incident.json`, postmortems |
| ram-polisetti/rag-redteam | `169e4c8` | eval report JSON, hash-chained audit JSONL |
| ram-polisetti/rag-governance-demo | `c339ae1` | eval report JSON, `eval_audit.jsonl` |
| ram-polisetti/opsaudit | `e2f6220` | audit report JSON |
| ram-polisetti/disparity-monitor | `e5426ff` | outbox alert JSON |
| ram-polisetti/rag-eval-drift | `836bc85` | outbox alert JSON, `audit.jsonl` |
| ram-polisetti/ai-act-checker | `bab26de` | (via conformance-pack evidence) |

Nothing is reimplemented: adapters read, never duplicate, sibling logic.
If a sibling's format changes, the pinned SHA in the bundle tells the
auditor which version the adapter was written against.

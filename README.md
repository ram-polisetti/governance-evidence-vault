# Governance Evidence Vault

The registry knows what was approved. The vault proves **what it was approved on.**

A tool that assembles everything behind a deployed AI system — conformance
packs, model cards, risk assessments, approvals, incident records, monitor
alerts, eval reports — into a single tamper-evident **governance bundle**:
every artifact hashed, an SLSA-style attestation describing exactly what
evidence backs the deployment, the attestation signed (HMAC-SHA256), and a
hash-chained vault audit log recording every build and verification.

An external auditor can verify the bundle **offline, without access to our
infrastructure**: every file re-hashed against the attestation, the
signature checked with a shared key, any alteration detected.

## Install

Stdlib only — no dependencies.

```bash
pip install .
# or run from source:
PYTHONPATH=src python -m govault --help
```

## Usage

```bash
# Assemble a bundle for a system
vault build --system demohire-cv-ranker \
  --pack /path/to/conformance-pack \
  --registry /path/to/registry.sqlite \
  --incident-store /path/to/incident-store \
  --alert disparity-monitor:/path/to/alert.json \
  --eval rag-governance-demo:/path/to/eval-report.json \
  --audit rag-redteam:/path/to/redteam-audit.jsonl \
  --out ./bundle --key ./vault.key

# Verify as an external auditor (offline)
vault verify --bundle ./bundle --key ./vault.key

# Summarize a bundle
vault show --bundle ./bundle

# Inspect / verify the vault's own audit log
vault log
vault log --verify
```

Input kinds (`--alert`, `--eval`, `--audit`) are read with adapters that
parse the siblings' **real** formats — nothing is reimplemented. Every
artifact records its source repo and the pinned source SHA, so an auditor
knows exactly which code produced it.

Exit codes: `0` verified/built, `1` tamper detected, `2` usage/input error.

## Bundle layout

```
bundle/
  attestation.json   # in-toto-style statement; predicate lists every
                     # evidence file with its sha256, source and source SHA
  signature.json     # HMAC-SHA256 over the attestation (only with --key)
  evidence/
    conformance-pack/...   # verbatim copies from the pack
    registry/...           # model card + risk assessment from the registry
    incidents/...          # incident records + postmortems
    alerts/<source>/...    # monitor / drift alerts
    evals/<source>/...     # eval reports
    audit-logs/<source>/...# sibling audit logs
```

## Demo

`python examples/demo.py` runs the full pipeline with the siblings' real
code: a conformance pack (`--collect`, real opsaudit + act-checker runs),
a real registry DB, a real incident store, then builds a signed bundle and
verifies it from a fresh directory as an external auditor would —
including a tamper demo where verification correctly fails.

## Docs

- `docs/METHODOLOGY.md` — how the vault works and why
- `docs/BUNDLE_FORMAT.md` — bundle directory + attestation schema
- `docs/SOURCES.md` — sibling repos and pinned SHAs
- `docs/LIMITATIONS.md` — what the vault does and does not prove
- `docs/CHANGELOG.md` — release notes

## License

Apache-2.0.

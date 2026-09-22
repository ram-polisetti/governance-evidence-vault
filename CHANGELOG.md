# Changelog

## 0.1.0 — 2026-09-22

- Initial release.
- `vault build`: assemble a governance bundle from real sibling artifacts —
  conformance packs, registry DB (card/risk/approvals), incident stores,
  monitor/drift alerts, eval reports, sibling audit logs, operator extras.
- `vault verify`: offline auditor-mode verification — re-hash every file,
  check statement/predicate types, verify HMAC signature with a shared key,
  explicit per-file reporting; exit 1 on tamper.
- `vault show`: summarize a bundle's attestation.
- `vault log` / `vault log --verify`: hash-chained vault audit log of every
  build and verification.
- SLSA/in-toto-style attestation (`predicateType:
  https://ram-polisetti.dev/governance-evidence-bundle/v1`) recording every
  artifact's sha256, source tool, and pinned source SHA.
- HMAC-SHA256 attestation signing with an operator-held key.
- Adapters pinned to sibling SHAs (see docs/SOURCES.md); never reimplements
  sibling logic.
- 31 tests; end-to-end demo with real sibling tools (pack --collect with
  real opsaudit + act-checker runs, real registry, real incident store),
  auditor-mode verification from a fresh directory, and a tamper demo.
- Stdlib only. Apache-2.0.

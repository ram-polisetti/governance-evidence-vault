# Methodology

## Problem

A deployed AI system accumulates governance evidence across many tools:
fairness audits (opsaudit), AI Act conformity checks (ai-act-checker),
deployment verdicts (conformance-pack), approvals (model-governance-registry),
incident records (ai-incident-runbook), monitor alerts (disparity-monitor,
rag-eval-drift), eval and red-team reports. An auditor asked "what backs
this deployment?" gets a scavenger hunt across repos, databases, and JSONL
logs — with no way to prove nothing was added, removed, or edited after the
fact.

## Approach

The vault does not create evidence. It **collects, hashes, and attests**:

1. **Adapters read real formats.** Each sibling tool's output is parsed by
   an adapter that understands that tool's actual format (pack.json
   manifests, mgreg sqlite schema, incidentrun JSONL, outbox alert JSON).
   The vault never reimplements a sibling's logic — it invokes nothing and
   duplicates nothing; it reads.
2. **Verbatim copies.** Every artifact is copied byte-for-byte into
   `evidence/`. The bundle is self-contained: an auditor needs nothing but
   the bundle directory.
3. **Attestation.** An in-toto-style statement lists every evidence file
   with its SHA-256, byte size, slot, source tool, and the pinned source
   SHA of the tool that produced it. The predicate also records approvals,
   incidents, the pack recommendation, and sibling SHAs.
4. **Signature.** With `--key`, the attestation is HMAC-SHA256-signed with
   an operator-held key. This adds origin assurance for parties sharing the
   key; it is not a PKI signature (see LIMITATIONS.md).
5. **Vault audit log.** Every build and verification is appended to a
   SHA-256 hash-chained `vault.jsonl`, so the vault's own history is
   tamper-evident too.

## Verification (auditor mode)

`vault verify` re-hashes every evidence file and compares against the
attestation, checks statement/predicate types, verifies the signature when
a key is given, and reports each check. A missing or altered file is
reported explicitly — never silently skipped. Exit 1 on any failure.

## Why HMAC, not X.509

The vault is stdlib-only by design (it must run anywhere, including
air-gapped auditor machines, with zero dependency risk). Stdlib Python has
no X.509 signing; HMAC-SHA256 with an operator-held key is the strongest
origin guarantee available without third-party crypto. The hash chain over
artifacts is the primary integrity mechanism — the signature is origin
assurance on top.

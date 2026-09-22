# Limitations

1. **The vault proves integrity, not truth.** A bundle proves the listed
   artifacts existed at build time and have not been altered since. It does
   not prove the artifacts are correct — a flawed audit bundled honestly is
   still a flawed audit. Garbage in, tamper-evident garbage out.
2. **HMAC signing is not PKI.** The signature proves origin only to parties
   holding the shared key. There is no certificate chain, no key rotation
   story, and no non-repudiation against a key holder. An auditor without
   the key still gets full hash + chain verification.
3. **Adapter coverage is format-pinned.** Adapters parse the formats of the
   pinned sibling SHAs (see SOURCES.md). A newer sibling release may change
   a format and break an adapter — loudly (AdapterError), not silently.
4. **Evidence completeness is the operator's job.** The vault bundles what
   it is given. If an incident was never recorded, it cannot appear in the
   bundle. `vault show` lists exactly what is inside; absence of evidence is
   visible, not hidden — but nothing forces the operator to include it.
5. **Approvals are snapshots.** Approval records are copied as they exist
   in the registry at build time. Later demotions (e.g. by the
   stale-approval sweeper) do not retroactively update an old bundle —
   build a new bundle after material changes.
6. **No confidentiality.** Bundles are plaintext JSON. Do not put secrets,
   PII, or raw production data in artifacts you intend to hand to an
   external auditor.
7. **Timestamps are local claims.** `built_utc` comes from the build
   machine's clock. The hash chain orders events; it does not prove wall-
   clock time.

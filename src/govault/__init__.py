"""governance-evidence-vault: tamper-evident governance bundles for AI systems.

Assembles eval results, red-team reports, fairness audits, monitor alerts,
approvals and incident records into a single signed, hash-chained bundle
that an external auditor can verify offline.
"""

__version__ = "0.1.0"

# Pinned SHAs of the sibling repos this tool reads. Every bundle records
# these so an auditor knows exactly which code produced each artifact.
SIBLING_SHAS = {
    "conformance-pack": "eb3fcce",
    "model-governance-registry": "a8a8a23",
    "ai-incident-runbook": "7c28259",
    "rag-redteam": "169e4c8",
    "rag-governance-demo": "c339ae1",
    "opsaudit": "e2f6220",
    "disparity-monitor": "e5426ff",
    "rag-eval-drift": "836bc85",
    "ai-act-checker": "bab26de",
}

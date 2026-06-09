"""Phase 0 / Workstream B "Pith" — Infrastructure-as-Code analysis.

This package owns everything that runs *before* the orchestrator touches
the network: source ingestion, scanner subprocess management, finding
normalisation, suppression, graph projection (M3), and identity merging
with live cloud nodes (M3).

The package is laid out so each milestone in the workstream lights up a
separate module without churn elsewhere:

    sources.py         — resolve every IacSourceConfig to a local tree
    scanners/          — one file per scanner (tfsec, checkov, …)
    normalize.py       — RawFinding -> db.Finding, with sanitisation
    suppress.py        — # clementine:false-positive: post-filter (M2)
    projection.py      — IaC resources -> planned graph nodes (M3)
    identity_merge.py  — match planned nodes to live nodes (M3)
"""

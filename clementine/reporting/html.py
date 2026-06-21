"""
HTML report renderer — Clementine dark-mode design.

Produces a self-contained interactive HTML report with:
  - Sticky sidebar rail navigation with scrollspy
  - Hero: risk score KPI strip, severity histogram, executive narrative
  - Attack chains: expandable step accordion with ENTRY/PIVOT/AMPLIFIER roles
  - Findings: OWASP-grouped accordion with live search + severity chips
  - Remediation playbook: 3-column effort grid (Quick Wins / Medium Lift / Structural)
  - Compliance mapping: aggregated per-control table
  - Attack graph: force-directed canvas visualization
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from ..config import ClementineConfig
from ..db import AttackChain, Finding, FindingsDB, Severity

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEV_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}
_CIRC = 282.74


def _risk_score(counts: dict[str, int]) -> int:
    raw = 100 - (
        counts["CRITICAL"] * 20
        + counts["HIGH"] * 8
        + counts["MEDIUM"] * 3
        + counts["LOW"] * 1
    )
    return max(0, min(100, raw))


def _risk_band(score: int) -> str:
    if score >= 80:
        return "low"
    if score >= 60:
        return "medium"
    if score >= 35:
        return "high"
    return "critical"


def _risk_label(score: int) -> str:
    return {
        "low": "Low Risk",
        "medium": "Moderate Risk",
        "high": "High Risk",
        "critical": "Critical Risk",
    }[_risk_band(score)]


def _md_bold(text: str) -> str:
    return re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)


# ---------------------------------------------------------------------------
# OWASP category mapping
# ---------------------------------------------------------------------------

_OWASP_PREFIXES = [
    ("wstg-athz", "A01", "Broken Access Control"),
    ("wstg-inpv", "A03", "Injection"),
    ("wstg-sess", "A07", "Identification & Authentication"),
    ("wstg-athn", "A07", "Identification & Authentication"),
    ("wstg-idnt", "A07", "Identification & Authentication"),
    ("wstg-cryp", "A02", "Cryptographic Failures"),
    ("wstg-conf", "A05", "Security Misconfiguration"),
    ("wstg-errh", "A05", "Security Misconfiguration"),
    ("wstg-info", "A05", "Security Misconfiguration"),
    ("wstg-busl", "A04", "Insecure Design"),
]
_OWASP_KEYWORDS = [
    ("ec2", "AWS", "Cloud Posture"),
    ("iam", "AWS", "Cloud Posture"),
    ("rds", "AWS", "Cloud Posture"),
    ("s3", "AWS", "Cloud Posture"),
    ("cloudtrail", "AWS", "Cloud Posture"),
    ("guardduty", "AWS", "Cloud Posture"),
    ("security-group", "AWS", "Cloud Posture"),
    ("cloud-audit", "AWS", "Cloud Posture"),
    ("imds", "AWS", "Cloud Posture"),
    ("prowler", "AWS", "Cloud Posture"),
    # Azure keywords
    ("azure:", "AZURE", "Azure Posture"),
    ("az_", "AZURE", "Azure Posture"),
    ("keyvault", "AZURE", "Azure Posture"),
    ("entra", "AZURE", "Azure Posture"),
    ("defender", "AZURE", "Azure Posture"),
    ("clementine-azure-probe", "AZURE", "Azure Posture"),
]
_OWASP_ORDER = [
    "A01", "A02", "A03", "A04", "A05", "A06",
    "A07", "A08", "A09", "A10", "AWS", "AZURE", "OTHER",
]


def _owasp_category(cat: str) -> tuple[str, str]:
    if not cat:
        return "OTHER", "Other Findings"
    lo = cat.lower()
    for prefix, code, name in _OWASP_PREFIXES:
        if lo.startswith(prefix):
            return code, name
    for kw, code, name in _OWASP_KEYWORDS:
        if kw in lo:
            return code, name
    return "OTHER", "Other Findings"


def _group_by_owasp(findings: list[Finding]) -> list[dict]:
    groups: dict[str, dict] = {}
    for f in findings:
        cat = f.category or f.source or ""
        code, name = _owasp_category(cat)
        if code not in groups:
            groups[code] = {"code": code, "name": name, "findings": []}
        groups[code]["findings"].append(f)
    return sorted(
        groups.values(),
        key=lambda g: _OWASP_ORDER.index(g["code"]) if g["code"] in _OWASP_ORDER else 99,
    )


def _aggregate_compliance(findings: list[Finding]) -> list[dict]:
    controls: dict[tuple, dict] = {}
    for f in findings:
        if not f.compliance_mappings:
            continue
        for fw, ctrl in f.compliance_mappings.items():
            key = (fw, str(ctrl))
            if key not in controls:
                controls[key] = {
                    "framework": fw,
                    "control": str(ctrl),
                    "n_findings": 0,
                    "_titles": [],
                }
            controls[key]["n_findings"] += 1
            if len(controls[key]["_titles"]) < 2:
                controls[key]["_titles"].append(f.title[:45])
    rows = []
    for r in sorted(controls.values(), key=lambda x: (x["framework"], x["control"])):
        rows.append({
            "framework": r["framework"],
            "control": r["control"],
            "n_findings": r["n_findings"],
            "note": "; ".join(r["_titles"]),
        })
    return rows


def _narrative_html(
    chains: list[AttackChain],
    severity_counts: dict[str, int],
    total_findings: int,
) -> tuple[str, str]:
    """Return (headline_html, body_text) for the hero section."""
    if chains:
        top = min(chains, key=lambda c: _SEV_RANK.get(c.severity, 99))
        raw = re.sub(r"\*\*(.+?)\*\*", r"\1", top.narrative or "")
        first = raw.strip().splitlines()[0] if raw.strip() else top.pattern_name
        first = re.sub(r"^(Entry|Impact|Pivot):\s*", "", first, flags=re.I)
        if len(first) > 110:
            first = first[:107] + "…"
        hl = first
        for kw in ("SSRF", "SQL injection", "SQL", "XSS", "injection", "credential", "privilege", "remote"):
            if kw.lower() in hl.lower():
                hl = re.sub(
                    r"(?i)(" + re.escape(kw) + r")",
                    r"<em>\1</em>",
                    hl,
                    count=1,
                )
                break
        headline_html = hl
    else:
        headline_html = (
            f"Assessment identified <em>{total_findings} findings</em> "
            "requiring immediate attention."
        )

    n_crit = severity_counts.get("CRITICAL", 0)
    n_high = severity_counts.get("HIGH", 0)
    nc = len(chains)
    body = (
        f"Across {total_findings} findings"
        + (
            f", {nc} compound attack chain{'s' if nc != 1 else ''} "
            "were identified converging on the same outcome"
            if chains
            else ""
        )
        + f". Critical and high severity issues account for {n_crit + n_high} findings. "
    )
    if chains:
        names = " and ".join(f"“{c.pattern_name}”" for c in chains[:2])
        body += f"Primary paths: {names}."
    return headline_html, body


# ---------------------------------------------------------------------------
# Jinja templates
# ---------------------------------------------------------------------------
#
# The report and graph markup live as standalone Jinja templates under
# ``templates/`` so the HTML/CSS/JS can be edited with real tooling instead of
# being trapped in a multi-thousand-line Python string literal.

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _make_jinja_env() -> Environment:
    """Build the Jinja environment used to render the HTML reports.

    ``autoescape`` is forced on for every template regardless of file
    extension — the report interpolates untrusted finding data (URLs,
    payloads, tool output), so escaping must never silently switch off.
    """
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=True,
    )
    env.filters["md_bold"] = _md_bold
    return env


# ---------------------------------------------------------------------------
# Reporter class
# ---------------------------------------------------------------------------

class HtmlReporter:
    """Renders findings and attack chains as an interactive HTML report."""

    def __init__(self, cfg: ClementineConfig, db: FindingsDB) -> None:
        self._cfg = cfg
        self._db = db

    async def write(
        self,
        findings: list[Finding],
        chains: list[AttackChain],
        output_path: Path,
    ) -> None:
        severity_counts = {s.value: 0 for s in Severity}
        for f in findings:
            severity_counts[f.severity.value] += 1
        total_findings = len(findings)

        score = _risk_score(severity_counts)
        band  = _risk_band(score)
        label = _risk_label(score)

        hist_max = max(severity_counts.values()) if severity_counts else 1

        health_score = await self._db.get_state("cloud_audit_health_score", "N/A")

        findings_by_category = _group_by_owasp(findings)
        compliance_controls  = _aggregate_compliance(findings)
        headline_html, narrative_body = _narrative_html(chains, severity_counts, total_findings)

        # Enrich chains with components and actions
        chain_data = []
        for chain in chains:
            components = await self._db.get_chain_findings(chain.id)
            actions    = await self._db.get_remediation_actions(chain_id=chain.id)
            chain_data.append({
                "chain":      chain,
                "components": components,
                "actions":    actions,
            })

        # Remediation playbook grouped by effort
        playbook: dict[str, list[dict]] = {"LOW": [], "MEDIUM": [], "HIGH": []}
        seen: set[str] = set()
        for cd in chain_data:
            for action in cd["actions"]:
                key = action.action_summary.strip()[:120]
                if key in seen:
                    continue
                seen.add(key)
                playbook[action.effort_level.value].append({
                    "action_summary": action.action_summary,
                    "breaks_chain":   action.breaks_chain,
                    "cli_command":    action.cli_command,
                    "iac_snippet":    getattr(action, "iac_snippet", None),
                    "chain_name":     cd["chain"].pattern_name,
                })
        for group in playbook.values():
            group.sort(key=lambda x: (not x["breaks_chain"],))

        # ------------------------------------------------------------------
        # Azure-specific report data
        # ------------------------------------------------------------------

        # Per-cloud severity counts for the posture cards
        aws_counts: dict[str, int] = {s.value: 0 for s in Severity}
        az_counts: dict[str, int]  = {s.value: 0 for s in Severity}
        # IaC (Phase 0 / Workstream B) findings get their own breakdown
        # so reviewers can see at a glance how much of the posture story
        # is "this would be CRITICAL on deployment" versus runtime live
        # state.
        iac_counts: dict[str, int] = {s.value: 0 for s in Severity}
        iac_findings_top: list[Finding] = []
        for f in findings:
            if (f.source or "").startswith("iac-scanner-"):
                iac_counts[f.severity.value] += 1
                continue
            provider = getattr(f, "provider", "aws") or "aws"
            if provider == "azure":
                az_counts[f.severity.value] += 1
            else:
                aws_counts[f.severity.value] += 1

        # Surface up to 8 high-severity IaC findings in the report so
        # the section has concrete callouts, not just a count grid.
        _sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        iac_findings_top = sorted(
            (f for f in findings if (f.source or "").startswith("iac-scanner-")),
            key=lambda f: (_sev_rank.get(f.severity.value, 99), f.iac_source_path or ""),
        )[:8]

        # Multi-cloud chains — chains whose components span both providers.
        # ``get_chain_findings`` returns ``(Finding, ChainRole, int)`` tuples,
        # which is what the Jinja template iterates as
        # ``for comp_finding, role, order in cd.components`` further down. We
        # destructure the same shape here. The dict / attribute branches are
        # kept as defensive fallbacks for any future shape change so this code
        # path doesn't silently drop multi-cloud chains again.
        finding_by_id = {f.id: f for f in findings}
        multi_cloud_chains: list[dict] = []
        for cd in chain_data:
            providers_seen: set[str] = set()
            for comp in cd["components"]:
                if isinstance(comp, tuple) and comp:
                    finding_obj = comp[0]
                    fid = getattr(finding_obj, "id", None)
                elif hasattr(comp, "finding_id"):
                    fid = comp.finding_id
                elif isinstance(comp, dict):
                    fid = comp.get("finding_id")
                else:
                    fid = None
                if fid and fid in finding_by_id:
                    prov = getattr(finding_by_id[fid], "provider", "aws") or "aws"
                    providers_seen.add(prov)
            if len(providers_seen) > 1:
                multi_cloud_chains.append(cd)

        # Identity hygiene: federated credentials and PIM-eligible role assignments
        identity_hygiene: list[dict] = []
        try:
            fed_creds = await self._db.get_azure_federated_credentials()
            for cred in fed_creds:
                identity_hygiene.append({
                    "type":    "federated_credential",
                    "name":    cred.get("name") or cred.get("id", "")[:60],
                    "detail":  f"issuer={cred.get('issuer','?')} subject={cred.get('subject','?')}",
                    "risk":    "HIGH" if cred.get("subject") == "*" else "INFO",
                })
        except Exception:
            pass
        try:
            role_assignments = await self._db.get_azure_role_assignments()
            for ra in role_assignments:
                if ra.get("pim_eligible"):
                    identity_hygiene.append({
                        "type":   "pim_eligible",
                        "name":   ra.get("role_definition_name", ra.get("role_definition_id", "?"))[:60],
                        "detail": f"principal={ra.get('principal_id','?')} scope={ra.get('scope','?')}",
                        "risk":   "MEDIUM",
                    })
        except Exception:
            pass

        # Defender vs Prowler drift
        defender_prowler_drift: list[dict] = []
        try:
            compliance_findings = await self._db.get_azure_compliance_findings()
            prowler_map: dict[tuple, str] = {}
            defender_map: dict[tuple, str] = {}
            for cf in compliance_findings:
                key = (cf.get("framework", ""), cf.get("control_id", ""))
                source = cf.get("source", "")
                state = cf.get("state", "")
                if "prowler" in source.lower():
                    prowler_map[key] = state
                elif "defender" in source.lower():
                    defender_map[key] = state
            for key in set(prowler_map) & set(defender_map):
                ps, ds = prowler_map[key], defender_map[key]
                # Drift: one says passed, the other says failed
                if (ps.lower() in ("passed", "pass")) != (ds.lower() in ("passed", "pass")):
                    defender_prowler_drift.append({
                        "framework":       key[0],
                        "control_id":      key[1],
                        "prowler_state":   ps,
                        "defender_state":  ds,
                    })
        except Exception:
            pass

        # Attack graph
        graph_json = "{}"
        try:
            from ..graph import GraphBuilder
            from ..graph.attack_surface import AttackSurfaceAnalyzer
            nx_graph = await GraphBuilder(self._db).build_from_db()
            if nx_graph.number_of_nodes() > 0:
                cytoscape_data = AttackSurfaceAnalyzer(nx_graph).to_cytoscape(
                    {f.id: f for f in findings}
                )
                graph_json = json.dumps(cytoscape_data)
        except Exception as exc:
            log.warning("Could not build attack graph for report: %s", exc)

        env = _make_jinja_env()

        graph_path = ""
        if graph_json != "{}":
            graph_page_path = output_path.parent / "graph.html"
            try:
                graph_tmpl = env.get_template("graph.html.j2")
                graph_page_path.write_text(
                    graph_tmpl.render(
                        target_url=self._cfg.target.url,
                        graph_json=graph_json,
                    ),
                    encoding="utf-8",
                )
                graph_path = "graph.html"
                log.info("Graph page written to %s", graph_page_path)
            except Exception as exc:
                log.warning("Could not write graph.html: %s", exc)

        template = env.get_template("report.html.j2")
        html = template.render(
            target_url=self._cfg.target.url,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            severity_counts=severity_counts,
            total_findings=total_findings,
            hist_max=hist_max,
            risk_score=score,
            risk_band=band,
            risk_label=label,
            narrative_headline_html=headline_html,
            narrative_body=narrative_body,
            chain_data=chain_data,
            findings=findings,
            findings_by_category=findings_by_category,
            compliance_controls=compliance_controls,
            playbook=playbook,
            health_score=health_score,
            graph_json=graph_json,
            graph_path=graph_path,
            # Azure additions
            aws_counts=aws_counts,
            az_counts=az_counts,
            multi_cloud_chains=multi_cloud_chains,
            identity_hygiene=identity_hygiene,
            defender_prowler_drift=defender_prowler_drift,
            # IaC additions (Phase 0 / Workstream B)
            iac_counts=iac_counts,
            iac_findings_top=iac_findings_top,
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")

"""
HTML report renderer.

Produces a self-contained interactive HTML report with:
  - Executive summary (severity distribution, health score, top 5 risks)
  - Attack chains section (collapsible, severity-sorted)
  - Findings section (filterable by severity, WSTG category, source)
  - Compliance mapping matrix
  - Remediation playbook (grouped by effort level)

The template is embedded as a string to avoid external file dependencies at
install time.  It uses vanilla CSS/JS only — no external CDN resources.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from jinja2 import Environment, BaseLoader

from ..config import ClementineConfig
from ..db import AttackChain, Finding, FindingsDB, Severity

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Jinja2 template — self-contained, no external CDN dependencies
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Project Clementine — Security Assessment Report</title>
<style>
  :root {
    --critical: #dc2626; --high: #ea580c; --medium: #d97706;
    --low: #65a30d; --info: #2563eb;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #f8fafc; color: #1e293b; }
  header { background: #0f172a; color: #f8fafc; padding: 1.5rem 2rem; }
  header h1 { font-size: 1.5rem; }
  header p { opacity: .7; font-size: .875rem; margin-top: .25rem; }
  main { max-width: 1200px; margin: 2rem auto; padding: 0 1rem; }
  section { margin-bottom: 2.5rem; }
  h2 { font-size: 1.25rem; font-weight: 700; margin-bottom: 1rem; border-bottom: 2px solid #e2e8f0; padding-bottom: .5rem; }
  h3 { font-size: 1rem; font-weight: 600; margin-bottom: .5rem; }
  .badge { display: inline-block; padding: .2rem .6rem; border-radius: 9999px; font-size: .75rem; font-weight: 700; color: #fff; }
  .badge-CRITICAL { background: var(--critical); }
  .badge-HIGH { background: var(--high); }
  .badge-MEDIUM { background: var(--medium); }
  .badge-LOW { background: var(--low); }
  .badge-INFO { background: var(--info); }
  .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; }
  .summary-card { background: #fff; border-radius: .5rem; padding: 1rem; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
  .summary-card .count { font-size: 2rem; font-weight: 800; }
  .chain-card, .finding-card { background: #fff; border-radius: .5rem; padding: 1.25rem; margin-bottom: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
  .chain-card { border-left: 4px solid var(--critical); }
  .chain-card.HIGH { border-color: var(--high); }
  .chain-card.MEDIUM { border-color: var(--medium); }
  details summary { cursor: pointer; user-select: none; }
  details summary:hover { opacity: .8; }
  pre { background: #0f172a; color: #e2e8f0; padding: 1rem; border-radius: .375rem; font-size: .8rem; overflow-x: auto; margin-top: .75rem; }
  table { width: 100%; border-collapse: collapse; font-size: .875rem; }
  th { text-align: left; padding: .5rem .75rem; background: #f1f5f9; border-bottom: 2px solid #e2e8f0; }
  td { padding: .5rem .75rem; border-bottom: 1px solid #e2e8f0; }
  .filter-bar { display: flex; gap: .5rem; margin-bottom: 1rem; flex-wrap: wrap; }
  select { padding: .375rem .75rem; border: 1px solid #cbd5e1; border-radius: .375rem; font-size: .875rem; }
  .narrative { font-size: .875rem; line-height: 1.6; white-space: pre-wrap; }
</style>
</head>
<body>
<header>
  <h1>Project Clementine — Security Assessment Report</h1>
  <p>Target: {{ target_url }} &bull; Generated: {{ generated_at }}</p>
</header>
<main>

<!-- Executive Summary -->
<section>
  <h2>Executive Summary</h2>
  <div class="summary-grid">
    {% for sev in ['CRITICAL','HIGH','MEDIUM','LOW','INFO'] %}
    <div class="summary-card">
      <div class="count badge badge-{{ sev }}">{{ severity_counts[sev] }}</div>
      <div style="margin-top:.5rem;font-size:.875rem">{{ sev }}</div>
    </div>
    {% endfor %}
  </div>
  <p style="margin-top:1rem">
    <strong>Attack Chains:</strong> {{ chains|length }} &bull;
    <strong>AWS Health Score:</strong> {{ health_score }}/100
  </p>
  {% if top5 %}
  <h3 style="margin-top:1.5rem">Top 5 Findings</h3>
  <ul style="margin-left:1.5rem;margin-top:.5rem;line-height:2">
    {% for f in top5 %}
    <li><span class="badge badge-{{ f.severity.value }}">{{ f.severity.value }}</span> {{ f.title }}</li>
    {% endfor %}
  </ul>
  {% endif %}
</section>

<!-- Attack Chains -->
{% if chains %}
<section>
  <h2>Attack Chains</h2>
  {% for chain in chains %}
  <div class="chain-card {{ chain.severity.value }}">
    <details>
      <summary>
        <span class="badge badge-{{ chain.severity.value }}">{{ chain.severity.value }}</span>
        <strong style="margin-left:.5rem">{{ chain.pattern_name }}</strong>
      </summary>
      <div class="narrative" style="margin-top:.75rem">{{ chain.narrative }}</div>
      {% if chain.breach_cost_low %}
      <p style="margin-top:.75rem;font-size:.875rem">
        <strong>Estimated Breach Cost:</strong>
        ${{ "{:,.0f}".format(chain.breach_cost_low) }} – ${{ "{:,.0f}".format(chain.breach_cost_high) }}
      </p>
      {% endif %}
    </details>
  </div>
  {% endfor %}
</section>
{% endif %}

<!-- Findings -->
<section>
  <h2>Findings</h2>
  <div class="filter-bar">
    <select id="sev-filter" onchange="applyFilters()">
      <option value="">All Severities</option>
      {% for s in ['CRITICAL','HIGH','MEDIUM','LOW','INFO'] %}<option>{{ s }}</option>{% endfor %}
    </select>
    <select id="src-filter" onchange="applyFilters()">
      <option value="">All Sources</option>
      {% for s in sources %}<option>{{ s }}</option>{% endfor %}
    </select>
  </div>
  {% for f in findings %}
  <div class="finding-card" data-severity="{{ f.severity.value }}" data-source="{{ f.source }}">
    <details>
      <summary>
        <span class="badge badge-{{ f.severity.value }}">{{ f.severity.value }}</span>
        <strong style="margin-left:.5rem">{{ f.title }}</strong>
        <span style="margin-left:.5rem;opacity:.6;font-size:.8rem">{{ f.category }}</span>
      </summary>
      <p style="margin-top:.75rem;font-size:.875rem">{{ f.description }}</p>
      {% if f.resource_id %}
      <p style="margin-top:.5rem;font-size:.8rem"><strong>Resource:</strong> {{ f.resource_id }}</p>
      {% endif %}
      {% if f.remediation_summary %}
      <p style="margin-top:.5rem;font-size:.875rem"><strong>Remediation:</strong> {{ f.remediation_summary }}</p>
      {% endif %}
      {% if f.remediation_cli %}
      <pre>{{ f.remediation_cli }}</pre>
      {% endif %}
      {% if f.remediation_iac %}
      <pre>{{ f.remediation_iac }}</pre>
      {% endif %}
    </details>
  </div>
  {% endfor %}
</section>

{% if compliance_rows %}
<!-- Compliance Mapping -->
<section>
  <h2>Compliance Mapping</h2>
  <table>
    <thead><tr><th>Finding</th><th>Framework</th><th>Control</th></tr></thead>
    <tbody>
    {% for row in compliance_rows %}
    <tr>
      <td>{{ row.title }}</td>
      <td>{{ row.framework }}</td>
      <td>{{ row.control }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</section>
{% endif %}

</main>
<script>
function applyFilters() {
  const sev = document.getElementById('sev-filter').value;
  const src = document.getElementById('src-filter').value;
  document.querySelectorAll('.finding-card').forEach(el => {
    const sevMatch = !sev || el.dataset.severity === sev;
    const srcMatch = !src || el.dataset.source === src;
    el.style.display = (sevMatch && srcMatch) ? '' : 'none';
  });
}
</script>
</body>
</html>
"""


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
        """Render the report and write it to *output_path*."""
        from datetime import datetime, timezone

        # Severity distribution
        severity_counts = {s.value: 0 for s in Severity}
        for f in findings:
            severity_counts[f.severity.value] += 1

        # Health score from assessment state
        health_score = await self._db.get_state("cloud_audit_health_score", "N/A")

        # Top 5 by severity order
        severity_rank = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        top5 = sorted(findings, key=lambda f: severity_rank[f.severity])[:5]

        # Unique sources
        sources = sorted({f.source for f in findings})

        # Compliance rows
        compliance_rows = []
        for f in findings:
            if f.compliance_mappings:
                for framework, control in f.compliance_mappings.items():
                    compliance_rows.append({
                        "title": f.title[:60],
                        "framework": framework,
                        "control": control,
                    })

        env = Environment(loader=BaseLoader(), autoescape=True)
        template = env.from_string(_HTML_TEMPLATE)
        html = template.render(
            target_url=self._cfg.target.url,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            severity_counts=severity_counts,
            chains=chains,
            findings=findings,
            top5=top5,
            health_score=health_score,
            sources=sources,
            compliance_rows=compliance_rows,
        )

        output_path.write_text(html, encoding="utf-8")
        log.info("HTML report written to %s", output_path)

"""
HTML report renderer.

Produces a self-contained interactive HTML report with:
  - Sticky sidebar navigation
  - Executive summary: risk score ring, severity distribution bars, top-5 table
  - Attack chains: visual step-flow (ENTRY → PIVOT → AMPLIFIER), impact, remediation
  - Findings: search + multi-filter table with expandable detail drawers
  - Remediation playbook: grouped by effort, chain-breaking items highlighted
  - Compliance mapping table
  - Copy-to-clipboard on all code blocks
  - AI triage confidence / false-positive badges

Template is embedded as a string — no external file dependencies at install time.
Vanilla CSS/JS only; no CDN resources.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, BaseLoader

from ..config import ClementineConfig
from ..db import AttackChain, Finding, FindingsDB, RemediationAction, Severity

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEV_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
_CIRC = 282.74  # circumference of SVG circle r=45


def _risk_score(counts: dict[str, int]) -> int:
    raw = 100 - (counts["CRITICAL"] * 20 + counts["HIGH"] * 8 + counts["MEDIUM"] * 3 + counts["LOW"] * 1)
    return max(0, min(100, raw))


def _risk_meta(score: int) -> tuple[str, str, str]:
    """Return (color, label, svg_dash) for the risk score ring."""
    if score >= 80:
        return "#16a34a", "Low Risk", str(round(_CIRC * score / 100, 1))
    if score >= 60:
        return "#d97706", "Moderate Risk", str(round(_CIRC * score / 100, 1))
    if score >= 35:
        return "#ea580c", "High Risk", str(round(_CIRC * score / 100, 1))
    return "#dc2626", "Critical Risk", str(round(_CIRC * score / 100, 1))


def _md_bold(text: str) -> str:
    """Convert **text** → <strong>text</strong> for narrative display."""
    return re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)


# ---------------------------------------------------------------------------
# Jinja2 template — self-contained, no external CDN dependencies
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Clementine &mdash; {{ target_url }}</title>
<style>
/* ── Base ── */
:root {
  --c-critical:#dc2626; --c-high:#ea580c; --c-medium:#d97706;
  --c-low:#65a30d; --c-info:#2563eb;
  --c-bg:#f8fafc; --c-card:#fff; --c-border:#e2e8f0;
  --c-dark:#0f172a; --c-text:#1e293b; --c-muted:#64748b;
  --c-code-bg:#0f172a; --c-code-text:#e2e8f0;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:var(--c-bg);color:var(--c-text);line-height:1.5}
a{color:#2563eb;text-decoration:none}
a:hover{text-decoration:underline}

/* ── Layout ── */
.layout{display:grid;grid-template-columns:220px 1fr;min-height:100vh}
.sidebar{position:sticky;top:0;height:100vh;background:var(--c-dark);overflow-y:auto;flex-shrink:0}
.sidebar-logo{padding:.875rem 1.25rem 1rem;border-bottom:1px solid rgba(255,255,255,.1)}
.sidebar-logo .name{color:#f8fafc;font-size:.875rem;font-weight:700;display:block}
.sidebar-logo .sub{color:rgba(255,255,255,.35);font-size:.7rem;display:block;margin-top:.15rem}
.nav-group{padding:.5rem 1.25rem .2rem;color:rgba(255,255,255,.28);font-size:.625rem;text-transform:uppercase;letter-spacing:.1em;margin-top:.75rem}
.nav-item{display:flex;align-items:center;justify-content:space-between;padding:.45rem 1.25rem;color:rgba(255,255,255,.55);font-size:.8125rem;transition:background .12s,color .12s;cursor:pointer}
.nav-item:hover,.nav-item.active{background:rgba(255,255,255,.08);color:#f8fafc;text-decoration:none}
.nav-badge{background:rgba(255,255,255,.1);color:rgba(255,255,255,.4);border-radius:9999px;padding:.1rem .5rem;font-size:.7rem}
.nav-badge.red{background:rgba(220,38,38,.3);color:#fca5a5}
.sidebar-footer{padding:1.25rem;border-top:1px solid rgba(255,255,255,.07);color:rgba(255,255,255,.28);font-size:.7rem;line-height:1.65;margin-top:2rem}
.main{padding:2rem 2.5rem;max-width:1100px}

/* ── Page header ── */
.page-header{margin-bottom:2rem;padding-bottom:1.25rem;border-bottom:1px solid var(--c-border)}
.page-header h1{font-size:1.375rem;font-weight:800;color:var(--c-dark)}
.page-header .meta{color:var(--c-muted);font-size:.875rem;margin-top:.35rem}

/* ── Sections ── */
.section{margin-bottom:3rem;scroll-margin-top:1.5rem}
.section-title{font-size:1.05rem;font-weight:700;color:var(--c-dark);margin-bottom:1.25rem;padding-bottom:.5rem;border-bottom:2px solid var(--c-border);display:flex;align-items:center;gap:.5rem}
.section-subtitle{font-size:.8rem;font-weight:400;color:var(--c-muted)}

/* ── Cards ── */
.card{background:var(--c-card);border-radius:.625rem;box-shadow:0 1px 3px rgba(0,0,0,.07),0 1px 2px rgba(0,0,0,.04)}
.card-pad{padding:1.25rem 1.5rem}

/* ── Badges ── */
.badge{display:inline-flex;align-items:center;padding:.175rem .55rem;border-radius:9999px;font-size:.6875rem;font-weight:700;letter-spacing:.03em;text-transform:uppercase;white-space:nowrap}
.badge-CRITICAL,.badge-critical{background:#fee2e2;color:var(--c-critical)}
.badge-HIGH,.badge-high{background:#ffedd5;color:var(--c-high)}
.badge-MEDIUM,.badge-medium{background:#fef3c7;color:var(--c-medium)}
.badge-LOW,.badge-low{background:#ecfccb;color:var(--c-low)}
.badge-INFO,.badge-info{background:#dbeafe;color:var(--c-info)}
.badge-ai{background:#f3e8ff;color:#7c3aed}
.badge-entry{background:#fee2e2;color:#b91c1c}
.badge-pivot{background:#ffedd5;color:#c2410c}
.badge-amplifier{background:#fef9c3;color:#a16207}
.badge-breaks{background:#ecfdf5;color:#047857}
.badge-fp{background:#f3f4f6;color:#6b7280}
.badge-conf{background:#f0fdf4;color:#15803d}

/* ── Executive summary ── */
.summary-grid{display:grid;grid-template-columns:1fr 1.5fr;gap:1.25rem;margin-bottom:1.25rem}
.score-card{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:.75rem;padding:1.75rem 1.5rem}
.score-ring{position:relative;width:120px;height:120px}
.score-ring svg{width:120px;height:120px;transform:rotate(-90deg)}
.score-ring .track{fill:none;stroke:#e2e8f0;stroke-width:10}
.score-ring .fill{fill:none;stroke-width:10;stroke-linecap:round}
.score-center{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;flex-direction:column}
.score-number{font-size:2rem;font-weight:900;line-height:1}
.score-desc{font-size:.8125rem;font-weight:600}
.score-meta{display:flex;gap:1.5rem;font-size:.8125rem;text-align:center}
.score-meta strong{font-size:1.25rem;display:block}
.score-meta span{color:var(--c-muted);font-size:.75rem}
.sev-counts{display:grid;grid-template-columns:repeat(5,1fr);gap:.75rem;margin-bottom:.875rem}
.sev-cell{text-align:center;padding:.75rem .5rem;border-radius:.5rem}
.sev-cell .n{font-size:1.5rem;font-weight:900;display:block}
.sev-cell .lbl{font-size:.625rem;font-weight:700;opacity:.7;display:block;margin-top:.15rem;text-transform:uppercase;letter-spacing:.04em}
.sev-CRITICAL{background:#fff1f2;color:var(--c-critical)}
.sev-HIGH{background:#fff7ed;color:var(--c-high)}
.sev-MEDIUM{background:#fffbeb;color:var(--c-medium)}
.sev-LOW{background:#f7fee7;color:var(--c-low)}
.sev-INFO{background:#eff6ff;color:var(--c-info)}
.sev-bars{display:flex;flex-direction:column;gap:.4rem}
.sev-bar-row{display:flex;align-items:center;gap:.75rem;font-size:.8rem}
.sev-bar-lbl{width:68px;text-align:right;font-weight:600;font-size:.7rem;opacity:.7}
.sev-bar-track{flex:1;height:7px;background:#f1f5f9;border-radius:9999px;overflow:hidden}
.sev-bar-fill{height:100%;border-radius:9999px;min-width:2px}
.fill-CRITICAL{background:var(--c-critical)}
.fill-HIGH{background:var(--c-high)}
.fill-MEDIUM{background:var(--c-medium)}
.fill-LOW{background:var(--c-low)}
.fill-INFO{background:var(--c-info)}
.sev-bar-n{width:26px;font-size:.75rem;font-weight:700;color:var(--c-muted)}

/* ── Attack chains ── */
.chain-card{border-radius:.625rem;border-left:4px solid #94a3b8;overflow:hidden;margin-bottom:1.25rem;background:var(--c-card);box-shadow:0 1px 3px rgba(0,0,0,.07)}
.chain-card.CRITICAL{border-color:var(--c-critical)}
.chain-card.HIGH{border-color:var(--c-high)}
.chain-card.MEDIUM{border-color:var(--c-medium)}
.chain-card.LOW{border-color:var(--c-low)}
.chain-header{display:flex;align-items:center;gap:.75rem;padding:1rem 1.25rem;cursor:pointer;user-select:none}
.chain-header:hover{background:#f8fafc}
.chain-title{flex:1;font-weight:700;font-size:.9375rem}
.chain-cost{font-size:.8rem;color:var(--c-muted)}
.chain-chevron{color:var(--c-muted);transition:transform .2s;font-size:.875rem}
.chain-body{padding:0 1.25rem 1.25rem;border-top:1px solid var(--c-border)}
.chain-steps{display:flex;align-items:flex-start;flex-wrap:wrap;gap:0;margin:1rem 0}
.step-node{background:#f8fafc;border:1px solid var(--c-border);border-radius:.5rem;padding:.625rem .875rem;min-width:130px;max-width:195px}
.step-node-role{margin-bottom:.35rem}
.step-node-title{font-size:.8rem;font-weight:600;line-height:1.35;color:var(--c-text)}
.step-node-src{font-size:.7rem;color:var(--c-muted);margin-top:.25rem}
.step-arrow{display:flex;align-items:center;padding:0 .5rem;color:#94a3b8;font-size:1.125rem;align-self:center;padding-bottom:.875rem}
.chain-impact{font-size:.875rem;line-height:1.7;color:#334155;margin:.875rem 0;padding:.875rem 1rem;background:#f8fafc;border-radius:.375rem;border-left:3px solid #cbd5e1}
.chain-impact strong{color:var(--c-text)}
.remediation-list{display:flex;flex-direction:column;gap:.625rem;margin-top:.75rem}
.rem-item{display:flex;gap:.75rem;align-items:flex-start;padding:.75rem;border-radius:.375rem;border:1px solid var(--c-border)}
.rem-item.breaks{border-color:#86efac;background:#f0fdf4}
.rem-meta{display:flex;flex-direction:column;gap:.3rem;min-width:90px;flex-shrink:0}
.rem-summary{font-size:.875rem;flex:1}

/* ── Findings table ── */
.filter-bar{display:flex;gap:.625rem;margin-bottom:1rem;flex-wrap:wrap;align-items:center}
.filter-bar input,.filter-bar select{padding:.4rem .75rem;border:1px solid #cbd5e1;border-radius:.375rem;font-size:.8125rem;outline:none;background:#fff;color:var(--c-text)}
.filter-bar input:focus,.filter-bar select:focus{border-color:#94a3b8;box-shadow:0 0 0 3px rgba(148,163,184,.15)}
.filter-bar input{min-width:200px}
.filter-count{font-size:.8rem;color:var(--c-muted)}
.ftable{width:100%;border-collapse:collapse;font-size:.8125rem}
.ftable thead tr{background:#f1f5f9}
.ftable th{padding:.6rem .875rem;text-align:left;font-weight:700;font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;color:var(--c-muted);border-bottom:2px solid var(--c-border);white-space:nowrap}
.ftable td{padding:.6rem .875rem;border-bottom:1px solid #f1f5f9;vertical-align:middle}
.finding-row{cursor:pointer}
.finding-row:hover{background:#f8fafc}
.detail-row td{padding:0}
.finding-detail{padding:1rem 1.25rem 1.25rem;background:#f8fafc;border-bottom:1px solid var(--c-border);font-size:.8125rem}
.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:1.25rem}
.detail-label{font-weight:700;font-size:.7rem;color:var(--c-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:.3rem}
.triage-note{background:#f5f3ff;border-left:3px solid #8b5cf6;padding:.625rem .875rem;border-radius:0 .375rem .375rem 0;font-size:.8rem;color:#4c1d95;margin-top:.625rem;line-height:1.55}

/* ── Code blocks ── */
pre.code{background:var(--c-code-bg);color:var(--c-code-text);padding:.875rem 1rem;border-radius:.375rem;font-size:.78rem;overflow-x:auto;margin-top:.5rem;position:relative;white-space:pre-wrap;word-break:break-all}
.copy-btn{position:absolute;top:.5rem;right:.5rem;padding:.2rem .55rem;background:rgba(255,255,255,.08);color:#94a3b8;border:1px solid rgba(255,255,255,.1);border-radius:.25rem;font-size:.7rem;cursor:pointer}
.copy-btn:hover{background:rgba(255,255,255,.18);color:#e2e8f0}

/* ── Remediation playbook ── */
.effort-group{margin-bottom:2rem}
.effort-title{font-size:.875rem;font-weight:800;text-transform:uppercase;letter-spacing:.07em;margin-bottom:.875rem;display:flex;align-items:center;gap:.6rem}
.effort-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.dot-low{background:var(--c-low)}.dot-medium{background:var(--c-medium)}.dot-high{background:var(--c-critical)}

/* ── Compliance ── */
.comp-table{width:100%;border-collapse:collapse;font-size:.8125rem}
.comp-table th{padding:.55rem .875rem;text-align:left;background:#f1f5f9;border-bottom:2px solid var(--c-border);font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;color:var(--c-muted)}
.comp-table td{padding:.55rem .875rem;border-bottom:1px solid #f1f5f9}

/* ── Attack Graph ── */
.graph-canvas-wrap{background:#0f172a;border-radius:.5rem;overflow:hidden;position:relative;height:580px}
#cy-canvas{display:block;width:100%;height:100%;cursor:grab}
#cy-canvas:active{cursor:grabbing}
#cy-tip{position:absolute;display:none;pointer-events:none;background:#1e293b;border:1px solid rgba(255,255,255,.15);border-radius:6px;padding:8px 11px;font-size:.78rem;color:#f8fafc;max-width:240px;box-shadow:0 6px 20px rgba(0,0,0,.5);z-index:20;line-height:1.45}
#cy-tip .tip-type{font-size:.68rem;color:rgba(255,255,255,.4);margin-top:3px}
#cy-panel{position:absolute;right:0;top:0;bottom:0;width:260px;background:#1e293b;border-left:1px solid rgba(255,255,255,.08);overflow-y:auto;transform:translateX(100%);transition:transform .18s ease;z-index:10}
#cy-panel.open{transform:translateX(0)}
.cy-panel-head{padding:12px 14px 10px;border-bottom:1px solid rgba(255,255,255,.07);display:flex;align-items:flex-start;gap:8px}
.cy-panel-close{margin-left:auto;cursor:pointer;color:rgba(255,255,255,.3);font-size:1.1rem;padding:0 2px;flex-shrink:0;line-height:1}
.cy-panel-close:hover{color:#f8fafc}
.cy-panel-body{padding:12px 14px}
.cy-p-type{font-size:.65rem;text-transform:uppercase;letter-spacing:.09em;color:rgba(255,255,255,.3);margin-bottom:4px}
.cy-p-label{font-size:.8rem;font-weight:700;color:#f8fafc;line-height:1.4;word-break:break-all;margin-bottom:8px}
.cy-p-sec-title{font-size:.65rem;text-transform:uppercase;letter-spacing:.09em;color:rgba(255,255,255,.3);margin-bottom:5px;margin-top:10px}
.cy-p-arn{font-family:monospace;font-size:.72rem;color:#94a3b8;word-break:break-all;line-height:1.5}
.cy-p-nbr{font-size:.75rem;color:#94a3b8;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.05);display:flex;align-items:center;gap:5px}
.cy-p-nbr:last-child{border-bottom:none}
.cy-ndot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.cy-zoom-ctrls{position:absolute;top:10px;right:10px;display:flex;flex-direction:column;gap:4px;z-index:5}
.cy-btn{padding:3px 8px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);color:#94a3b8;border-radius:4px;font-size:.75rem;cursor:pointer;transition:background .12s,color .12s}
.cy-btn:hover{background:rgba(255,255,255,.12);color:#f8fafc}
.graph-link{display:inline-block;margin-top:.625rem;font-size:.8125rem;color:#60a5fa}
.graph-link:hover{color:#93c5fd}
.graph-legend{display:flex;flex-wrap:wrap;gap:.5rem 1rem;margin-top:.875rem;font-size:.75rem;color:var(--c-muted)}
.legend-dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:.35rem;vertical-align:middle}
.legend-line{display:inline-block;width:18px;height:2px;margin-right:.35rem;vertical-align:middle}
.legend-dashed{background:repeating-linear-gradient(90deg,#dc2626 0 5px,transparent 5px 8px)}

/* ── Responsive ── */
@media(max-width:900px){
  .layout{grid-template-columns:1fr}
  .sidebar{display:none}
  .main{padding:1.25rem}
  .summary-grid{grid-template-columns:1fr}
  .detail-grid{grid-template-columns:1fr}
  .chain-steps{flex-direction:column}
  .step-arrow{transform:rotate(90deg)}
}
</style>
</head>
<body>
<div class="layout">

<!-- ══════════ Sidebar ══════════ -->
<aside class="sidebar">
  <div class="sidebar-logo">
    <span class="name">Project Clementine</span>
    <span class="sub">Security Assessment Report</span>
  </div>
  <div class="nav-group">Report</div>
  <a class="nav-item" href="#summary">Executive Summary</a>
  {% if chain_data %}
  <a class="nav-item" href="#chains">
    Attack Chains
    <span class="nav-badge red">{{ chain_data|length }}</span>
  </a>
  {% endif %}
  <a class="nav-item" href="#findings">
    Findings
    <span class="nav-badge">{{ findings|length }}</span>
  </a>
  <a class="nav-item" href="#playbook">Remediation Playbook</a>
  {% if compliance_rows %}
  <a class="nav-item" href="#compliance">Compliance</a>
  {% endif %}
  {% if graph_json != '{}' %}
  <a class="nav-item" href="#attack-graph">Attack Graph</a>
  {% endif %}
  <div class="sidebar-footer">
    {{ generated_at }}<br>
    {{ target_url }}
  </div>
</aside>

<!-- ══════════ Main ══════════ -->
<div class="main">
<header class="page-header">
  <h1>Security Assessment Report</h1>
  <div class="meta">
    Target: <strong>{{ target_url }}</strong>
    &nbsp;&bull;&nbsp; {{ generated_at }}
    {% if health_score != 'N/A' %}
    &nbsp;&bull;&nbsp; Cloud Health Score: <strong>{{ health_score }}/100</strong>
    {% endif %}
  </div>
</header>

<!-- ── Executive Summary ── -->
<section class="section" id="summary">
  <div class="section-title">Executive Summary</div>
  <div class="summary-grid">
    <div class="card card-pad score-card">
      <div class="score-ring">
        <svg viewBox="0 0 110 110">
          <circle class="track" cx="55" cy="55" r="45"/>
          <circle class="fill" cx="55" cy="55" r="45"
            stroke="{{ risk_color }}"
            stroke-dasharray="{{ risk_dash }} {{ circ }}"
            stroke-dashoffset="0"/>
        </svg>
        <div class="score-center">
          <span class="score-number" style="color:{{ risk_color }}">{{ risk_score }}</span>
          <span style="font-size:.65rem;color:var(--c-muted)">/ 100</span>
        </div>
      </div>
      <span class="score-desc" style="color:{{ risk_color }}">{{ risk_label }}</span>
      <div class="score-meta">
        <div><strong>{{ chain_data|length }}</strong><span>Attack Chains</span></div>
        <div><strong>{{ findings|length }}</strong><span>Findings</span></div>
      </div>
    </div>
    <div class="card card-pad">
      <div class="sev-counts">
        {% for sev in ['CRITICAL','HIGH','MEDIUM','LOW','INFO'] %}
        <div class="sev-cell sev-{{ sev }}">
          <span class="n">{{ severity_counts[sev] }}</span>
          <span class="lbl">{{ sev }}</span>
        </div>
        {% endfor %}
      </div>
      <div class="sev-bars">
        {% for sev in ['CRITICAL','HIGH','MEDIUM','LOW','INFO'] %}
        {% set pct = (severity_counts[sev] / total_findings * 100)|int if total_findings > 0 else 0 %}
        <div class="sev-bar-row">
          <span class="sev-bar-lbl">{{ sev }}</span>
          <div class="sev-bar-track">
            <div class="sev-bar-fill fill-{{ sev }}" style="width:{{ pct }}%"></div>
          </div>
          <span class="sev-bar-n">{{ severity_counts[sev] }}</span>
        </div>
        {% endfor %}
      </div>
    </div>
  </div>

  {% if top5 %}
  <div class="card" style="overflow:hidden">
    <table class="ftable">
      <thead><tr><th>Severity</th><th>Top Finding</th><th>Source</th><th>Category</th></tr></thead>
      <tbody>
      {% for f in top5 %}
      <tr>
        <td><span class="badge badge-{{ f.severity.value }}">{{ f.severity.value }}</span></td>
        <td style="font-weight:600">{{ f.title }}</td>
        <td style="color:var(--c-muted)">{{ f.source }}</td>
        <td style="color:var(--c-muted);font-size:.8rem">{{ f.category }}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}
</section>

<!-- ── Attack Chains ── -->
{% if chain_data %}
<section class="section" id="chains">
  <div class="section-title">
    Attack Chains
    <span class="section-subtitle">{{ chain_data|length }} compound attack path{{ 's' if chain_data|length != 1 }}</span>
  </div>
  {% for cd in chain_data %}
  {% set chain = cd.chain %}
  <div class="chain-card {{ chain.severity.value }}" id="chain-{{ loop.index }}">
    <div class="chain-header" onclick="toggleChain({{ loop.index }})">
      <span class="badge badge-{{ chain.severity.value }}">{{ chain.severity.value }}</span>
      <span class="chain-title">{{ chain.pattern_name }}</span>
      {% if chain.chain_source == 'ai-discovered' %}
        <span class="badge badge-ai">&#x1F916; AI-discovered</span>
      {% else %}
        <span class="badge" style="background:#f1f5f9;color:#64748b">Rule</span>
      {% endif %}
      {% if chain.breach_cost_low %}
      <span class="chain-cost">~${{ "{:,.0f}".format(chain.breach_cost_low) }}&ndash;${{ "{:,.0f}".format(chain.breach_cost_high) }}</span>
      {% endif %}
      <span class="chain-chevron" id="chev-{{ loop.index }}">&#9660;</span>
    </div>
    <div class="chain-body" id="cbody-{{ loop.index }}" style="display:none">
      {% if cd.components %}
      <div class="chain-steps">
        {% for comp_finding, role, order in cd.components %}
        {% if not loop.first %}<div class="step-arrow">&#8594;</div>{% endif %}
        <div class="step-node">
          <div class="step-node-role"><span class="badge badge-{{ role.value }}">{{ role.value }}</span></div>
          <div class="step-node-title">{{ comp_finding.title | truncate(52) }}</div>
          <div class="step-node-src">{{ comp_finding.source }} &middot; {{ comp_finding.category | truncate(22) }}</div>
        </div>
        {% endfor %}
      </div>
      {% endif %}
      <div class="chain-impact">{{ chain.narrative | md_bold | safe }}</div>
      {% if cd.actions %}
      <div style="margin-top:1.125rem">
        <div style="font-size:.75rem;font-weight:700;color:var(--c-muted);text-transform:uppercase;letter-spacing:.07em;margin-bottom:.625rem">Remediation Steps</div>
        <div class="remediation-list">
          {% for action in cd.actions %}
          <div class="rem-item {{ 'breaks' if action.breaks_chain }}">
            <div class="rem-meta">
              <span class="badge badge-{{ action.effort_level.value.lower() }}"
                style="background:{% if action.effort_level.value=='LOW' %}#d1fae5;color:#065f46{% elif action.effort_level.value=='MEDIUM' %}#dbeafe;color:#1e40af{% else %}#fce7f3;color:#be185d{% endif %}">
                {{ action.effort_level.value }}
              </span>
              {% if action.breaks_chain %}
              <span class="badge badge-breaks">&#10003; Breaks Chain</span>
              {% endif %}
            </div>
            <div class="rem-summary">
              {{ action.action_summary }}
              {% if action.cli_command %}
              <div style="position:relative">
                <pre class="code">{{ action.cli_command }}</pre>
                <button class="copy-btn" onclick="copyPre(this)">copy</button>
              </div>
              {% endif %}
              {% if action.iac_snippet %}
              <div style="position:relative">
                <pre class="code">{{ action.iac_snippet }}</pre>
                <button class="copy-btn" onclick="copyPre(this)">copy</button>
              </div>
              {% endif %}
            </div>
          </div>
          {% endfor %}
        </div>
      </div>
      {% endif %}
    </div>
  </div>
  {% endfor %}
</section>
{% endif %}

<!-- ── Findings ── -->
<section class="section" id="findings">
  <div class="section-title">Findings</div>
  <div class="filter-bar">
    <input type="text" id="search" placeholder="Search findings&hellip;" oninput="applyFilters()">
    <select id="sev-filter" onchange="applyFilters()">
      <option value="">All Severities</option>
      {% for s in ['CRITICAL','HIGH','MEDIUM','LOW','INFO'] %}<option>{{ s }}</option>{% endfor %}
    </select>
    <select id="src-filter" onchange="applyFilters()">
      <option value="">All Sources</option>
      {% for s in sources %}<option>{{ s }}</option>{% endfor %}
    </select>
    <select id="cat-filter" onchange="applyFilters()">
      <option value="">All Categories</option>
      {% for c in categories %}<option>{{ c }}</option>{% endfor %}
    </select>
    <span class="filter-count" id="fcount"></span>
  </div>
  <div class="card" style="overflow:hidden">
    <table class="ftable" id="ftable">
      <thead><tr>
        <th>Severity</th><th>Title</th><th>Category</th>
        <th>Source</th><th>Resource</th><th>Triage</th>
      </tr></thead>
      <tbody>
      {% for f in findings %}
      <tr class="finding-row"
          data-id="{{ f.id }}"
          data-severity="{{ f.severity.value }}"
          data-source="{{ f.source }}"
          data-category="{{ f.category }}"
          data-search="{{ (f.title ~ ' ' ~ f.description ~ ' ' ~ f.category ~ ' ' ~ (f.resource_id or '') ~ ' ' ~ f.source) | lower }}"
          onclick="toggleFinding(this.dataset.id)">
        <td><span class="badge badge-{{ f.severity.value }}">{{ f.severity.value }}</span></td>
        <td style="font-weight:600;max-width:310px">{{ f.title }}</td>
        <td style="color:var(--c-muted);font-size:.8rem">{{ f.category }}</td>
        <td style="color:var(--c-muted)">{{ f.source }}</td>
        <td style="font-size:.75rem;color:var(--c-muted);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
          {{ f.resource_id or '&mdash;' }}
        </td>
        <td>
          {% if f.triage_confidence is not none %}
            {% if f.triage_is_false_positive %}
              <span class="badge badge-fp">FP</span>
            {% else %}
              <span class="badge badge-conf">{{ (f.triage_confidence * 100)|int }}%</span>
            {% endif %}
          {% else %}&mdash;{% endif %}
        </td>
      </tr>
      <tr class="detail-row" id="detail-{{ f.id }}" style="display:none">
        <td colspan="6">
          <div class="finding-detail">
            <div class="detail-grid">
              <div>
                <div class="detail-label">Description</div>
                <div style="line-height:1.7">{{ f.description }}</div>
                {% if f.remediation_summary %}
                <div class="detail-label" style="margin-top:.875rem">Remediation</div>
                <div>{{ f.remediation_summary }}</div>
                {% endif %}
                {% if f.triage_notes %}
                <div class="triage-note">&#x1F916; <strong>AI Triage:</strong> {{ f.triage_notes }}</div>
                {% endif %}
              </div>
              <div>
                {% if f.resource_id %}
                <div class="detail-label">Resource</div>
                <div style="font-family:monospace;font-size:.8rem;word-break:break-all;margin-bottom:.75rem">{{ f.resource_id }}</div>
                {% endif %}
                {% if f.aws_account_id %}
                <div class="detail-label">AWS Account</div>
                <div style="font-family:monospace;font-size:.8rem;margin-bottom:.75rem">
                  {{ f.aws_account_id }}{% if f.aws_region %} ({{ f.aws_region }}){% endif %}
                </div>
                {% endif %}
                {% if f.remediation_cli %}
                <div class="detail-label">CLI Fix</div>
                <div style="position:relative">
                  <pre class="code">{{ f.remediation_cli }}</pre>
                  <button class="copy-btn" onclick="copyPre(this)">copy</button>
                </div>
                {% endif %}
                {% if f.remediation_iac %}
                <div class="detail-label" style="margin-top:.75rem">IaC Snippet</div>
                <div style="position:relative">
                  <pre class="code">{{ f.remediation_iac }}</pre>
                  <button class="copy-btn" onclick="copyPre(this)">copy</button>
                </div>
                {% endif %}
              </div>
            </div>
          </div>
        </td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
</section>

<!-- ── Remediation Playbook ── -->
<section class="section" id="playbook">
  <div class="section-title">Remediation Playbook</div>
  {% for effort_key, effort_label, dot_class in [('LOW','Quick Wins','low'),('MEDIUM','Medium Effort','medium'),('HIGH','High Effort','high')] %}
  {% set items = playbook[effort_key] %}
  {% if items %}
  <div class="effort-group">
    <div class="effort-title">
      <span class="effort-dot dot-{{ dot_class }}"></span>
      {{ effort_label }}
      <span style="font-weight:400;font-size:.8rem;color:var(--c-muted)">({{ items|length }} action{{ 's' if items|length != 1 }})</span>
    </div>
    <div class="card" style="overflow:hidden">
      <div class="remediation-list" style="padding:1rem 1.25rem">
        {% for item in items %}
        <div class="rem-item {{ 'breaks' if item.breaks_chain }}">
          <div class="rem-meta">
            {% if item.breaks_chain %}<span class="badge badge-breaks">&#10003; Breaks Chain</span>{% endif %}
            <span style="font-size:.72rem;color:var(--c-muted);line-height:1.35">{{ item.chain_name }}</span>
          </div>
          <div class="rem-summary">
            {{ item.action_summary }}
            {% if item.cli_command %}
            <div style="position:relative">
              <pre class="code">{{ item.cli_command }}</pre>
              <button class="copy-btn" onclick="copyPre(this)">copy</button>
            </div>
            {% endif %}
          </div>
        </div>
        {% endfor %}
      </div>
    </div>
  </div>
  {% endif %}
  {% endfor %}
</section>

<!-- ── Compliance Mapping ── -->
{% if compliance_rows %}
<section class="section" id="compliance">
  <div class="section-title">Compliance Mapping</div>
  <div class="card" style="overflow:hidden">
    <table class="comp-table">
      <thead><tr><th>Finding</th><th>Framework</th><th>Control</th></tr></thead>
      <tbody>
      {% for row in compliance_rows %}
      <tr>
        <td>{{ row.title }}</td>
        <td><span class="badge badge-INFO">{{ row.framework }}</span></td>
        <td style="font-family:monospace;font-size:.8rem">{{ row.control }}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
</section>
{% endif %}

{% if graph_json != '{}' %}
<!-- ── Attack Graph ── -->
<section class="section" id="attack-graph">
  <div class="section-title">Attack Graph</div>
  <div class="card card-pad">
    <div style="font-size:.8125rem;color:var(--c-muted);margin-bottom:.875rem">
      Multi-hop attack surface &mdash; nodes represent AWS resources and principals; edges represent permissions, trust relationships, and exploit paths.
      Hover to highlight connections. Click a node for details. Scroll to zoom. Drag to pan.
    </div>
    <div class="graph-canvas-wrap">
      <canvas id="cy-canvas"></canvas>
      <div id="cy-tip"></div>
      <div class="cy-zoom-ctrls">
        <button class="cy-btn" onclick="_gZoomBy(1.25)">+</button>
        <button class="cy-btn" onclick="_gZoomBy(0.8)">&minus;</button>
        <button class="cy-btn" onclick="_gZoomFit()" style="font-size:.68rem">Fit</button>
      </div>
      <div id="cy-panel">
        <div class="cy-panel-head">
          <div>
            <div class="cy-p-type" id="cy-p-type"></div>
            <div class="cy-p-label" id="cy-p-label"></div>
            <div id="cy-p-badges"></div>
          </div>
          <span class="cy-panel-close" onclick="_gClosePanel()">&#x2715;</span>
        </div>
        <div class="cy-panel-body">
          <div class="cy-p-sec-title">Resource ID</div>
          <div class="cy-p-arn" id="cy-p-arn"></div>
          <div id="cy-p-nbr-wrap">
            <div class="cy-p-sec-title">Connected nodes</div>
            <div id="cy-p-neighbors"></div>
          </div>
        </div>
      </div>
    </div>
    {% if graph_path %}
    <a class="graph-link" href="{{ graph_path }}">Open full graph &#x2192;</a>
    {% endif %}
    <div class="graph-legend">
      <span><span class="legend-dot" style="background:#7c3aed"></span>IAM / Principal</span>
      <span><span class="legend-dot" style="background:#2563eb"></span>Compute (EC2 / EKS)</span>
      <span><span class="legend-dot" style="background:#16a34a"></span>Storage / Secrets</span>
      <span><span class="legend-dot" style="background:#d97706"></span>Lambda</span>
      <span><span class="legend-dot" style="background:#dc2626"></span>Web / IMDS</span>
      <span><span class="legend-dot" style="background:#0891b2"></span>Network</span>
      <span><span class="legend-line legend-dashed"></span>Exploit path (SSRF / Internet)</span>
    </div>
  </div>
</section>
{% endif %}

</div><!-- /main -->
</div><!-- /layout -->

<script>
// Toggle attack chain body
function toggleChain(n) {
  const body = document.getElementById('cbody-' + n);
  const chev = document.getElementById('chev-' + n);
  const open = body.style.display !== 'none';
  body.style.display = open ? 'none' : 'block';
  chev.style.transform = open ? '' : 'rotate(180deg)';
}

// Toggle finding detail row
function toggleFinding(id) {
  const row = document.getElementById('detail-' + id);
  if (!row) return;
  const open = row.style.display !== 'none';
  row.style.display = open ? 'none' : '';
}

// Filter findings table
function applyFilters() {
  const search = (document.getElementById('search').value || '').toLowerCase();
  const sev = document.getElementById('sev-filter').value;
  const src = document.getElementById('src-filter').value;
  const cat = document.getElementById('cat-filter').value;
  let visible = 0;
  document.querySelectorAll('tr.finding-row').forEach(row => {
    const match =
      (!sev || row.dataset.severity === sev) &&
      (!src || row.dataset.source === src) &&
      (!cat || row.dataset.category === cat) &&
      (!search || row.dataset.search.includes(search));
    row.style.display = match ? '' : 'none';
    const detail = document.getElementById('detail-' + row.dataset.id);
    if (!match && detail) detail.style.display = 'none';
    if (match) visible++;
  });
  const total = document.querySelectorAll('tr.finding-row').length;
  document.getElementById('fcount').textContent =
    visible < total ? `Showing ${visible} of ${total}` : `${total} findings`;
}

// Copy code block text
function copyPre(btn) {
  const pre = btn.previousElementSibling;
  navigator.clipboard.writeText(pre.textContent.trim()).then(() => {
    btn.textContent = 'copied!';
    setTimeout(() => { btn.textContent = 'copy'; }, 1600);
  });
}

// ── Attack Graph renderer ──
{% if graph_json != '{}' %}
(function() {
  var _gdata   = {{ graph_json | safe }};
  var _gnodes  = (_gdata.elements.nodes || []).map(function(n) {
    return Object.assign({}, n.data, {vx:0, vy:0, x:0, y:0});
  });
  var _gedges  = (_gdata.elements.edges || []).map(function(e) { return e.data; });
  var _gmap    = {};
  _gnodes.forEach(function(n) { _gmap[n.id] = n; });

  var _canvas = document.getElementById('cy-canvas');
  if (!_canvas || !_gnodes.length) return;
  var _ctx    = _canvas.getContext('2d');
  var _tip    = document.getElementById('cy-tip');
  var _panel  = document.getElementById('cy-panel');

  function _gResize() {
    _canvas.width  = _canvas.offsetWidth  || 900;
    _canvas.height = _canvas.offsetHeight || 580;
  }

  // Cluster anchors: type → [x_fraction, y_fraction]
  var _CLUSTER = {
    iam_role:           [0.12, 0.40],
    iam_user:           [0.12, 0.62],
    eks_service_account:[0.18, 0.28],
    ec2_instance:       [0.40, 0.30],
    eks_node:           [0.48, 0.22],
    eks_pod:            [0.55, 0.28],
    lambda_function:    [0.70, 0.22],
    s3_bucket:          [0.76, 0.68],
    rds_instance:       [0.55, 0.72],
    secrets_manager:    [0.88, 0.42],
    ssm_parameter:      [0.88, 0.60],
    vpc:                [0.25, 0.18],
    security_group:     [0.35, 0.14],
    vpc_endpoint:       [0.22, 0.52],
    web_endpoint:       [0.44, 0.68],
    imds:               [0.58, 0.50],
  };

  var _REP_K = 220, _SPRING_K = 110, _DAMP = 0.80;
  var _gzoom = 1, _gpanX = 0, _gpanY = 0;
  var _gtick = 0;
  var _gHovNode = null, _gSelNode = null;
  var _gDragging = false, _glmx = 0, _glmy = 0;

  function _gInitPos() {
    var W = _canvas.width, H = _canvas.height;
    var cols = Math.ceil(Math.sqrt(_gnodes.length * (W / H)));
    var cw = W / (cols + 1), ch = H / (Math.ceil(_gnodes.length / cols) + 1);
    _gnodes.forEach(function(n, i) {
      var col = i % cols, row = Math.floor(i / cols);
      n.x  = (col + 1) * cw + (Math.random() - .5) * cw * .5;
      n.y  = (row + 1) * ch + (Math.random() - .5) * ch * .5;
      n.vx = 0; n.vy = 0;
    });
    _gtick = 0;
  }

  function _gSimulate() {
    if (_gtick > 400) return;
    _gtick++;
    var W = _canvas.width, H = _canvas.height;
    var i, j, dx, dy, d, minD, fMag, fx, fy;
    for (i = 0; i < _gnodes.length; i++) {
      for (j = i + 1; j < _gnodes.length; j++) {
        dx = _gnodes[j].x - _gnodes[i].x || .01;
        dy = _gnodes[j].y - _gnodes[i].y || .01;
        d  = Math.sqrt(dx * dx + dy * dy) || .01;
        if (d > 400) continue;
        minD = (_gnodes[i].radius || 10) + (_gnodes[j].radius || 10) + 22;
        fMag = d < minD ? _REP_K * _REP_K * 6 / d : _REP_K * _REP_K / d;
        fx = fMag * dx / d; fy = fMag * dy / d;
        _gnodes[i].vx -= fx; _gnodes[i].vy -= fy;
        _gnodes[j].vx += fx; _gnodes[j].vy += fy;
      }
    }
    _gedges.forEach(function(e) {
      var s = _gmap[e.source], t = _gmap[e.target];
      if (!s || !t) return;
      var edx = t.x - s.x, edy = t.y - s.y;
      var ed  = Math.sqrt(edx * edx + edy * edy) || 1;
      var ef  = (ed - _SPRING_K) / ed * 0.09;
      s.vx += ef * edx; s.vy += ef * edy;
      t.vx -= ef * edx; t.vy -= ef * edy;
    });
    _gnodes.forEach(function(n) {
      var cl = _CLUSTER[n.type] || [.5, .5];
      n.vx += (cl[0] * W - n.x) * .008;
      n.vy += (cl[1] * H - n.y) * .008;
      n.vx *= _DAMP; n.vy *= _DAMP;
      var r = (n.radius || 10) + 8;
      n.x = Math.max(r, Math.min(W - r, n.x + n.vx));
      n.y = Math.max(r, Math.min(H - r, n.y + n.vy));
    });
  }

  function _gNbrSet(nodeId) {
    var s = {};
    s[nodeId] = true;
    _gedges.forEach(function(e) {
      if (e.source === nodeId) s[e.target] = true;
      if (e.target === nodeId) s[e.source] = true;
    });
    return s;
  }

  function _gDraw() {
    var W = _canvas.width, H = _canvas.height;
    _ctx.clearRect(0, 0, W, H);
    _ctx.save();
    _ctx.translate(_gpanX, _gpanY);
    _ctx.scale(_gzoom, _gzoom);

    var nbrs = _gHovNode ? _gNbrSet(_gHovNode.id) : null;

    _gedges.forEach(function(e) {
      var s = _gmap[e.source], t = _gmap[e.target];
      if (!s || !t) return;
      var hi = _gHovNode && (e.source === _gHovNode.id || e.target === _gHovNode.id);
      _ctx.globalAlpha = hi ? .92 : (_gHovNode ? .12 : .42);
      _ctx.beginPath();
      _ctx.setLineDash(e.dashed ? [5, 3] : []);
      _ctx.moveTo(s.x, s.y);
      _ctx.lineTo(t.x, t.y);
      _ctx.strokeStyle = e.color || '#475569';
      _ctx.lineWidth   = hi ? 2.5 / _gzoom : 1.5 / _gzoom;
      _ctx.stroke();
      if (hi) {
        var angle = Math.atan2(t.y - s.y, t.x - s.x);
        var tr = (t.radius || 10) + 4;
        var ax = t.x - tr * Math.cos(angle), ay = t.y - tr * Math.sin(angle);
        _ctx.setLineDash([]);
        _ctx.beginPath();
        _ctx.moveTo(ax, ay);
        _ctx.lineTo(ax - 9 * Math.cos(angle - .4), ay - 9 * Math.sin(angle - .4));
        _ctx.lineTo(ax - 9 * Math.cos(angle + .4), ay - 9 * Math.sin(angle + .4));
        _ctx.closePath();
        _ctx.fillStyle = e.color || '#475569';
        _ctx.fill();
      }
    });
    _ctx.setLineDash([]);
    _ctx.globalAlpha = 1;

    _gnodes.forEach(function(n) {
      var r    = n.radius || 10;
      var isHov = _gHovNode && _gHovNode.id === n.id;
      var isSel = _gSelNode && _gSelNode.id === n.id;
      var dim   = nbrs && !nbrs[n.id];
      _ctx.globalAlpha = dim ? .18 : 1;

      if (isSel) {
        _ctx.beginPath();
        _ctx.arc(n.x, n.y, r + 6, 0, Math.PI * 2);
        _ctx.strokeStyle = '#f8fafc';
        _ctx.lineWidth   = 2 / _gzoom;
        _ctx.stroke();
      }
      _ctx.beginPath();
      _ctx.arc(n.x, n.y, isHov ? r + 3 : r, 0, Math.PI * 2);
      _ctx.fillStyle = n.color || '#94a3b8';
      _ctx.fill();
      if (n.border_color && n.border_color !== '#94a3b8') {
        _ctx.strokeStyle = n.border_color;
        _ctx.lineWidth   = (isHov ? 3 : 2) / _gzoom;
        _ctx.stroke();
      }
      if (n.internet_facing) {
        _ctx.beginPath();
        _ctx.arc(n.x + r * .65, n.y - r * .65, 3.5, 0, Math.PI * 2);
        _ctx.fillStyle = '#f8fafc';
        _ctx.fill();
      }
    });
    _ctx.globalAlpha = 1;
    _ctx.restore();
  }

  window._gZoomFit = function() {
    if (!_gnodes.length) return;
    var x0 = Infinity, x1 = -Infinity, y0 = Infinity, y1 = -Infinity;
    _gnodes.forEach(function(n) {
      var r = (n.radius || 10) + 4;
      if (n.x - r < x0) x0 = n.x - r;
      if (n.x + r > x1) x1 = n.x + r;
      if (n.y - r < y0) y0 = n.y - r;
      if (n.y + r > y1) y1 = n.y + r;
    });
    var W = _canvas.width, H = _canvas.height, pad = 40;
    var sx = (W - pad * 2) / (x1 - x0 || 1);
    var sy = (H - pad * 2) / (y1 - y0 || 1);
    _gzoom = Math.min(sx, sy, 3);
    _gpanX = pad - x0 * _gzoom + ((W - pad * 2) - (x1 - x0) * _gzoom) / 2;
    _gpanY = pad - y0 * _gzoom + ((H - pad * 2) - (y1 - y0) * _gzoom) / 2;
  };

  window._gZoomBy = function(factor) {
    var cx = _canvas.width / 2, cy = _canvas.height / 2;
    var nz = Math.max(.2, Math.min(5, _gzoom * factor));
    _gpanX = cx - (cx - _gpanX) * (nz / _gzoom);
    _gpanY = cy - (cy - _gpanY) * (nz / _gzoom);
    _gzoom = nz;
  };

  function _gHit(ox, oy) {
    var wx = (ox - _gpanX) / _gzoom, wy = (oy - _gpanY) / _gzoom;
    for (var i = _gnodes.length - 1; i >= 0; i--) {
      var n = _gnodes[i], r = (n.radius || 10) + 5;
      if ((wx - n.x) * (wx - n.x) + (wy - n.y) * (wy - n.y) <= r * r) return n;
    }
    return null;
  }

  var _SEV_BG = {CRITICAL:'#fee2e2',HIGH:'#ffedd5',MEDIUM:'#fef3c7',LOW:'#ecfccb',INFO:'#dbeafe'};
  var _SEV_FG = {CRITICAL:'#dc2626',HIGH:'#ea580c',MEDIUM:'#d97706',LOW:'#65a30d',INFO:'#2563eb'};
  var _NC = {
    iam_role:'#7c3aed',iam_user:'#7c3aed',eks_service_account:'#7c3aed',
    ec2_instance:'#2563eb',eks_pod:'#2563eb',eks_node:'#2563eb',
    s3_bucket:'#16a34a',rds_instance:'#16a34a',secrets_manager:'#16a34a',ssm_parameter:'#16a34a',
    lambda_function:'#d97706',vpc:'#0891b2',security_group:'#0891b2',vpc_endpoint:'#0891b2',
    web_endpoint:'#dc2626',imds:'#dc2626',
  };

  function _gOpenPanel(n) {
    _gSelNode = n;
    document.getElementById('cy-p-type').textContent  = (n.type || '').replace(/_/g, ' ');
    document.getElementById('cy-p-label').textContent = n.label || n.id;
    var badges = document.getElementById('cy-p-badges');
    badges.innerHTML = '';
    if (n.severity) {
      var b = document.createElement('span');
      b.className = 'badge badge-' + n.severity;
      b.textContent = n.severity;
      badges.appendChild(b);
    }
    if (n.internet_facing) {
      var b2 = document.createElement('span');
      b2.className = 'badge';
      b2.style.cssText = 'background:#fef3c7;color:#b45309;margin-left:6px';
      b2.textContent = 'INTERNET-FACING';
      badges.appendChild(b2);
    }
    document.getElementById('cy-p-arn').textContent = n.id;
    var nbrsEl = document.getElementById('cy-p-neighbors');
    nbrsEl.innerHTML = '';
    _gedges.forEach(function(e) {
      var other = null, dir = '';
      if (e.source === n.id) { other = _gmap[e.target]; dir = '\u2192 '; }
      if (e.target === n.id) { other = _gmap[e.source]; dir = '\u2190 '; }
      if (!other) return;
      var row = document.createElement('div');
      row.className = 'cy-p-nbr';
      var dot = document.createElement('span');
      dot.className = 'cy-ndot';
      dot.style.background = _NC[other.type] || '#94a3b8';
      row.appendChild(dot);
      var txt = document.createElement('span');
      txt.style.flex = '1';
      txt.textContent = dir + (other.label || other.id).slice(0, 30);
      row.appendChild(txt);
      var rel = document.createElement('span');
      rel.style.cssText = 'font-size:.65rem;color:rgba(255,255,255,.3)';
      rel.textContent = e.label || '';
      row.appendChild(rel);
      nbrsEl.appendChild(row);
    });
    document.getElementById('cy-p-nbr-wrap').style.display = nbrsEl.children.length ? '' : 'none';
    _panel.classList.add('open');
  }

  window._gClosePanel = function() {
    _panel.classList.remove('open');
    _gSelNode = null;
  };

  _canvas.addEventListener('mousedown', function(e) {
    _gDragging = true; _glmx = e.offsetX; _glmy = e.offsetY;
  });
  _canvas.addEventListener('mouseup', function(e) {
    if (!_gDragging) return;
    var moved = Math.abs(e.offsetX - _glmx) + Math.abs(e.offsetY - _glmy);
    _gDragging = false;
    if (moved < 4) {
      var n = _gHit(e.offsetX, e.offsetY);
      if (n) _gOpenPanel(n); else _gClosePanel();
    }
  });
  _canvas.addEventListener('mouseleave', function() {
    _gDragging = false; _gHovNode = null;
    if (_tip) _tip.style.display = 'none';
  });
  _canvas.addEventListener('mousemove', function(e) {
    if (_gDragging) {
      _gpanX += e.offsetX - _glmx; _gpanY += e.offsetY - _glmy;
      _glmx = e.offsetX; _glmy = e.offsetY;
      return;
    }
    var n = _gHit(e.offsetX, e.offsetY);
    _gHovNode = n;
    if (n && _tip) {
      _canvas.style.cursor = 'pointer';
      var tx = Math.min(e.offsetX + 14, _canvas.offsetWidth - 250);
      var ty = Math.max(e.offsetY - 50, 4);
      _tip.style.left = tx + 'px'; _tip.style.top = ty + 'px';
      _tip.style.display = 'block';
      var sev = n.severity;
      _tip.innerHTML =
        '<strong style="color:#f8fafc">' + (n.label || n.id).slice(0, 48) + '</strong>' +
        '<div class="tip-type">' + (n.type || '').replace(/_/g, ' ') +
        (sev ? ' &middot; <span style="background:' + (_SEV_BG[sev]||'') + ';color:' + (_SEV_FG[sev]||'') +
               ';padding:1px 6px;border-radius:9999px;font-size:.65rem;font-weight:700">' + sev + '</span>' : '') +
        '</div>';
    } else {
      _canvas.style.cursor = _gDragging ? 'grabbing' : 'grab';
      if (_tip) _tip.style.display = 'none';
    }
  });
  _canvas.addEventListener('wheel', function(e) {
    e.preventDefault();
    var factor = e.deltaY < 0 ? 1.12 : 1 / 1.12;
    var nz = Math.max(.15, Math.min(6, _gzoom * factor));
    _gpanX = e.offsetX - (e.offsetX - _gpanX) * (nz / _gzoom);
    _gpanY = e.offsetY - (e.offsetY - _gpanY) * (nz / _gzoom);
    _gzoom = nz;
  }, {passive: false});

  window.addEventListener('resize', function() { _gResize(); _gInitPos(); });

  _gResize();
  _gInitPos();
  for (var _pi = 0; _pi < 280; _pi++) _gSimulate();
  window._gZoomFit();

  (function _gLoop() { _gSimulate(); _gDraw(); requestAnimationFrame(_gLoop); })();
})();
{% endif %}

// Highlight active sidebar link on scroll
const _navSections = ['summary','chains','findings','playbook','compliance','attack-graph'];
const _navObserver = new IntersectionObserver(entries => {
  entries.forEach(e => {
    if (e.isIntersecting) {
      document.querySelectorAll('.nav-item').forEach(a => a.classList.remove('active'));
      const link = document.querySelector('.nav-item[href="#' + e.target.id + '"]');
      if (link) link.classList.add('active');
    }
  });
}, { rootMargin: '-20% 0px -70% 0px' });
_navSections.forEach(id => { const el = document.getElementById(id); if (el) _navObserver.observe(el); });

// Initial filter count
document.addEventListener('DOMContentLoaded', applyFilters);
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Full-size graph page template
# ---------------------------------------------------------------------------

_GRAPH_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Attack Graph &mdash; {{ target_url }}</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:#0f172a;color:#e2e8f0;font-family:system-ui,-apple-system,sans-serif;height:100vh;overflow:hidden;display:flex;flex-direction:column}
.hdr{display:flex;align-items:center;gap:12px;padding:9px 18px;background:#1e293b;border-bottom:1px solid rgba(255,255,255,.09);flex-shrink:0}
.hdr-title{font-size:.875rem;font-weight:700;color:#f8fafc}
.hdr-sub{font-size:.75rem;color:rgba(255,255,255,.35)}
.hdr-sep{width:1px;height:18px;background:rgba(255,255,255,.1);margin:0 2px}
.hdr-stat{font-size:.75rem;color:rgba(255,255,255,.4);padding:2px 8px;background:rgba(255,255,255,.06);border-radius:9999px}
.hdr-stat strong{color:#f8fafc}
.ctrl{display:flex;align-items:center;gap:6px;margin-left:auto}
.btn{padding:4px 12px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);color:#94a3b8;border-radius:4px;font-size:.75rem;cursor:pointer;transition:background .12s,color .12s}
.btn:hover{background:rgba(255,255,255,.12);color:#f8fafc}
.btn-icon{padding:4px 9px}
.main{flex:1;display:flex;overflow:hidden;position:relative}
#gc{display:block;flex:1;cursor:grab}
#gc:active{cursor:grabbing}
#tip{position:absolute;display:none;pointer-events:none;background:#1e293b;border:1px solid rgba(255,255,255,.15);border-radius:6px;padding:8px 11px;font-size:.78rem;color:#f8fafc;max-width:240px;box-shadow:0 6px 20px rgba(0,0,0,.5);z-index:20;line-height:1.45}
#tip .tip-type{font-size:.68rem;color:rgba(255,255,255,.4);margin-top:3px}
#panel{position:absolute;right:0;top:0;bottom:0;width:280px;background:#1e293b;border-left:1px solid rgba(255,255,255,.08);overflow-y:auto;transform:translateX(100%);transition:transform .18s ease;z-index:10}
#panel.open{transform:translateX(0)}
.panel-head{padding:14px 16px 10px;border-bottom:1px solid rgba(255,255,255,.07);display:flex;align-items:flex-start;gap:8px}
.panel-close{margin-left:auto;cursor:pointer;color:rgba(255,255,255,.3);font-size:1.1rem;padding:0 2px;flex-shrink:0;line-height:1}
.panel-close:hover{color:#f8fafc}
.panel-body{padding:14px 16px}
.p-type{font-size:.65rem;text-transform:uppercase;letter-spacing:.09em;color:rgba(255,255,255,.3);margin-bottom:5px}
.p-label{font-size:.875rem;font-weight:700;color:#f8fafc;line-height:1.4;word-break:break-all;margin-bottom:10px}
.badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:9999px;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em}
.badge-CRITICAL{background:#fee2e2;color:#dc2626}
.badge-HIGH{background:#ffedd5;color:#ea580c}
.badge-MEDIUM{background:#fef3c7;color:#d97706}
.badge-LOW{background:#ecfccb;color:#65a30d}
.badge-INFO{background:#dbeafe;color:#2563eb}
.p-section{margin-top:12px}
.p-sec-title{font-size:.65rem;text-transform:uppercase;letter-spacing:.09em;color:rgba(255,255,255,.3);margin-bottom:6px}
.p-arn{font-family:monospace;font-size:.72rem;color:#94a3b8;word-break:break-all;line-height:1.5}
.p-neighbor{font-size:.75rem;color:#94a3b8;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.05);display:flex;align-items:center;gap:6px}
.p-neighbor:last-child{border-bottom:none}
.ndot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.legend{position:absolute;bottom:12px;left:12px;background:rgba(15,23,42,.88);backdrop-filter:blur(4px);border:1px solid rgba(255,255,255,.08);border-radius:6px;padding:9px 13px;display:flex;flex-wrap:wrap;gap:5px 14px;font-size:.72rem;color:rgba(255,255,255,.45);z-index:5;max-width:540px}
.li{display:flex;align-items:center;gap:5px;white-space:nowrap}
.ldot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.lline{width:16px;height:2px;flex-shrink:0}
.ldash{background:repeating-linear-gradient(90deg,#dc2626 0 4px,transparent 4px 7px)}
.zoom-ctrls{position:absolute;top:12px;right:12px;display:flex;flex-direction:column;gap:4px;z-index:5}
</style>
</head>
<body>
<header class="hdr">
  <span class="hdr-title">Attack Graph</span>
  <span class="hdr-sep"></span>
  <span class="hdr-sub">{{ target_url }}</span>
  <span class="hdr-stat"><strong id="stat-n">0</strong> nodes</span>
  <span class="hdr-stat"><strong id="stat-e">0</strong> edges</span>
  <div class="ctrl">
    <button class="btn" onclick="zoomFit()">Fit all</button>
    <button class="btn" onclick="resetView()">Reset</button>
    <a href="report.html" class="btn">&larr; Report</a>
  </div>
</header>
<div class="main">
  <canvas id="gc"></canvas>
  <div id="tip"></div>
  <div class="zoom-ctrls">
    <button class="btn btn-icon" onclick="zoomBy(1.25)">+</button>
    <button class="btn btn-icon" onclick="zoomBy(0.8)">&minus;</button>
  </div>
  <div id="panel">
    <div class="panel-head">
      <div>
        <div class="p-type" id="p-type"></div>
        <div class="p-label" id="p-label"></div>
        <div id="p-badges"></div>
      </div>
      <span class="panel-close" onclick="closePanel()">&#x2715;</span>
    </div>
    <div class="panel-body">
      <div class="p-section">
        <div class="p-sec-title">Resource ID</div>
        <div class="p-arn" id="p-arn"></div>
      </div>
      <div class="p-section" id="p-nbr-wrap">
        <div class="p-sec-title">Connected nodes</div>
        <div id="p-neighbors"></div>
      </div>
    </div>
  </div>
</div>
<div class="legend">
  <span class="li"><span class="ldot" style="background:#7c3aed"></span>IAM / Principal</span>
  <span class="li"><span class="ldot" style="background:#2563eb"></span>Compute (EC2 / EKS)</span>
  <span class="li"><span class="ldot" style="background:#16a34a"></span>Storage / Secrets</span>
  <span class="li"><span class="ldot" style="background:#d97706"></span>Lambda</span>
  <span class="li"><span class="ldot" style="background:#dc2626"></span>Web / IMDS</span>
  <span class="li"><span class="ldot" style="background:#0891b2"></span>Network</span>
  <span class="li"><span class="lline ldash"></span>Exploit path</span>
</div>
<script>
var DATA = {{ graph_json | safe }};

var canvas = document.getElementById('gc');
var ctx    = canvas.getContext('2d');
var tip    = document.getElementById('tip');
var panel  = document.getElementById('panel');

var nodes  = (DATA.elements.nodes || []).map(function(n) {
  return Object.assign({}, n.data, {x:0, y:0, vx:0, vy:0});
});
var edges  = (DATA.elements.edges || []).map(function(e) { return e.data; });
var nmap   = {};
nodes.forEach(function(n) { nmap[n.id] = n; });

document.getElementById('stat-n').textContent = nodes.length;
document.getElementById('stat-e').textContent = edges.length;

var CLUSTER = {
  iam_role:           [0.12, 0.40],
  iam_user:           [0.12, 0.62],
  eks_service_account:[0.18, 0.28],
  ec2_instance:       [0.40, 0.30],
  eks_node:           [0.48, 0.22],
  eks_pod:            [0.55, 0.28],
  lambda_function:    [0.70, 0.22],
  s3_bucket:          [0.76, 0.68],
  rds_instance:       [0.55, 0.72],
  secrets_manager:    [0.88, 0.42],
  ssm_parameter:      [0.88, 0.60],
  vpc:                [0.25, 0.18],
  security_group:     [0.35, 0.14],
  vpc_endpoint:       [0.22, 0.52],
  web_endpoint:       [0.44, 0.68],
  imds:               [0.58, 0.50],
};

var REP_K = 220, SPRING_K = 110, DAMP = 0.80;
var zoom = 1, panX = 0, panY = 0, tick = 0;
var hovNode = null, selNode = null;
var dragging = false, lmx = 0, lmy = 0;

function resize() {
  canvas.width  = canvas.offsetWidth  || canvas.parentElement.offsetWidth  || 900;
  canvas.height = canvas.offsetHeight || canvas.parentElement.offsetHeight || 600;
}

function initPos() {
  var W = canvas.width, H = canvas.height;
  var cols = Math.ceil(Math.sqrt(nodes.length * (W / H)));
  var cw = W / (cols + 1), ch = H / (Math.ceil(nodes.length / cols) + 1);
  nodes.forEach(function(n, i) {
    var col = i % cols, row = Math.floor(i / cols);
    n.x  = (col + 1) * cw + (Math.random() - .5) * cw * .5;
    n.y  = (row + 1) * ch + (Math.random() - .5) * ch * .5;
    n.vx = 0; n.vy = 0;
  });
  tick = 0;
}

function simulate() {
  if (tick > 400) return;
  tick++;
  var W = canvas.width, H = canvas.height;
  var i, j, dx, dy, d, minD, fMag, fx, fy;
  for (i = 0; i < nodes.length; i++) {
    for (j = i + 1; j < nodes.length; j++) {
      dx = nodes[j].x - nodes[i].x || .01;
      dy = nodes[j].y - nodes[i].y || .01;
      d  = Math.sqrt(dx * dx + dy * dy) || .01;
      if (d > 400) continue;
      minD = (nodes[i].radius || 10) + (nodes[j].radius || 10) + 22;
      fMag = d < minD ? REP_K * REP_K * 6 / d : REP_K * REP_K / d;
      fx = fMag * dx / d; fy = fMag * dy / d;
      nodes[i].vx -= fx; nodes[i].vy -= fy;
      nodes[j].vx += fx; nodes[j].vy += fy;
    }
  }
  edges.forEach(function(e) {
    var s = nmap[e.source], t = nmap[e.target];
    if (!s || !t) return;
    var edx = t.x - s.x, edy = t.y - s.y;
    var ed  = Math.sqrt(edx * edx + edy * edy) || 1;
    var ef  = (ed - SPRING_K) / ed * 0.09;
    s.vx += ef * edx; s.vy += ef * edy;
    t.vx -= ef * edx; t.vy -= ef * edy;
  });
  nodes.forEach(function(n) {
    var cl = CLUSTER[n.type] || [.5, .5];
    n.vx += (cl[0] * W - n.x) * .008;
    n.vy += (cl[1] * H - n.y) * .008;
    n.vx *= DAMP; n.vy *= DAMP;
    var r = (n.radius || 10) + 8;
    n.x = Math.max(r, Math.min(W - r, n.x + n.vx));
    n.y = Math.max(r, Math.min(H - r, n.y + n.vy));
  });
}

function neighborSet(nodeId) {
  var s = {};
  s[nodeId] = true;
  edges.forEach(function(e) {
    if (e.source === nodeId) s[e.target] = true;
    if (e.target === nodeId) s[e.source] = true;
  });
  return s;
}

function draw() {
  var W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);
  ctx.save();
  ctx.translate(panX, panY);
  ctx.scale(zoom, zoom);
  var nbrs = hovNode ? neighborSet(hovNode.id) : null;
  edges.forEach(function(e) {
    var s = nmap[e.source], t = nmap[e.target];
    if (!s || !t) return;
    var hi = hovNode && (e.source === hovNode.id || e.target === hovNode.id);
    ctx.globalAlpha = hi ? .92 : (hovNode ? .12 : .42);
    ctx.beginPath();
    ctx.setLineDash(e.dashed ? [5, 3] : []);
    ctx.moveTo(s.x, s.y); ctx.lineTo(t.x, t.y);
    ctx.strokeStyle = e.color || '#475569';
    ctx.lineWidth   = hi ? 2.5 / zoom : 1.5 / zoom;
    ctx.stroke();
    if (hi) {
      var angle = Math.atan2(t.y - s.y, t.x - s.x);
      var tr = (t.radius || 10) + 4;
      var ax = t.x - tr * Math.cos(angle), ay = t.y - tr * Math.sin(angle);
      ctx.setLineDash([]);
      ctx.beginPath();
      ctx.moveTo(ax, ay);
      ctx.lineTo(ax - 9 * Math.cos(angle - .4), ay - 9 * Math.sin(angle - .4));
      ctx.lineTo(ax - 9 * Math.cos(angle + .4), ay - 9 * Math.sin(angle + .4));
      ctx.closePath();
      ctx.fillStyle = e.color || '#475569';
      ctx.fill();
    }
  });
  ctx.setLineDash([]); ctx.globalAlpha = 1;
  nodes.forEach(function(n) {
    var r = n.radius || 10;
    var isHov = hovNode && hovNode.id === n.id;
    var isSel = selNode && selNode.id === n.id;
    var dim   = nbrs && !nbrs[n.id];
    ctx.globalAlpha = dim ? .18 : 1;
    if (isSel) {
      ctx.beginPath(); ctx.arc(n.x, n.y, r + 6, 0, Math.PI * 2);
      ctx.strokeStyle = '#f8fafc'; ctx.lineWidth = 2 / zoom; ctx.stroke();
    }
    ctx.beginPath(); ctx.arc(n.x, n.y, isHov ? r + 3 : r, 0, Math.PI * 2);
    ctx.fillStyle = n.color || '#94a3b8'; ctx.fill();
    if (n.border_color && n.border_color !== '#94a3b8') {
      ctx.strokeStyle = n.border_color; ctx.lineWidth = (isHov ? 3 : 2) / zoom; ctx.stroke();
    }
    if (n.internet_facing) {
      ctx.beginPath(); ctx.arc(n.x + r * .65, n.y - r * .65, 3.5, 0, Math.PI * 2);
      ctx.fillStyle = '#f8fafc'; ctx.fill();
    }
  });
  ctx.globalAlpha = 1; ctx.restore();
}

function zoomFit() {
  if (!nodes.length) return;
  var x0 = Infinity, x1 = -Infinity, y0 = Infinity, y1 = -Infinity;
  nodes.forEach(function(n) {
    var r = (n.radius || 10) + 4;
    if (n.x - r < x0) x0 = n.x - r; if (n.x + r > x1) x1 = n.x + r;
    if (n.y - r < y0) y0 = n.y - r; if (n.y + r > y1) y1 = n.y + r;
  });
  var W = canvas.width, H = canvas.height, pad = 48;
  var sx = (W - pad * 2) / (x1 - x0 || 1);
  var sy = (H - pad * 2) / (y1 - y0 || 1);
  zoom = Math.min(sx, sy, 3);
  panX = pad - x0 * zoom + ((W - pad * 2) - (x1 - x0) * zoom) / 2;
  panY = pad - y0 * zoom + ((H - pad * 2) - (y1 - y0) * zoom) / 2;
}

function zoomBy(factor) {
  var cx = canvas.width / 2, cy = canvas.height / 2;
  var nz = Math.max(.2, Math.min(5, zoom * factor));
  panX = cx - (cx - panX) * (nz / zoom);
  panY = cy - (cy - panY) * (nz / zoom);
  zoom = nz;
}

function resetView() { zoom = 1; panX = 0; panY = 0; initPos(); }

function hitNode(ox, oy) {
  var wx = (ox - panX) / zoom, wy = (oy - panY) / zoom;
  for (var i = nodes.length - 1; i >= 0; i--) {
    var n = nodes[i], r = (n.radius || 10) + 5;
    if ((wx - n.x) * (wx - n.x) + (wy - n.y) * (wy - n.y) <= r * r) return n;
  }
  return null;
}

var SEV_BG = {CRITICAL:'#fee2e2',HIGH:'#ffedd5',MEDIUM:'#fef3c7',LOW:'#ecfccb',INFO:'#dbeafe'};
var SEV_FG = {CRITICAL:'#dc2626',HIGH:'#ea580c',MEDIUM:'#d97706',LOW:'#65a30d',INFO:'#2563eb'};
var NC = {
  iam_role:'#7c3aed',iam_user:'#7c3aed',eks_service_account:'#7c3aed',
  ec2_instance:'#2563eb',eks_pod:'#2563eb',eks_node:'#2563eb',
  s3_bucket:'#16a34a',rds_instance:'#16a34a',secrets_manager:'#16a34a',ssm_parameter:'#16a34a',
  lambda_function:'#d97706',vpc:'#0891b2',security_group:'#0891b2',vpc_endpoint:'#0891b2',
  web_endpoint:'#dc2626',imds:'#dc2626',
};

function openPanel(n) {
  selNode = n;
  document.getElementById('p-type').textContent  = (n.type || '').replace(/_/g, ' ');
  document.getElementById('p-label').textContent = n.label || n.id;
  var badges = document.getElementById('p-badges');
  badges.innerHTML = '';
  if (n.severity) {
    var b = document.createElement('span');
    b.className = 'badge badge-' + n.severity; b.textContent = n.severity;
    badges.appendChild(b);
  }
  if (n.internet_facing) {
    var b2 = document.createElement('span');
    b2.className = 'badge';
    b2.style.cssText = 'background:#fef3c7;color:#b45309;margin-left:6px';
    b2.textContent = 'INTERNET-FACING'; badges.appendChild(b2);
  }
  document.getElementById('p-arn').textContent = n.id;
  var nbrsEl = document.getElementById('p-neighbors');
  nbrsEl.innerHTML = '';
  edges.forEach(function(e) {
    var other = null, dir = '';
    if (e.source === n.id) { other = nmap[e.target];  dir = '\u2192 '; }
    if (e.target === n.id) { other = nmap[e.source];  dir = '\u2190 '; }
    if (!other) return;
    var row = document.createElement('div'); row.className = 'p-neighbor';
    var dot = document.createElement('span'); dot.className = 'ndot';
    dot.style.background = NC[other.type] || '#94a3b8'; row.appendChild(dot);
    var txt = document.createElement('span'); txt.style.flex = '1';
    txt.textContent = dir + (other.label || other.id).slice(0, 32); row.appendChild(txt);
    var rel = document.createElement('span');
    rel.style.cssText = 'font-size:.65rem;color:rgba(255,255,255,.3)';
    rel.textContent = e.label || ''; row.appendChild(rel);
    nbrsEl.appendChild(row);
  });
  document.getElementById('p-nbr-wrap').style.display = nbrsEl.children.length ? '' : 'none';
  panel.classList.add('open');
}

function closePanel() { panel.classList.remove('open'); selNode = null; }

canvas.addEventListener('mousedown', function(e) { dragging = true; lmx = e.offsetX; lmy = e.offsetY; });
canvas.addEventListener('mouseup', function(e) {
  if (!dragging) return;
  var moved = Math.abs(e.offsetX - lmx) + Math.abs(e.offsetY - lmy);
  dragging = false;
  if (moved < 4) { var n = hitNode(e.offsetX, e.offsetY); if (n) openPanel(n); else closePanel(); }
});
canvas.addEventListener('mouseleave', function() { dragging = false; hovNode = null; tip.style.display = 'none'; });
canvas.addEventListener('mousemove', function(e) {
  if (dragging) {
    panX += e.offsetX - lmx; panY += e.offsetY - lmy;
    lmx = e.offsetX; lmy = e.offsetY; return;
  }
  var n = hitNode(e.offsetX, e.offsetY);
  hovNode = n;
  if (n) {
    canvas.style.cursor = 'pointer';
    var tx = Math.min(e.offsetX + 14, canvas.offsetWidth - 250);
    var ty = Math.max(e.offsetY - 50, 4);
    tip.style.left = tx + 'px'; tip.style.top = ty + 'px'; tip.style.display = 'block';
    var sev = n.severity;
    tip.innerHTML =
      '<strong style="color:#f8fafc">' + (n.label || n.id).slice(0, 48) + '</strong>' +
      '<div class="tip-type">' + (n.type || '').replace(/_/g, ' ') +
      (sev ? ' &middot; <span style="background:' + (SEV_BG[sev]||'') + ';color:' + (SEV_FG[sev]||'') +
             ';padding:1px 6px;border-radius:9999px;font-size:.65rem;font-weight:700">' + sev + '</span>' : '') +
      '</div>';
  } else {
    canvas.style.cursor = dragging ? 'grabbing' : 'grab';
    tip.style.display = 'none';
  }
});
canvas.addEventListener('wheel', function(e) {
  e.preventDefault();
  var factor = e.deltaY < 0 ? 1.12 : 1 / 1.12;
  var nz = Math.max(.15, Math.min(6, zoom * factor));
  panX = e.offsetX - (e.offsetX - panX) * (nz / zoom);
  panY = e.offsetY - (e.offsetY - panY) * (nz / zoom);
  zoom = nz;
}, {passive: false});

window.addEventListener('resize', function() { resize(); });

resize();
initPos();
for (var _pi = 0; _pi < 280; _pi++) simulate();
zoomFit();
(function loop() { simulate(); draw(); requestAnimationFrame(loop); })();
</script>
</body>
</html>"""


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
        # Severity distribution
        severity_counts = {s.value: 0 for s in Severity}
        for f in findings:
            severity_counts[f.severity.value] += 1
        total_findings = len(findings)

        # Risk score + visual metadata
        score = _risk_score(severity_counts)
        risk_color, risk_label, risk_dash = _risk_meta(score)

        # Cloud health score from DB state
        health_score = await self._db.get_state("cloud_audit_health_score", "N/A")

        # Top 5 by severity
        top5 = sorted(findings, key=lambda f: _SEV_RANK[f.severity])[:5]

        # Unique sources and categories for filter dropdowns
        sources = sorted({f.source for f in findings})
        categories = sorted({f.category for f in findings if f.category})

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

        # Enrich each chain with its step components and remediation actions
        chain_data = []
        for chain in chains:
            components = await self._db.get_chain_findings(chain.id)
            actions = await self._db.get_remediation_actions(chain_id=chain.id)
            chain_data.append({
                "chain": chain,
                "components": components,   # list of (Finding, ChainRole, int)
                "actions": actions,         # list of RemediationAction
            })

        # Build remediation playbook: all actions across chains, grouped by effort
        playbook: dict[str, list[dict]] = {"LOW": [], "MEDIUM": [], "HIGH": []}
        seen: set[str] = set()
        for cd in chain_data:
            for action in cd["actions"]:
                key = action.action_summary.strip()[:120]
                if key in seen:
                    continue
                seen.add(key)
                entry = {
                    "action_summary": action.action_summary,
                    "breaks_chain": action.breaks_chain,
                    "cli_command": action.cli_command,
                    "iac_snippet": action.iac_snippet,
                    "chain_name": cd["chain"].pattern_name,
                }
                playbook[action.effort_level.value].append(entry)
        # Sort: chain-breakers first within each effort group
        for group in playbook.values():
            group.sort(key=lambda x: (not x["breaks_chain"],))

        # Build attack surface graph for the report
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

        # Build Jinja2 environment with custom filter
        env = Environment(loader=BaseLoader(), autoescape=True)
        env.filters["md_bold"] = _md_bold

        # Write full-size graph.html when graph data is available
        graph_path = ""
        if graph_json != "{}":
            graph_page_path = output_path.parent / "graph.html"
            try:
                graph_tmpl = env.from_string(_GRAPH_TEMPLATE)
                graph_html = graph_tmpl.render(
                    target_url=self._cfg.target.url,
                    graph_json=graph_json,
                )
                graph_page_path.write_text(graph_html, encoding="utf-8")
                graph_path = "graph.html"
                log.info("Graph page written to %s", graph_page_path)
            except Exception as exc:
                log.warning("Could not write graph.html: %s", exc)

        template = env.from_string(_HTML_TEMPLATE)
        html = template.render(
            target_url=self._cfg.target.url,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            severity_counts=severity_counts,
            total_findings=total_findings,
            risk_score=score,
            risk_color=risk_color,
            risk_label=risk_label,
            risk_dash=risk_dash,
            circ=str(round(_CIRC, 2)),
            chain_data=chain_data,
            chains=chains,
            findings=findings,
            top5=top5,
            health_score=health_score,
            sources=sources,
            categories=categories,
            compliance_rows=compliance_rows,
            playbook=playbook,
            graph_json=graph_json,
            graph_path=graph_path,
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
        log.info("HTML report written to %s (%d KB)", output_path, len(html) // 1024)

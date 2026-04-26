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

from jinja2 import BaseLoader, Environment

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
]
_OWASP_ORDER = [
    "A01", "A02", "A03", "A04", "A05", "A06",
    "A07", "A08", "A09", "A10", "AWS", "OTHER",
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
# Main HTML template
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Clementine &mdash; {{ target_url }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&family=Instrument+Serif:ital@0;1&display=swap" rel="stylesheet">
<style>
{% raw %}
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&family=Instrument+Serif:ital@0;1&display=swap');

:root {
  --bg:          #0a0c0f;
  --bg-1:        #0f1216;
  --bg-2:        #161a20;
  --bg-3:        #1c2128;
  --line:        #1f242c;
  --line-2:      #2a3038;
  --line-3:      #3a424c;
  --ink:         #e8eaed;
  --ink-2:       #b8bec7;
  --ink-3:       #7a818b;
  --ink-4:       #4a5058;
  --accent:      oklch(0.78 0.14 60);
  --accent-dim:  oklch(0.78 0.14 60 / 0.18);
  --accent-line: oklch(0.78 0.14 60 / 0.35);
  --sev-critical: oklch(0.68 0.16 25);
  --sev-high:     oklch(0.74 0.14 55);
  --sev-medium:   oklch(0.78 0.12 90);
  --sev-low:      oklch(0.74 0.10 160);
  --sev-info:     oklch(0.72 0.09 240);
  --sev-critical-dim:  oklch(0.68 0.16 25 / 0.14);
  --sev-high-dim:      oklch(0.74 0.14 55 / 0.14);
  --sev-medium-dim:    oklch(0.78 0.12 90 / 0.14);
  --sev-low-dim:       oklch(0.74 0.10 160 / 0.14);
  --sev-info-dim:      oklch(0.72 0.09 240 / 0.14);
  --sev-critical-line: oklch(0.68 0.16 25 / 0.35);
  --sev-high-line:     oklch(0.74 0.14 55 / 0.35);
  --sev-medium-line:   oklch(0.78 0.12 90 / 0.35);
  --sev-low-line:      oklch(0.74 0.10 160 / 0.35);
  --sev-info-line:     oklch(0.72 0.09 240 / 0.35);
  --f-sans:  'Inter', system-ui, sans-serif;
  --f-mono:  'JetBrains Mono', ui-monospace, monospace;
  --f-serif: 'Instrument Serif', Georgia, serif;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html, body { background: var(--bg); color: var(--ink); }
body {
  font-family: var(--f-sans);
  font-feature-settings: 'ss01', 'cv11';
  font-size: 14px;
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}
a { color: inherit; text-decoration: none; }
button { font: inherit; color: inherit; background: none; border: 0; cursor: pointer; }
::selection { background: var(--accent-dim); color: #fff; }
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--line-2); border-radius: 6px; border: 2px solid var(--bg); }
::-webkit-scrollbar-thumb:hover { background: var(--line-3); }

/* ── Layout ── */
.app { display: grid; grid-template-columns: 240px 1fr; min-height: 100vh; }

/* ── Rail ── */
.rail {
  position: sticky; top: 0; height: 100vh;
  border-right: 1px solid var(--line);
  background: var(--bg);
  display: flex; flex-direction: column;
  overflow-y: auto; z-index: 10;
}
.rail-brand { padding: 20px 22px 18px; border-bottom: 1px solid var(--line); }
.rail-brand .mark { display: flex; align-items: center; gap: 10px; }
.rail-brand .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--accent); box-shadow: 0 0 12px var(--accent-line); }
.rail-brand .name { font-family: var(--f-mono); font-size: 12px; font-weight: 600; letter-spacing: 0.04em; color: var(--ink); }
.rail-brand .sub { font-family: var(--f-mono); font-size: 10.5px; color: var(--ink-3); letter-spacing: 0.06em; margin-top: 6px; text-transform: uppercase; }
.rail-section { padding: 18px 22px 6px; font-family: var(--f-mono); font-size: 10px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--ink-4); }
.rail-link {
  display: flex; align-items: center; justify-content: space-between;
  padding: 7px 22px; font-size: 13px; color: var(--ink-2);
  border-left: 2px solid transparent; cursor: pointer;
  transition: color .15s, background .15s, border-color .15s;
}
.rail-link:hover { color: var(--ink); background: var(--bg-1); }
.rail-link.active { color: var(--ink); border-left-color: var(--accent); background: var(--bg-1); }
.rail-link .num { font-family: var(--f-mono); font-size: 11px; color: var(--ink-4); letter-spacing: 0.04em; }
.rail-link .num.crit { color: var(--sev-critical); }
.rail-foot {
  margin-top: auto; padding: 18px 22px;
  border-top: 1px solid var(--line);
  font-family: var(--f-mono); font-size: 10.5px; color: var(--ink-4); line-height: 1.7;
}
.rail-foot .row { display: flex; justify-content: space-between; }
.rail-foot .row + .row { margin-top: 4px; }

/* ── Main ── */
.main { min-width: 0; }

/* ── Topbar ── */
.topbar {
  position: sticky; top: 0; z-index: 5;
  display: flex; align-items: center; gap: 18px;
  padding: 0 32px; height: 44px;
  background: rgba(10,12,15,0.85);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border-bottom: 1px solid var(--line);
  font-family: var(--f-mono); font-size: 11px; color: var(--ink-3); letter-spacing: 0.04em;
}
.topbar .crumb { color: var(--ink-3); }
.topbar .crumb strong { color: var(--ink); font-weight: 500; }
.topbar .sep { color: var(--ink-4); }
.topbar .pulse { width: 6px; height: 6px; border-radius: 50%; background: var(--sev-critical); box-shadow: 0 0 10px var(--sev-critical); animation: pulse 1.6s infinite; }
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .35; } }
.topbar .right { margin-left: auto; display: flex; gap: 18px; align-items: center; }
.topbar .target { color: var(--ink-2); }

/* ── Section frame ── */
section.s { padding: 56px 56px 24px; border-bottom: 1px solid var(--line); scroll-margin-top: 60px; }
section.s.tight { padding-bottom: 56px; }
.s-head { display: flex; align-items: baseline; gap: 14px; margin-bottom: 28px; }
.s-eyebrow { font-family: var(--f-mono); font-size: 10.5px; letter-spacing: 0.16em; text-transform: uppercase; color: var(--ink-4); }
.s-title { font-size: 22px; font-weight: 500; letter-spacing: -0.01em; color: var(--ink); }
.s-sub { font-size: 13px; color: var(--ink-3); margin-left: auto; font-family: var(--f-mono); }

/* ── Hero ── */
.hero { padding: 64px 56px 56px; border-bottom: 1px solid var(--line); position: relative; overflow: hidden; }
.hero::before {
  content: '';
  position: absolute; inset: 0;
  background:
    radial-gradient(900px 400px at 100% 0%, var(--sev-critical-dim), transparent 60%),
    radial-gradient(600px 300px at 0% 100%, var(--accent-dim), transparent 60%);
  opacity: 0.6;
  pointer-events: none;
}
.hero > * { position: relative; }
.hero-meta {
  display: flex; align-items: center; gap: 14px;
  font-family: var(--f-mono); font-size: 10.5px; letter-spacing: 0.14em; text-transform: uppercase;
  color: var(--ink-3); margin-bottom: 22px;
}
.hero-meta .dot { width: 6px; height: 6px; border-radius: 50%; background: var(--sev-critical); box-shadow: 0 0 10px var(--sev-critical); }
.hero-meta .verdict { color: var(--sev-critical); font-weight: 600; }
.hero-meta .sep::before { content: '/'; color: var(--ink-4); }
.hero-title {
  font-family: var(--f-serif); font-weight: 400;
  font-size: 52px; line-height: 1.06; letter-spacing: -0.02em;
  color: var(--ink); max-width: 920px; margin-bottom: 28px;
}
.hero-title em { font-style: italic; color: var(--accent); }
.hero-narrative { max-width: 720px; font-size: 16px; line-height: 1.65; color: var(--ink-2); margin-bottom: 40px; }
.hero-narrative .em { color: var(--ink); font-weight: 500; background: linear-gradient(180deg, transparent 70%, var(--accent-dim) 70%); }

/* KPI strip */
.kpi-strip { display: grid; grid-template-columns: 1.4fr repeat(4,1fr); gap: 0; border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); margin-top: 8px; }
.kpi { padding: 22px 24px; border-right: 1px solid var(--line); display: flex; flex-direction: column; gap: 6px; }
.kpi:last-child { border-right: 0; }
.kpi-label { font-family: var(--f-mono); font-size: 10px; letter-spacing: 0.16em; text-transform: uppercase; color: var(--ink-4); }
.kpi-value { font-family: var(--f-mono); font-size: 32px; font-weight: 500; color: var(--ink); letter-spacing: -0.02em; line-height: 1; font-variant-numeric: tabular-nums; }
.kpi-value.crit { color: var(--sev-critical); }
.kpi-value.high { color: var(--sev-high); }
.kpi-value.med  { color: var(--sev-medium); }
.kpi-value.low  { color: var(--sev-low); }
.kpi-foot { font-family: var(--f-mono); font-size: 11px; color: var(--ink-3); }
.kpi.score { background: var(--bg-1); }
.kpi.score .gauge { display: flex; align-items: baseline; gap: 8px; }
.kpi.score .gauge .big { font-family: var(--f-mono); font-size: 56px; font-weight: 500; line-height: 0.9; letter-spacing: -0.04em; font-variant-numeric: tabular-nums; }
.kpi.score .gauge .denom { font-family: var(--f-mono); font-size: 16px; color: var(--ink-4); }
.kpi.score .bar { margin-top: 8px; height: 4px; background: var(--line); border-radius: 2px; overflow: hidden; position: relative; }
.kpi.score .bar-fill { position: absolute; inset: 0; border-radius: 2px; }

/* Severity histogram */
.sev-hist { display: grid; grid-template-columns: 1fr; gap: 10px; margin-top: 28px; max-width: 720px; }
.sev-hist .row { display: grid; grid-template-columns: 88px 1fr 56px; align-items: center; gap: 14px; font-family: var(--f-mono); font-size: 11px; }
.sev-hist .label { color: var(--ink-3); letter-spacing: 0.08em; text-transform: uppercase; font-size: 10.5px; }
.sev-hist .track { height: 6px; background: var(--line); border-radius: 3px; overflow: hidden; }
.sev-hist .fill { height: 100%; border-radius: 3px; }
.sev-hist .n { text-align: right; font-variant-numeric: tabular-nums; color: var(--ink); font-weight: 500; }
.fill-critical { background: var(--sev-critical); box-shadow: 0 0 8px var(--sev-critical-line); }
.fill-high     { background: var(--sev-high); }
.fill-medium   { background: var(--sev-medium); }
.fill-low      { background: var(--sev-low); }
.fill-info     { background: var(--sev-info); }

/* ── Severity badge ── */
.badge { display: inline-flex; align-items: center; gap: 6px; padding: 3px 8px; border-radius: 3px; font-family: var(--f-mono); font-size: 10px; font-weight: 500; letter-spacing: 0.1em; text-transform: uppercase; border: 1px solid; }
.badge .d { width: 5px; height: 5px; border-radius: 50%; }
.b-critical { color: var(--sev-critical); background: var(--sev-critical-dim); border-color: var(--sev-critical-line); }
.b-critical .d { background: var(--sev-critical); }
.b-high     { color: var(--sev-high);     background: var(--sev-high-dim);     border-color: var(--sev-high-line); }
.b-high .d  { background: var(--sev-high); }
.b-medium   { color: var(--sev-medium);   background: var(--sev-medium-dim);   border-color: var(--sev-medium-line); }
.b-medium .d{ background: var(--sev-medium); }
.b-low      { color: var(--sev-low);      background: var(--sev-low-dim);      border-color: var(--sev-low-line); }
.b-low .d   { background: var(--sev-low); }
.b-info     { color: var(--sev-info);     background: var(--sev-info-dim);     border-color: var(--sev-info-line); }
.b-info .d  { background: var(--sev-info); }

.tag { display: inline-flex; align-items: center; gap: 6px; padding: 2px 7px; border-radius: 3px; font-family: var(--f-mono); font-size: 10px; letter-spacing: 0.06em; color: var(--ink-3); background: var(--bg-2); border: 1px solid var(--line-2); }
.tag.ai           { color: var(--accent); border-color: var(--accent-line); background: var(--accent-dim); }
.tag.role-entry   { color: var(--sev-critical); border-color: var(--sev-critical-line); background: var(--sev-critical-dim); }
.tag.role-pivot   { color: var(--sev-high);     border-color: var(--sev-high-line);     background: var(--sev-high-dim); }
.tag.role-amplifier { color: var(--sev-medium); border-color: var(--sev-medium-line);   background: var(--sev-medium-dim); }

/* ── Attack Chains ── */
.chains { display: flex; flex-direction: column; gap: 12px; }
.chain { background: var(--bg-1); border: 1px solid var(--line); border-radius: 6px; overflow: hidden; transition: border-color .2s; }
.chain:hover { border-color: var(--line-2); }
.chain.open  { border-color: var(--line-3); }
.chain-row { display: grid; grid-template-columns: auto 80px 1fr auto auto; align-items: center; gap: 18px; padding: 18px 22px; cursor: pointer; }
.chain-id   { font-family: var(--f-mono); font-size: 10.5px; color: var(--ink-4); letter-spacing: 0.1em; font-variant-numeric: tabular-nums; }
.chain-name { font-family: var(--f-mono); font-size: 13px; color: var(--ink); letter-spacing: 0.01em; }
.chain-meta { font-family: var(--f-mono); font-size: 11px; color: var(--ink-3); }
.chain-meta strong { color: var(--ink-2); font-weight: 500; }
.chain-chev { width: 22px; height: 22px; display: grid; place-items: center; color: var(--ink-3); transition: transform .2s, color .2s; font-family: var(--f-mono); font-size: 14px; }
.chain.open .chain-chev { transform: rotate(90deg); color: var(--ink); }
.chain-body { border-top: 1px solid var(--line); padding: 24px 22px 26px; display: none; background: var(--bg); }
.chain.open .chain-body { display: block; }
.chain-narr { max-width: 760px; font-size: 14.5px; line-height: 1.7; color: var(--ink-2); margin-bottom: 28px; }
.chain-narr code { font-family: var(--f-mono); font-size: 12px; color: var(--accent); background: var(--accent-dim); padding: 1px 5px; border-radius: 3px; }

/* Stepper */
.steps { display: grid; gap: 0; position: relative; margin: 0 0 28px; }
.step { display: grid; grid-template-columns: 60px 1fr; gap: 18px; padding: 14px 0; position: relative; }
.step:not(:last-child)::before { content: ''; position: absolute; left: 22px; top: 38px; bottom: -8px; width: 1px; background: var(--line-2); }
.step-idx { font-family: var(--f-mono); font-size: 11px; color: var(--ink-4); display: flex; align-items: flex-start; gap: 8px; position: relative; z-index: 1; }
.step-idx .pip { width: 16px; height: 16px; border-radius: 50%; background: var(--bg-1); border: 1px solid var(--line-3); display: grid; place-items: center; margin-top: 1px; flex-shrink: 0; }
.step-idx .pip::after { content: ''; width: 5px; height: 5px; border-radius: 50%; background: var(--ink-3); }
.step-idx.entry     .pip::after { background: var(--sev-critical); box-shadow: 0 0 6px var(--sev-critical); }
.step-idx.pivot     .pip::after { background: var(--sev-high); }
.step-idx.amplifier .pip::after { background: var(--sev-medium); }
.step-body { padding-top: 1px; }
.step-title { font-family: var(--f-mono); font-size: 12.5px; color: var(--ink); margin-bottom: 4px; }
.step-meta { display: flex; gap: 8px; align-items: center; font-family: var(--f-mono); font-size: 10.5px; color: var(--ink-4); letter-spacing: 0.04em; }

/* Remediation items */
.rem-list { display: grid; gap: 8px; margin-top: 8px; }
.rem-list .head { font-family: var(--f-mono); font-size: 10px; letter-spacing: 0.16em; text-transform: uppercase; color: var(--ink-4); margin-bottom: 4px; }
.rem { display: grid; grid-template-columns: auto auto 1fr; gap: 14px; align-items: center; padding: 12px 14px; background: var(--bg-1); border: 1px solid var(--line); border-radius: 4px; font-size: 13px; color: var(--ink-2); }
.rem.breaks { border-color: var(--sev-low-line); background: var(--sev-low-dim); }
.rem-eff { font-family: var(--f-mono); font-size: 10px; letter-spacing: 0.1em; text-transform: uppercase; padding: 2px 7px; border-radius: 3px; border: 1px solid var(--line-2); color: var(--ink-3); background: var(--bg-2); }
.rem-eff.low { color: var(--sev-low); border-color: var(--sev-low-line); background: var(--sev-low-dim); }
.rem-eff.medium { color: var(--sev-medium); border-color: var(--sev-medium-line); background: var(--sev-medium-dim); }
.rem-eff.high { color: var(--sev-critical); border-color: var(--sev-critical-line); background: var(--sev-critical-dim); }

/* Code blocks in remediations */
.rem-code { margin-top: 8px; grid-column: 1 / -1; }
pre.code { font-family: var(--f-mono); font-size: 11.5px; background: var(--bg-3); border: 1px solid var(--line); border-radius: 4px; padding: 10px 12px; color: var(--ink); overflow-x: auto; white-space: pre-wrap; word-break: break-all; line-height: 1.55; position: relative; }
.copy-btn { position: absolute; top: 6px; right: 6px; padding: 2px 8px; background: var(--bg-2); border: 1px solid var(--line-2); color: var(--ink-3); border-radius: 3px; font-family: var(--f-mono); font-size: 10px; cursor: pointer; transition: background .12s, color .12s; }
.copy-btn:hover { background: var(--bg-3); color: var(--ink); }

/* ── Findings ── */
.find-toolbar { display: flex; align-items: center; gap: 10px; margin-bottom: 18px; padding: 8px; background: var(--bg-1); border: 1px solid var(--line); border-radius: 6px; }
.find-toolbar input { flex: 1; background: transparent; border: 0; outline: 0; padding: 6px 10px; font-family: var(--f-mono); font-size: 12px; color: var(--ink); }
.find-toolbar input::placeholder { color: var(--ink-4); }
.find-chips { display: flex; gap: 6px; flex-wrap: wrap; }
.chip { display: inline-flex; align-items: center; gap: 6px; padding: 5px 10px; border-radius: 3px; font-family: var(--f-mono); font-size: 10.5px; letter-spacing: 0.06em; color: var(--ink-3); background: var(--bg-2); border: 1px solid var(--line-2); cursor: pointer; user-select: none; transition: all .15s; }
.chip:hover { color: var(--ink); border-color: var(--line-3); }
.chip.on { color: var(--ink); border-color: var(--ink-4); background: var(--bg-3); }
.chip .d { width: 5px; height: 5px; border-radius: 50%; }
.chip .n { color: var(--ink-4); margin-left: 2px; font-variant-numeric: tabular-nums; }
.chip.on .n { color: var(--ink-2); }

/* OWASP category accordion */
.cat { border-top: 1px solid var(--line); }
.cat:last-child { border-bottom: 1px solid var(--line); }
.cat-head { display: grid; grid-template-columns: 80px 1fr auto auto; gap: 18px; align-items: center; padding: 16px 4px; cursor: pointer; }
.cat-head:hover { background: var(--bg-1); }
.cat-code { font-family: var(--f-mono); font-size: 11px; color: var(--ink-4); letter-spacing: 0.06em; }
.cat-name { font-size: 14px; color: var(--ink); font-weight: 500; }
.cat-name .n { font-family: var(--f-mono); color: var(--ink-3); font-weight: 400; margin-left: 8px; font-size: 12px; }
.cat-spark { display: flex; gap: 2px; height: 18px; align-items: flex-end; }
.cat-spark .s { width: 5px; border-radius: 1px; opacity: 0.85; }
.cat-chev { font-family: var(--f-mono); font-size: 12px; color: var(--ink-3); width: 16px; text-align: center; transition: transform .2s; }
.cat.open .cat-chev { transform: rotate(90deg); color: var(--ink); }
.cat-body { display: none; padding: 4px 0 16px; }
.cat.open .cat-body { display: block; }

/* Finding rows */
.find-row { display: grid; grid-template-columns: 100px 1fr 140px 100px; gap: 16px; align-items: baseline; padding: 11px 14px 11px 22px; border-left: 2px solid transparent; cursor: pointer; transition: background .12s, border-color .12s; }
.find-row:hover { background: var(--bg-1); border-left-color: var(--accent); }
.find-row .find-sev { font-family: var(--f-mono); font-size: 10px; letter-spacing: 0.14em; text-transform: uppercase; display: flex; align-items: center; gap: 8px; }
.find-row .find-sev .d { width: 6px; height: 6px; border-radius: 50%; }
.find-row .find-sev.crit { color: var(--sev-critical); } .find-row .find-sev.crit .d { background: var(--sev-critical); }
.find-row .find-sev.high { color: var(--sev-high); }     .find-row .find-sev.high .d { background: var(--sev-high); }
.find-row .find-sev.medium { color: var(--sev-medium); } .find-row .find-sev.medium .d { background: var(--sev-medium); }
.find-row .find-sev.low  { color: var(--sev-low); }      .find-row .find-sev.low  .d { background: var(--sev-low); }
.find-row .find-sev.info { color: var(--sev-info); }     .find-row .find-sev.info .d { background: var(--sev-info); }
.find-title { font-size: 13px; color: var(--ink); }
.find-src { font-family: var(--f-mono); font-size: 11px; color: var(--ink-3); }
.find-id { font-family: var(--f-mono); font-size: 10.5px; color: var(--ink-4); text-align: right; font-variant-numeric: tabular-nums; }

/* Finding detail drawer */
.find-detail { display: none; padding: 16px 22px 22px; background: var(--bg-1); border-left: 2px solid var(--accent); border-bottom: 1px solid var(--line); font-size: 13px; color: var(--ink-2); line-height: 1.65; }
.find-row.open + .find-detail { display: block; }
.find-detail .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-top: 14px; }
.find-detail .lbl { font-family: var(--f-mono); font-size: 10px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--ink-4); margin-bottom: 6px; }
.triage-note { background: var(--accent-dim); border-left: 2px solid var(--accent-line); padding: 8px 12px; border-radius: 0 4px 4px 0; font-size: 12px; color: var(--ink-2); margin-top: 10px; line-height: 1.55; }

/* ── Remediation Playbook ── */
.playbook { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
.pb { background: var(--bg-1); border: 1px solid var(--line); border-radius: 6px; padding: 22px; }
.pb-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; padding-bottom: 14px; border-bottom: 1px solid var(--line); }
.pb-eff { font-family: var(--f-mono); font-size: 11px; letter-spacing: 0.1em; text-transform: uppercase; display: flex; align-items: center; gap: 8px; color: var(--ink); }
.pb-eff .d { width: 7px; height: 7px; border-radius: 50%; }
.pb.low  .pb-eff .d { background: var(--sev-low); }
.pb.medium .pb-eff .d { background: var(--sev-medium); }
.pb.high .pb-eff .d { background: var(--sev-critical); }
.pb-count { font-family: var(--f-mono); font-size: 11px; color: var(--ink-3); }
.pb-list { display: flex; flex-direction: column; gap: 10px; }
.pb-item { font-size: 13px; line-height: 1.55; color: var(--ink-2); padding: 10px 12px; background: var(--bg); border: 1px solid var(--line); border-radius: 4px; }
.pb-item .meta { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; font-family: var(--f-mono); font-size: 10px; letter-spacing: 0.06em; color: var(--ink-4); }
.pb-item .meta .d { width: 5px; height: 5px; border-radius: 50%; }
.pb-code-wrap { position: relative; margin-top: 8px; }

/* ── Compliance ── */
.comp { background: var(--bg-1); border: 1px solid var(--line); border-radius: 6px; overflow: hidden; }
.comp table { width: 100%; border-collapse: collapse; font-size: 13px; }
.comp th { text-align: left; font-family: var(--f-mono); font-size: 10px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--ink-4); font-weight: 500; padding: 12px 18px; border-bottom: 1px solid var(--line); background: var(--bg); }
.comp td { padding: 12px 18px; border-bottom: 1px solid var(--line); color: var(--ink-2); vertical-align: top; }
.comp tr:last-child td { border-bottom: 0; }
.comp tr:hover td { background: var(--bg-2); }
.comp .code { font-family: var(--f-mono); font-size: 11.5px; color: var(--ink); white-space: nowrap; }
.comp .fail { display: inline-flex; align-items: center; gap: 6px; font-family: var(--f-mono); font-size: 11px; color: var(--sev-critical); }
.comp .fail .d { width: 6px; height: 6px; border-radius: 50%; background: var(--sev-critical); }

/* ── Attack Graph ── */
.graph-wrap { background: var(--bg-1); border: 1px solid var(--line); border-radius: 6px; padding: 22px; }
.graph-canvas-wrap { background: var(--bg-3); border-radius: 4px; overflow: hidden; position: relative; height: 520px; border: 1px solid var(--line); }
#cy-canvas { display: block; width: 100%; height: 100%; cursor: grab; }
#cy-canvas:active { cursor: grabbing; }
#cy-tip { position: absolute; display: none; pointer-events: none; background: var(--bg-2); border: 1px solid var(--line-3); border-radius: 6px; padding: 8px 11px; font-size: .78rem; font-family: var(--f-mono); color: var(--ink); max-width: 240px; box-shadow: 0 6px 20px rgba(0,0,0,.5); z-index: 20; line-height: 1.45; }
#cy-tip .tip-type { font-size: .68rem; color: var(--ink-3); margin-top: 3px; }
#cy-panel { position: absolute; right: 0; top: 0; bottom: 0; width: 260px; background: var(--bg-2); border-left: 1px solid var(--line-2); overflow-y: auto; transform: translateX(100%); transition: transform .18s ease; z-index: 10; }
#cy-panel.open { transform: translateX(0); }
.cy-panel-head { padding: 12px 14px 10px; border-bottom: 1px solid var(--line); display: flex; align-items: flex-start; gap: 8px; }
.cy-panel-close { margin-left: auto; cursor: pointer; color: var(--ink-3); font-size: 1.1rem; padding: 0 2px; flex-shrink: 0; line-height: 1; }
.cy-panel-close:hover { color: var(--ink); }
.cy-panel-body { padding: 12px 14px; }
.cy-p-type { font-family: var(--f-mono); font-size: .65rem; text-transform: uppercase; letter-spacing: .09em; color: var(--ink-4); margin-bottom: 4px; }
.cy-p-label { font-family: var(--f-mono); font-size: .8rem; font-weight: 700; color: var(--ink); line-height: 1.4; word-break: break-all; margin-bottom: 8px; }
.cy-p-sec-title { font-family: var(--f-mono); font-size: .65rem; text-transform: uppercase; letter-spacing: .09em; color: var(--ink-4); margin-bottom: 5px; margin-top: 10px; }
.cy-p-arn { font-family: var(--f-mono); font-size: .72rem; color: var(--ink-3); word-break: break-all; line-height: 1.5; }
.cy-p-nbr { font-family: var(--f-mono); font-size: .75rem; color: var(--ink-3); padding: 4px 0; border-bottom: 1px solid var(--line); display: flex; align-items: center; gap: 5px; }
.cy-p-nbr:last-child { border-bottom: none; }
.cy-ndot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
.cy-zoom-ctrls { position: absolute; top: 10px; right: 10px; display: flex; flex-direction: column; gap: 4px; z-index: 5; }
.cy-btn { padding: 3px 8px; background: var(--bg-2); border: 1px solid var(--line-2); color: var(--ink-3); border-radius: 4px; font-family: var(--f-mono); font-size: .75rem; cursor: pointer; transition: background .12s, color .12s; }
.cy-btn:hover { background: var(--bg-3); color: var(--ink); }
.graph-legend { display: flex; gap: 18px; margin-top: 16px; flex-wrap: wrap; font-family: var(--f-mono); font-size: 11px; color: var(--ink-3); }
.graph-legend .item { display: flex; align-items: center; gap: 8px; }
.graph-legend .d { width: 8px; height: 8px; border-radius: 2px; border: 1px solid; }
.graph-link { display: inline-block; margin-top: 12px; font-family: var(--f-mono); font-size: 11px; color: var(--accent); }
.graph-link:hover { text-decoration: underline; }

/* ── Footer ── */
.foot { padding: 32px 56px 56px; border-top: 1px solid var(--line); display: flex; justify-content: space-between; align-items: baseline; font-family: var(--f-mono); font-size: 11px; color: var(--ink-4); letter-spacing: 0.04em; }
.foot .name { color: var(--ink-3); }

/* ── Responsive ── */
@media (max-width: 1100px) {
  .app { grid-template-columns: 1fr; }
  .rail { display: none; }
  .hero { padding: 40px 24px; }
  .hero-title { font-size: 36px; }
  section.s { padding: 40px 24px 20px; }
  .kpi-strip { grid-template-columns: 1fr 1fr; }
  .kpi-strip .kpi { border-right: 0; border-bottom: 1px solid var(--line); }
  .playbook { grid-template-columns: 1fr; }
  .find-row { grid-template-columns: 90px 1fr; }
  .find-row .find-src, .find-row .find-id { display: none; }
  .find-detail .grid2 { grid-template-columns: 1fr; }
}
{% endraw %}
</style>
</head>
<body>

<div class="app" id="app">

<!-- ══════════ Rail ══════════ -->
<aside class="rail" id="rail">
  <div class="rail-brand">
    <div class="mark">
      <span class="dot"></span>
      <span class="name">CLEMENTINE</span>
    </div>
    <div class="sub">Security Assessment</div>
  </div>
  <div class="rail-section">REPORT</div>
  <a class="rail-link" href="#summary">Executive Summary</a>
  {% if chain_data %}
  <a class="rail-link" href="#chains">
    Attack Chains
    <span class="num crit">{{ "%02d"|format(chain_data|length) }}</span>
  </a>
  {% endif %}
  <a class="rail-link" href="#findings">
    Findings
    <span class="num">{{ "%03d"|format(total_findings) }}</span>
  </a>
  <a class="rail-link" href="#playbook">Remediation</a>
  {% if compliance_controls %}
  <a class="rail-link" href="#compliance">Compliance</a>
  {% endif %}
  {% if graph_json != '{}' %}
  <a class="rail-link" href="#graph">Attack Graph</a>
  {% endif %}
  <div class="rail-foot">
    <div class="row"><span>RUN</span><span>{{ generated_at.split(' ')[0] }}</span></div>
    <div class="row"><span>SCOPE</span><span>{{ target_url | truncate(16, True, '…') }}</span></div>
    <div class="row"><span>SCORE</span><span style="color:var(--sev-{{ risk_band }})">{{ risk_score }}/100</span></div>
    <div class="row"><span>STATUS</span><span style="color:var(--sev-{{ risk_band }})">● {{ risk_label.upper() }}</span></div>
  </div>
</aside>

<!-- ══════════ Main ══════════ -->
<main class="main">

<!-- ── Topbar ── -->
<div class="topbar">
  <span class="pulse"></span>
  <span class="crumb">Project <strong>Clementine</strong></span>
  <span class="sep">/</span>
  <span class="crumb">Security <strong>Assessment</strong></span>
  <span class="sep">/</span>
  <span class="crumb">Status <strong style="color:var(--sev-{{ risk_band }})">{{ risk_label }}</strong></span>
  <div class="right">
    <span class="target">{{ target_url }}</span>
    <span class="sep">·</span>
    <span>{{ generated_at }}</span>
  </div>
</div>

<!-- ── Hero / Executive Summary ── -->
<section class="hero" id="summary">
  <div class="hero-meta">
    <span class="dot"></span>
    <span class="verdict">{{ risk_label.upper() }}</span>
    <span class="sep"></span>
    <span>SCORE {{ risk_score }} / 100</span>
    <span class="sep"></span>
    <span>{{ total_findings }} FINDINGS</span>
    <span class="sep"></span>
    <span>{{ chain_data|length }} ATTACK CHAIN{{ 'S' if chain_data|length != 1 }}</span>
  </div>

  <h1 class="hero-title">{{ narrative_headline_html|safe }}</h1>

  <p class="hero-narrative">{{ narrative_body }}</p>

  <div class="kpi-strip">
    <div class="kpi score">
      <span class="kpi-label">Risk Score</span>
      <div class="gauge">
        <span class="big" style="color:var(--sev-{{ risk_band }})">{{ risk_score }}</span>
        <span class="denom">/ 100</span>
      </div>
      <div class="bar">
        <div class="bar-fill" style="right:{{ 100 - risk_score }}%;background:var(--sev-{{ risk_band }});box-shadow:0 0 8px var(--sev-{{ risk_band }})"></div>
      </div>
      <span class="kpi-foot" style="color:var(--sev-{{ risk_band }})">{{ risk_label }}</span>
    </div>
    <div class="kpi">
      <span class="kpi-label">Critical</span>
      <span class="kpi-value crit">{{ "%02d"|format(severity_counts['CRITICAL']) }}</span>
      <span class="kpi-foot">unauth-reachable</span>
    </div>
    <div class="kpi">
      <span class="kpi-label">High</span>
      <span class="kpi-value high">{{ "%02d"|format(severity_counts['HIGH']) }}</span>
      <span class="kpi-foot">needs attention</span>
    </div>
    <div class="kpi">
      <span class="kpi-label">Medium</span>
      <span class="kpi-value med">{{ "%02d"|format(severity_counts['MEDIUM']) }}</span>
      <span class="kpi-foot">posture + config</span>
    </div>
    <div class="kpi">
      <span class="kpi-label">Chains</span>
      <span class="kpi-value">{{ "%02d"|format(chain_data|length) }}</span>
      <span class="kpi-foot">compound paths</span>
    </div>
  </div>

  <div class="sev-hist">
    {% for sev in ['CRITICAL','HIGH','MEDIUM','LOW','INFO'] %}
    <div class="row">
      <span class="label">{{ sev }}</span>
      <div class="track">
        <div class="fill fill-{{ sev.lower() }}" style="width:{{ (severity_counts[sev] / hist_max * 100)|int if hist_max > 0 else 0 }}%"></div>
      </div>
      <span class="n">{{ "%03d"|format(severity_counts[sev]) }}</span>
    </div>
    {% endfor %}
  </div>
</section>

<!-- ── Attack Chains ── -->
{% if chain_data %}
<section class="s" id="chains">
  <div class="s-head">
    <span class="s-eyebrow">02 — Attack Chains</span>
    <h2 class="s-title">Compound attack paths through the stack.</h2>
    <span class="s-sub">{{ chain_data|length }} chain{{ 's' if chain_data|length != 1 }} &middot; all reachable</span>
  </div>
  <div class="chains">
    {% for cd in chain_data %}
    {% set chain = cd.chain %}
    {% set cidx = loop.index %}
    {% set sevlo = chain.severity.value.lower() %}
    <div class="chain {% if loop.first %}open{% endif %}" id="chain-{{ cidx }}">
      <div class="chain-row" onclick="toggleChain({{ cidx }})">
        <span class="badge b-{{ sevlo }}"><span class="d"></span>{{ chain.severity.value }}</span>
        <span class="chain-id">C-{{ "%02d"|format(cidx) }}</span>
        <span class="chain-name">{{ chain.pattern_name }}</span>
        <span class="chain-meta">
          {% if chain.chain_source == 'ai-discovered' %}
          <span class="tag ai">&#9670; AI-DISCOVERED</span>&nbsp;&nbsp;
          {% endif %}
          <strong>{{ cd.components|length }}</strong> STEPS
          {% if chain.breach_cost_low %}
          &nbsp;&middot;&nbsp; ~${{ "{:,.0f}".format(chain.breach_cost_low) }}&ndash;${{ "{:,.0f}".format(chain.breach_cost_high) }}
          {% endif %}
          &nbsp;&middot;&nbsp; BREAKS <strong>{{ cd.actions|selectattr('breaks_chain')|list|length }}</strong>
        </span>
        <span class="chain-chev">&#x203a;</span>
      </div>
      <div class="chain-body" id="cbody-{{ cidx }}">
        <p class="chain-narr">{{ chain.narrative | md_bold | safe }}</p>

        {% if cd.components %}
        <div class="steps">
          {% for comp_finding, role, order in cd.components %}
          <div class="step">
            <div class="step-idx {{ role.value.lower() }}">
              <span class="pip"></span>
              <span>{{ "%02d"|format(loop.index) }}</span>
            </div>
            <div class="step-body">
              <div class="step-title">{{ comp_finding.title }}</div>
              <div class="step-meta">
                <span class="tag role-{{ role.value.lower() }}">{{ role.value }}</span>
                <span>{{ comp_finding.source }}</span>
                <span>&middot;</span>
                <span>{{ comp_finding.category or comp_finding.source }}</span>
              </div>
            </div>
          </div>
          {% endfor %}
        </div>
        {% endif %}

        {% if cd.actions %}
        <div class="rem-list">
          <div class="head">REMEDIATION &middot; {{ cd.actions|length }} STEP{{ 'S' if cd.actions|length != 1 }}</div>
          {% for action in cd.actions %}
          <div class="rem {{ 'breaks' if action.breaks_chain }}">
            <span class="rem-eff {{ action.effort_level.value.lower() }}">{{ action.effort_level.value }} EFFORT</span>
            {% if action.breaks_chain %}
            <span class="tag" style="color:var(--sev-low);border-color:var(--sev-low-line);background:var(--sev-low-dim)">&#10003; BREAKS CHAIN</span>
            {% else %}
            <span class="tag">&#x2198; MITIGATES</span>
            {% endif %}
            <span>{{ action.action_summary }}</span>
            {% if action.cli_command %}
            <div class="rem-code" style="grid-column:1/-1;position:relative">
              <pre class="code">{{ action.cli_command }}</pre>
              <button class="copy-btn" onclick="copyPre(this)">copy</button>
            </div>
            {% endif %}
            {% if action.iac_snippet %}
            <div class="rem-code" style="grid-column:1/-1;position:relative">
              <pre class="code">{{ action.iac_snippet }}</pre>
              <button class="copy-btn" onclick="copyPre(this)">copy</button>
            </div>
            {% endif %}
          </div>
          {% endfor %}
        </div>
        {% endif %}
      </div>
    </div>
    {% endfor %}
  </div>
</section>
{% endif %}

<!-- ── Findings ── -->
<section class="s" id="findings">
  <div class="s-head">
    <span class="s-eyebrow">03 — Findings</span>
    <h2 class="s-title">All findings, grouped by OWASP category.</h2>
    <span class="s-sub">{{ total_findings }} total &middot; {{ findings_by_category|length }} categories</span>
  </div>

  <div class="find-toolbar">
    <input id="find-search" type="text" placeholder="Search findings, IDs, references&hellip;" oninput="applyFilters()">
    <div class="find-chips" id="find-chips">
      {% for sev in ['CRITICAL','HIGH','MEDIUM','LOW','INFO'] %}
      <span class="chip" id="chip-{{ sev }}"
            data-sev="{{ sev }}"
            onclick="toggleChip('{{ sev }}')"
            title="Filter to {{ sev }} only">
        <span class="d" style="background:var(--sev-{{ sev.lower() }})"></span>
        {{ sev }}
        <span class="n">{{ severity_counts[sev] }}</span>
      </span>
      {% endfor %}
    </div>
  </div>

  <div id="findings-list">
    {% for group in findings_by_category %}
    {% set gid = group.code | replace(' ', '_') %}
    <div class="cat open" id="cat-{{ gid }}" data-code="{{ group.code }}">
      <div class="cat-head" onclick="toggleCat('{{ gid }}')">
        <span class="cat-code">{{ group.code }}</span>
        <span class="cat-name">
          {{ group.name }}
          <span class="n" id="catcount-{{ gid }}">{{ group.findings|length }}</span>
        </span>
        <div class="cat-spark" aria-hidden="true">
          {% for sev in ['CRITICAL','HIGH','MEDIUM','LOW','INFO'] %}
          {% set sc = group.findings|selectattr('severity.value','equalto',sev)|list|length %}
          <span class="s" style="
            height:{{ (sc / (group.findings|length) * 16 + 2)|int }}px;
            background:var(--sev-{{ sev.lower() }});
            opacity:{{ '0.9' if sc else '0.15' }};
          "></span>
          {% endfor %}
        </div>
        <span class="cat-chev">&#x203a;</span>
      </div>
      <div class="cat-body" id="catbody-{{ gid }}">
        {% for f in group.findings %}
        {% set sevlo = f.severity.value.lower() %}
        {% set sevdisp = 'crit' if sevlo == 'critical' else sevlo %}
        <div class="find-row"
             id="frow-{{ f.id }}"
             data-sev="{{ f.severity.value }}"
             data-search="{{ (f.title ~ ' ' ~ (f.category or '') ~ ' ' ~ f.source ~ ' ' ~ f.id) | lower }}"
             onclick="toggleFinding('{{ f.id }}')">
          <span class="find-sev {{ sevdisp }}"><span class="d"></span>{{ f.severity.value }}</span>
          <span class="find-title">{{ f.title }}</span>
          <span class="find-src">{{ f.source }} &middot; {{ (f.category or '') | truncate(22, True, '…') }}</span>
          <span class="find-id">{{ f.id }}</span>
        </div>
        <div class="find-detail" id="fdetail-{{ f.id }}">
          <div>{{ f.description }}</div>
          <div class="grid2">
            <div>
              {% if f.remediation_summary %}
              <div class="lbl" style="margin-top:12px">Remediation</div>
              <div style="margin-top:6px">{{ f.remediation_summary }}</div>
              {% endif %}
              {% if f.triage_notes %}
              <div class="triage-note">&#x1F916; <strong style="color:var(--ink)">AI Triage:</strong> {{ f.triage_notes }}</div>
              {% endif %}
            </div>
            <div>
              {% if f.resource_id %}
              <div class="lbl">Resource</div>
              <div style="font-family:var(--f-mono);font-size:.8rem;word-break:break-all;margin-bottom:10px;margin-top:4px;color:var(--ink-2)">{{ f.resource_id }}</div>
              {% endif %}
              {% if f.remediation_cli %}
              <div class="lbl" style="margin-top:8px">CLI Fix</div>
              <div style="position:relative;margin-top:6px">
                <pre class="code">{{ f.remediation_cli }}</pre>
                <button class="copy-btn" onclick="copyPre(this)">copy</button>
              </div>
              {% endif %}
              {% if f.remediation_iac %}
              <div class="lbl" style="margin-top:10px">IaC</div>
              <div style="position:relative;margin-top:6px">
                <pre class="code">{{ f.remediation_iac }}</pre>
                <button class="copy-btn" onclick="copyPre(this)">copy</button>
              </div>
              {% endif %}
            </div>
          </div>
        </div>
        {% endfor %}
      </div>
    </div>
    {% endfor %}
  </div>
</section>

<!-- ── Remediation Playbook ── -->
<section class="s" id="playbook">
  <div class="s-head">
    <span class="s-eyebrow">04 — Remediation Playbook</span>
    <h2 class="s-title">Sequenced by effort, weighted by chain coverage.</h2>
    <span class="s-sub">{{ (playbook['LOW']|length) + (playbook['MEDIUM']|length) + (playbook['HIGH']|length) }} actions</span>
  </div>
  <div class="playbook">
    {% for eff_key, eff_title, eff_sub in [('LOW','Quick Wins','≤ 1 day each'),('MEDIUM','Medium Lift','1–5 days each'),('HIGH','Structural Work','1–4 weeks each')] %}
    {% set items = playbook[eff_key] %}
    {% if items %}
    <div class="pb {{ eff_key.lower() }}">
      <div class="pb-head">
        <span class="pb-eff"><span class="d"></span>{{ eff_title }}</span>
        <span class="pb-count">{{ items|length }} &middot; {{ eff_sub }}</span>
      </div>
      <div class="pb-list">
        {% for item in items %}
        <div class="pb-item">
          <div class="meta">
            <span class="d" style="background:var(--sev-critical)"></span>
            {% if item.breaks_chain %}
            <span style="color:var(--sev-low)">BREAKS CHAIN</span>
            {% endif %}
            <span>{{ item.chain_name }}</span>
          </div>
          {{ item.action_summary }}
          {% if item.cli_command %}
          <div class="pb-code-wrap" style="position:relative">
            <pre class="code">{{ item.cli_command }}</pre>
            <button class="copy-btn" onclick="copyPre(this)">copy</button>
          </div>
          {% endif %}
        </div>
        {% endfor %}
      </div>
    </div>
    {% else %}
    <div class="pb {{ eff_key.lower() }}">
      <div class="pb-head">
        <span class="pb-eff"><span class="d"></span>{{ eff_title }}</span>
        <span class="pb-count">0 &middot; {{ eff_sub }}</span>
      </div>
      <div style="font-family:var(--f-mono);font-size:11px;color:var(--ink-4);padding:16px 0">No actions in this tier.</div>
    </div>
    {% endif %}
    {% endfor %}
  </div>
</section>

<!-- ── Compliance Mapping ── -->
{% if compliance_controls %}
<section class="s" id="compliance">
  <div class="s-head">
    <span class="s-eyebrow">05 — Compliance Mapping</span>
    <h2 class="s-title">Where findings land against mapped frameworks.</h2>
    <span class="s-sub">{{ compliance_controls|length }} failing control{{ 's' if compliance_controls|length != 1 }}</span>
  </div>
  <div class="comp">
    <table>
      <thead>
        <tr>
          <th style="width:160px">Framework</th>
          <th>Control</th>
          <th style="width:110px">Status</th>
          <th style="width:80px;text-align:right">Findings</th>
          <th>Note</th>
        </tr>
      </thead>
      <tbody>
        {% for row in compliance_controls %}
        <tr>
          <td class="code">{{ row.framework }}</td>
          <td>{{ row.control }}</td>
          <td>
            <span class="fail"><span class="d"></span>Failing</span>
          </td>
          <td style="text-align:right;font-family:var(--f-mono);color:var(--ink)">{{ "%02d"|format(row.n_findings) }}</td>
          <td style="color:var(--ink-3)">{{ row.note }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</section>
{% endif %}

<!-- ── Attack Graph ── -->
{% if graph_json != '{}' %}
<section class="s tight" id="graph">
  <div class="s-head">
    <span class="s-eyebrow">06 — Attack Graph</span>
    <h2 class="s-title">Multi-hop attack surface — resources, trust, and exploit paths.</h2>
    <span class="s-sub">Hover to highlight &middot; click for details &middot; scroll to zoom</span>
  </div>
  <div class="graph-wrap">
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
      <span class="item"><span class="d" style="background:oklch(0.68 0.16 25/0.14);border-color:oklch(0.68 0.16 25/0.35)"></span>Critical</span>
      <span class="item"><span class="d" style="background:oklch(0.74 0.14 55/0.14);border-color:oklch(0.74 0.14 55/0.35)"></span>High</span>
      <span class="item"><span class="d" style="background:oklch(0.78 0.12 90/0.14);border-color:oklch(0.78 0.12 90/0.35)"></span>Medium</span>
      <span class="item"><span class="d" style="background:var(--accent-dim);border-color:var(--accent-line)"></span>Objective</span>
      <span class="item">&#x2014; solid chain edge</span>
      <span class="item">&#x2012;&#x2012; dashed lateral</span>
    </div>
  </div>
</section>
{% endif %}

<!-- ── Footer ── -->
<div class="foot">
  <span class="name">Project Clementine &mdash; Security Assessment Report</span>
  <span>Generated {{ generated_at }}{% if health_score != 'N/A' %} &middot; Cloud Health {{ health_score }}/100{% endif %}</span>
</div>

</main>
</div><!-- /app -->

<script>
// ── Chain accordion ──
function toggleChain(n) {
  var el = document.getElementById('chain-' + n);
  if (!el) return;
  el.classList.toggle('open');
}

// ── Finding detail ──
function toggleFinding(id) {
  var row = document.getElementById('frow-' + id);
  var det = document.getElementById('fdetail-' + id);
  if (!row || !det) return;
  var open = row.classList.toggle('open');
  det.style.display = open ? 'block' : 'none';
}

// ── Category accordion ──
function toggleCat(code) {
  var el = document.getElementById('cat-' + code);
  if (el) el.classList.toggle('open');
}

// ── Severity chip filter ──
var _activeChips = new Set();
function toggleChip(sev) {
  var chip = document.getElementById('chip-' + sev);
  if (_activeChips.has(sev)) {
    _activeChips.delete(sev);
    chip.classList.remove('on');
  } else {
    _activeChips.add(sev);
    chip.classList.add('on');
  }
  applyFilters();
}

// ── Live filter (search + severity chips) ──
function applyFilters() {
  var q = (document.getElementById('find-search').value || '').toLowerCase().trim();
  var cats = document.querySelectorAll('.cat');
  cats.forEach(function(cat) {
    var rows = cat.querySelectorAll('.find-row');
    var visCount = 0;
    rows.forEach(function(row) {
      var sevMatch = _activeChips.size === 0 || _activeChips.has(row.dataset.sev);
      var qMatch   = !q || row.dataset.search.includes(q);
      var show     = sevMatch && qMatch;
      row.style.display = show ? '' : 'none';
      var id = row.id.replace('frow-', '');
      var det = document.getElementById('fdetail-' + id);
      if (!show && det) { det.style.display = 'none'; row.classList.remove('open'); }
      if (show) visCount++;
    });
    var countEl = cat.querySelector('.cat-name .n');
    if (countEl) countEl.textContent = visCount;
    cat.style.display = visCount === 0 ? 'none' : '';
  });
}

// ── Copy code block ──
function copyPre(btn) {
  var pre = btn.previousElementSibling;
  if (!pre) return;
  navigator.clipboard.writeText(pre.textContent.trim()).then(function() {
    btn.textContent = 'copied!';
    setTimeout(function() { btn.textContent = 'copy'; }, 1600);
  });
}

// ── Scrollspy ──
var _railSections = ['summary','chains','findings','playbook','compliance','graph'];
var _railObserver = new IntersectionObserver(function(entries) {
  entries.forEach(function(e) {
    if (e.isIntersecting) {
      document.querySelectorAll('.rail-link').forEach(function(a) { a.classList.remove('active'); });
      var link = document.querySelector('.rail-link[href="#' + e.target.id + '"]');
      if (link) link.classList.add('active');
    }
  });
}, { rootMargin: '-10% 0px -70% 0px' });
_railSections.forEach(function(id) {
  var el = document.getElementById(id);
  if (el) _railObserver.observe(el);
});

{% if graph_json != '{}' %}
// ── Attack Graph ──
(function() {
  var _gdata  = {{ graph_json | safe }};
  var _gnodes = (_gdata.elements.nodes || []).map(function(n) { return Object.assign({}, n.data, {vx:0,vy:0,x:0,y:0}); });
  var _gedges = (_gdata.elements.edges || []).map(function(e) { return e.data; });
  var _gmap   = {};
  _gnodes.forEach(function(n) { _gmap[n.id] = n; });

  var _canvas = document.getElementById('cy-canvas');
  if (!_canvas || !_gnodes.length) return;
  var _ctx   = _canvas.getContext('2d');
  var _tip   = document.getElementById('cy-tip');
  var _panel = document.getElementById('cy-panel');

  function _gResize() { _canvas.width = _canvas.offsetWidth || 900; _canvas.height = _canvas.offsetHeight || 520; }

  var _CLUSTER = {
    iam_role:[.12,.40],iam_user:[.12,.62],eks_service_account:[.18,.28],
    ec2_instance:[.40,.30],eks_node:[.48,.22],eks_pod:[.55,.28],
    lambda_function:[.70,.22],s3_bucket:[.76,.68],rds_instance:[.55,.72],
    secrets_manager:[.88,.42],ssm_parameter:[.88,.60],vpc:[.25,.18],
    security_group:[.35,.14],vpc_endpoint:[.22,.52],web_endpoint:[.44,.68],imds:[.58,.50],
  };
  var _REP_K=220,_SPRING_K=110,_DAMP=.80,_gzoom=1,_gpanX=0,_gpanY=0,_gtick=0;
  var _gHovNode=null,_gSelNode=null,_gDragging=false,_glmx=0,_glmy=0;

  function _gInitPos() {
    var W=_canvas.width,H=_canvas.height;
    var cols=Math.ceil(Math.sqrt(_gnodes.length*(W/H)));
    var cw=W/(cols+1),ch=H/(Math.ceil(_gnodes.length/cols)+1);
    _gnodes.forEach(function(n,i){
      n.x=(i%cols+1)*cw+(Math.random()-.5)*cw*.5;
      n.y=(Math.floor(i/cols)+1)*ch+(Math.random()-.5)*ch*.5;
      n.vx=0;n.vy=0;
    });_gtick=0;
  }
  function _gSimulate() {
    if(_gtick>400)return;_gtick++;
    var W=_canvas.width,H=_canvas.height,i,j,dx,dy,d,minD,fMag,fx,fy;
    for(i=0;i<_gnodes.length;i++)for(j=i+1;j<_gnodes.length;j++){
      dx=_gnodes[j].x-_gnodes[i].x||.01;dy=_gnodes[j].y-_gnodes[i].y||.01;
      d=Math.sqrt(dx*dx+dy*dy)||.01;if(d>400)continue;
      minD=(_gnodes[i].radius||10)+(_gnodes[j].radius||10)+22;
      fMag=d<minD?_REP_K*_REP_K*6/d:_REP_K*_REP_K/d;fx=fMag*dx/d;fy=fMag*dy/d;
      _gnodes[i].vx-=fx;_gnodes[i].vy-=fy;_gnodes[j].vx+=fx;_gnodes[j].vy+=fy;
    }
    _gedges.forEach(function(e){
      var s=_gmap[e.source],t=_gmap[e.target];if(!s||!t)return;
      var edx=t.x-s.x,edy=t.y-s.y,ed=Math.sqrt(edx*edx+edy*edy)||1;
      var ef=(ed-_SPRING_K)/ed*.09;
      s.vx+=ef*edx;s.vy+=ef*edy;t.vx-=ef*edx;t.vy-=ef*edy;
    });
    _gnodes.forEach(function(n){
      var cl=_CLUSTER[n.type]||[.5,.5];
      n.vx+=(cl[0]*W-n.x)*.008;n.vy+=(cl[1]*H-n.y)*.008;
      n.vx*=_DAMP;n.vy*=_DAMP;var r=(n.radius||10)+8;
      n.x=Math.max(r,Math.min(W-r,n.x+n.vx));n.y=Math.max(r,Math.min(H-r,n.y+n.vy));
    });
  }
  function _gNbrSet(id){var s={};s[id]=true;_gedges.forEach(function(e){if(e.source===id)s[e.target]=true;if(e.target===id)s[e.source]=true;});return s;}
  function _gDraw(){
    var W=_canvas.width,H=_canvas.height;_ctx.clearRect(0,0,W,H);_ctx.save();_ctx.translate(_gpanX,_gpanY);_ctx.scale(_gzoom,_gzoom);
    var nbrs=_gHovNode?_gNbrSet(_gHovNode.id):null;
    _gedges.forEach(function(e){
      var s=_gmap[e.source],t=_gmap[e.target];if(!s||!t)return;
      var hi=_gHovNode&&(e.source===_gHovNode.id||e.target===_gHovNode.id);
      _ctx.globalAlpha=hi?.92:(_gHovNode?.12:.42);
      _ctx.beginPath();_ctx.setLineDash(e.dashed?[5,3]:[]);
      _ctx.moveTo(s.x,s.y);_ctx.lineTo(t.x,t.y);
      _ctx.strokeStyle=e.color||'#3a424c';_ctx.lineWidth=hi?2.5/_gzoom:1.5/_gzoom;_ctx.stroke();
      if(hi){var angle=Math.atan2(t.y-s.y,t.x-s.x),tr=(t.radius||10)+4,ax=t.x-tr*Math.cos(angle),ay=t.y-tr*Math.sin(angle);
        _ctx.setLineDash([]);_ctx.beginPath();_ctx.moveTo(ax,ay);
        _ctx.lineTo(ax-9*Math.cos(angle-.4),ay-9*Math.sin(angle-.4));
        _ctx.lineTo(ax-9*Math.cos(angle+.4),ay-9*Math.sin(angle+.4));
        _ctx.closePath();_ctx.fillStyle=e.color||'#3a424c';_ctx.fill();
      }
    });
    _ctx.setLineDash([]);_ctx.globalAlpha=1;
    _gnodes.forEach(function(n){
      var r=n.radius||10,isHov=_gHovNode&&_gHovNode.id===n.id,isSel=_gSelNode&&_gSelNode.id===n.id;
      var dim=nbrs&&!nbrs[n.id];_ctx.globalAlpha=dim?.18:1;
      if(isSel){_ctx.beginPath();_ctx.arc(n.x,n.y,r+6,0,Math.PI*2);_ctx.strokeStyle='#e8eaed';_ctx.lineWidth=2/_gzoom;_ctx.stroke();}
      _ctx.beginPath();_ctx.arc(n.x,n.y,isHov?r+3:r,0,Math.PI*2);_ctx.fillStyle=n.color||'#4a5058';_ctx.fill();
      if(n.border_color&&n.border_color!=='#94a3b8'){_ctx.strokeStyle=n.border_color;_ctx.lineWidth=(isHov?3:2)/_gzoom;_ctx.stroke();}
    });_ctx.globalAlpha=1;_ctx.restore();
  }
  window._gZoomFit=function(){
    if(!_gnodes.length)return;var x0=Infinity,x1=-Infinity,y0=Infinity,y1=-Infinity;
    _gnodes.forEach(function(n){var r=(n.radius||10)+4;if(n.x-r<x0)x0=n.x-r;if(n.x+r>x1)x1=n.x+r;if(n.y-r<y0)y0=n.y-r;if(n.y+r>y1)y1=n.y+r;});
    var W=_canvas.width,H=_canvas.height,pad=40,sx=(W-pad*2)/(x1-x0||1),sy=(H-pad*2)/(y1-y0||1);
    _gzoom=Math.min(sx,sy,3);_gpanX=pad-x0*_gzoom+((W-pad*2)-(x1-x0)*_gzoom)/2;_gpanY=pad-y0*_gzoom+((H-pad*2)-(y1-y0)*_gzoom)/2;
  };
  window._gZoomBy=function(f){var cx=_canvas.width/2,cy=_canvas.height/2,nz=Math.max(.2,Math.min(5,_gzoom*f));_gpanX=cx-(cx-_gpanX)*(nz/_gzoom);_gpanY=cy-(cy-_gpanY)*(nz/_gzoom);_gzoom=nz;};
  function _gHit(ox,oy){var wx=(ox-_gpanX)/_gzoom,wy=(oy-_gpanY)/_gzoom;for(var i=_gnodes.length-1;i>=0;i--){var n=_gnodes[i],r=(n.radius||10)+5;if((wx-n.x)*(wx-n.x)+(wy-n.y)*(wy-n.y)<=r*r)return n;}return null;}

  function _gOpenPanel(n){
    _gSelNode=n;
    document.getElementById('cy-p-type').textContent=(n.type||'').replace(/_/g,' ');
    document.getElementById('cy-p-label').textContent=n.label||n.id;
    var badges=document.getElementById('cy-p-badges');badges.innerHTML='';
    if(n.severity){var b=document.createElement('span');b.className='badge b-'+n.severity.toLowerCase();b.textContent=n.severity;badges.appendChild(b);}
    document.getElementById('cy-p-arn').textContent=n.id;
    var nbrsEl=document.getElementById('cy-p-neighbors');nbrsEl.innerHTML='';
    _gedges.forEach(function(e){
      var other=null,dir='';
      if(e.source===n.id){other=_gmap[e.target];dir='→ ';}
      if(e.target===n.id){other=_gmap[e.source];dir='← ';}
      if(!other)return;
      var row=document.createElement('div');row.className='cy-p-nbr';
      var dot=document.createElement('span');dot.className='cy-ndot';dot.style.background=other.color||'#4a5058';row.appendChild(dot);
      var txt=document.createElement('span');txt.style.flex='1';txt.textContent=dir+(other.label||other.id).slice(0,30);row.appendChild(txt);
      var rel=document.createElement('span');rel.style.cssText='font-size:.65rem;color:var(--ink-4)';rel.textContent=e.label||'';row.appendChild(rel);
      nbrsEl.appendChild(row);
    });
    document.getElementById('cy-p-nbr-wrap').style.display=nbrsEl.children.length?'':'none';
    _panel.classList.add('open');
  }
  window._gClosePanel=function(){_panel.classList.remove('open');_gSelNode=null;};

  _canvas.addEventListener('mousedown',function(e){_gDragging=true;_glmx=e.offsetX;_glmy=e.offsetY;});
  _canvas.addEventListener('mouseup',function(e){
    if(!_gDragging)return;var moved=Math.abs(e.offsetX-_glmx)+Math.abs(e.offsetY-_glmy);_gDragging=false;
    if(moved<4){var n=_gHit(e.offsetX,e.offsetY);if(n)_gOpenPanel(n);else _gClosePanel();}
  });
  _canvas.addEventListener('mouseleave',function(){_gDragging=false;_gHovNode=null;if(_tip)_tip.style.display='none';});
  _canvas.addEventListener('mousemove',function(e){
    if(_gDragging){_gpanX+=e.offsetX-_glmx;_gpanY+=e.offsetY-_glmy;_glmx=e.offsetX;_glmy=e.offsetY;return;}
    var n=_gHit(e.offsetX,e.offsetY);_gHovNode=n;
    if(n&&_tip){
      _canvas.style.cursor='pointer';
      var tx=Math.min(e.offsetX+14,_canvas.offsetWidth-250),ty=Math.max(e.offsetY-50,4);
      _tip.style.left=tx+'px';_tip.style.top=ty+'px';_tip.style.display='block';
      _tip.innerHTML='<strong style="color:var(--ink)">'+(n.label||n.id).slice(0,48)+'</strong><div class="tip-type">'+(n.type||'').replace(/_/g,' ')+'</div>';
    }else{_canvas.style.cursor=_gDragging?'grabbing':'grab';if(_tip)_tip.style.display='none';}
  });
  _canvas.addEventListener('wheel',function(e){
    e.preventDefault();var f=e.deltaY<0?1.12:1/1.12,nz=Math.max(.15,Math.min(6,_gzoom*f));
    _gpanX=e.offsetX-(e.offsetX-_gpanX)*(nz/_gzoom);_gpanY=e.offsetY-(e.offsetY-_gpanY)*(nz/_gzoom);_gzoom=nz;
  },{passive:false});
  window.addEventListener('resize',function(){_gResize();_gInitPos();});
  _gResize();_gInitPos();
  for(var _pi=0;_pi<280;_pi++)_gSimulate();
  window._gZoomFit();
  (function _gLoop(){_gSimulate();_gDraw();requestAnimationFrame(_gLoop);})();
})();
{% endif %}
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Full-size graph page template (dark-mode updated)
# ---------------------------------------------------------------------------

_GRAPH_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Attack Graph &mdash; {{ target_url }}</title>
<style>
{% raw %}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0c0f;color:#e8eaed;font-family:'JetBrains Mono',ui-monospace,monospace;height:100vh;overflow:hidden;display:flex;flex-direction:column}
.hdr{display:flex;align-items:center;gap:12px;padding:9px 18px;background:#0f1216;border-bottom:1px solid #1f242c;flex-shrink:0}
.hdr-title{font-size:.875rem;font-weight:700;color:#e8eaed}
.hdr-sub{font-size:.75rem;color:#4a5058}
.hdr-sep{width:1px;height:18px;background:#1f242c;margin:0 2px}
.hdr-stat{font-size:.75rem;color:#4a5058;padding:2px 8px;background:#161a20;border-radius:3px}
.hdr-stat strong{color:#e8eaed}
.ctrl{display:flex;align-items:center;gap:6px;margin-left:auto}
.btn{padding:4px 12px;background:#161a20;border:1px solid #2a3038;color:#7a818b;border-radius:4px;font-size:.75rem;cursor:pointer;transition:background .12s,color .12s}
.btn:hover{background:#1c2128;color:#e8eaed}
.btn-icon{padding:4px 9px}
.main{flex:1;display:flex;overflow:hidden;position:relative}
#gc{display:block;flex:1;cursor:grab}
#gc:active{cursor:grabbing}
#tip{position:absolute;display:none;pointer-events:none;background:#161a20;border:1px solid #3a424c;border-radius:6px;padding:8px 11px;font-size:.78rem;color:#e8eaed;max-width:240px;box-shadow:0 6px 20px rgba(0,0,0,.5);z-index:20;line-height:1.45}
#tip .tip-type{font-size:.68rem;color:#4a5058;margin-top:3px}
#panel{position:absolute;right:0;top:0;bottom:0;width:280px;background:#0f1216;border-left:1px solid #1f242c;overflow-y:auto;transform:translateX(100%);transition:transform .18s ease;z-index:10}
#panel.open{transform:translateX(0)}
.panel-head{padding:14px 16px 10px;border-bottom:1px solid #1f242c;display:flex;align-items:flex-start;gap:8px}
.panel-close{margin-left:auto;cursor:pointer;color:#4a5058;font-size:1.1rem;padding:0 2px;flex-shrink:0;line-height:1}
.panel-close:hover{color:#e8eaed}
.panel-body{padding:14px 16px}
.p-type{font-size:.65rem;text-transform:uppercase;letter-spacing:.09em;color:#4a5058;margin-bottom:5px}
.p-label{font-size:.875rem;font-weight:700;color:#e8eaed;line-height:1.4;word-break:break-all;margin-bottom:10px}
.p-section{margin-top:12px}
.p-sec-title{font-size:.65rem;text-transform:uppercase;letter-spacing:.09em;color:#4a5058;margin-bottom:6px}
.p-arn{font-size:.72rem;color:#7a818b;word-break:break-all;line-height:1.5}
.p-neighbor{font-size:.75rem;color:#7a818b;padding:4px 0;border-bottom:1px solid #1f242c;display:flex;align-items:center;gap:6px}
.p-neighbor:last-child{border-bottom:none}
.ndot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.legend{position:absolute;bottom:12px;left:12px;background:rgba(10,12,15,.88);backdrop-filter:blur(4px);border:1px solid #1f242c;border-radius:6px;padding:9px 13px;display:flex;flex-wrap:wrap;gap:5px 14px;font-size:.72rem;color:#4a5058;z-index:5;max-width:540px}
.li{display:flex;align-items:center;gap:5px;white-space:nowrap}
.ldot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.lline{width:16px;height:2px;flex-shrink:0}
.zoom-ctrls{position:absolute;top:12px;right:12px;display:flex;flex-direction:column;gap:4px;z-index:5}
{% endraw %}
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
</div>
<script>
var DATA={{ graph_json | safe }};
var canvas=document.getElementById('gc'),ctx=canvas.getContext('2d'),tip=document.getElementById('tip'),panel=document.getElementById('panel');
var nodes=(DATA.elements.nodes||[]).map(function(n){return Object.assign({},n.data,{x:0,y:0,vx:0,vy:0});});
var edges=(DATA.elements.edges||[]).map(function(e){return e.data;});
var nmap={};nodes.forEach(function(n){nmap[n.id]=n;});
document.getElementById('stat-n').textContent=nodes.length;
document.getElementById('stat-e').textContent=edges.length;
var CLUSTER={iam_role:[.12,.40],iam_user:[.12,.62],eks_service_account:[.18,.28],ec2_instance:[.40,.30],eks_node:[.48,.22],eks_pod:[.55,.28],lambda_function:[.70,.22],s3_bucket:[.76,.68],rds_instance:[.55,.72],secrets_manager:[.88,.42],ssm_parameter:[.88,.60],vpc:[.25,.18],security_group:[.35,.14],vpc_endpoint:[.22,.52],web_endpoint:[.44,.68],imds:[.58,.50]};
var REP_K=220,SPRING_K=110,DAMP=.80,zoom=1,panX=0,panY=0,tick=0,hovNode=null,selNode=null,dragging=false,lmx=0,lmy=0;
function resize(){canvas.width=canvas.offsetWidth||canvas.parentElement.offsetWidth||900;canvas.height=canvas.offsetHeight||canvas.parentElement.offsetHeight||600;}
function initPos(){var W=canvas.width,H=canvas.height,cols=Math.ceil(Math.sqrt(nodes.length*(W/H))),cw=W/(cols+1),ch=H/(Math.ceil(nodes.length/cols)+1);nodes.forEach(function(n,i){n.x=(i%cols+1)*cw+(Math.random()-.5)*cw*.5;n.y=(Math.floor(i/cols)+1)*ch+(Math.random()-.5)*ch*.5;n.vx=0;n.vy=0;});tick=0;}
function simulate(){if(tick>400)return;tick++;var W=canvas.width,H=canvas.height,i,j,dx,dy,d,minD,fMag,fx,fy;for(i=0;i<nodes.length;i++)for(j=i+1;j<nodes.length;j++){dx=nodes[j].x-nodes[i].x||.01;dy=nodes[j].y-nodes[i].y||.01;d=Math.sqrt(dx*dx+dy*dy)||.01;if(d>400)continue;minD=(nodes[i].radius||10)+(nodes[j].radius||10)+22;fMag=d<minD?REP_K*REP_K*6/d:REP_K*REP_K/d;fx=fMag*dx/d;fy=fMag*dy/d;nodes[i].vx-=fx;nodes[i].vy-=fy;nodes[j].vx+=fx;nodes[j].vy+=fy;}edges.forEach(function(e){var s=nmap[e.source],t=nmap[e.target];if(!s||!t)return;var edx=t.x-s.x,edy=t.y-s.y,ed=Math.sqrt(edx*edx+edy*edy)||1,ef=(ed-SPRING_K)/ed*.09;s.vx+=ef*edx;s.vy+=ef*edy;t.vx-=ef*edx;t.vy-=ef*edy;});nodes.forEach(function(n){var cl=CLUSTER[n.type]||[.5,.5];n.vx+=(cl[0]*W-n.x)*.008;n.vy+=(cl[1]*H-n.y)*.008;n.vx*=DAMP;n.vy*=DAMP;var r=(n.radius||10)+8;n.x=Math.max(r,Math.min(W-r,n.x+n.vx));n.y=Math.max(r,Math.min(H-r,n.y+n.vy));});}
function neighborSet(id){var s={};s[id]=true;edges.forEach(function(e){if(e.source===id)s[e.target]=true;if(e.target===id)s[e.source]=true;});return s;}
function draw(){var W=canvas.width,H=canvas.height;ctx.clearRect(0,0,W,H);ctx.save();ctx.translate(panX,panY);ctx.scale(zoom,zoom);var nbrs=hovNode?neighborSet(hovNode.id):null;edges.forEach(function(e){var s=nmap[e.source],t=nmap[e.target];if(!s||!t)return;var hi=hovNode&&(e.source===hovNode.id||e.target===hovNode.id);ctx.globalAlpha=hi?.92:(hovNode?.12:.42);ctx.beginPath();ctx.setLineDash(e.dashed?[5,3]:[]);ctx.moveTo(s.x,s.y);ctx.lineTo(t.x,t.y);ctx.strokeStyle=e.color||'#3a424c';ctx.lineWidth=hi?2.5/zoom:1.5/zoom;ctx.stroke();if(hi){var angle=Math.atan2(t.y-s.y,t.x-s.x),tr=(t.radius||10)+4,ax=t.x-tr*Math.cos(angle),ay=t.y-tr*Math.sin(angle);ctx.setLineDash([]);ctx.beginPath();ctx.moveTo(ax,ay);ctx.lineTo(ax-9*Math.cos(angle-.4),ay-9*Math.sin(angle-.4));ctx.lineTo(ax-9*Math.cos(angle+.4),ay-9*Math.sin(angle+.4));ctx.closePath();ctx.fillStyle=e.color||'#3a424c';ctx.fill();}});ctx.setLineDash([]);ctx.globalAlpha=1;nodes.forEach(function(n){var r=n.radius||10,isHov=hovNode&&hovNode.id===n.id,isSel=selNode&&selNode.id===n.id,dim=nbrs&&!nbrs[n.id];ctx.globalAlpha=dim?.18:1;if(isSel){ctx.beginPath();ctx.arc(n.x,n.y,r+6,0,Math.PI*2);ctx.strokeStyle='#e8eaed';ctx.lineWidth=2/zoom;ctx.stroke();}ctx.beginPath();ctx.arc(n.x,n.y,isHov?r+3:r,0,Math.PI*2);ctx.fillStyle=n.color||'#4a5058';ctx.fill();if(n.border_color&&n.border_color!=='#94a3b8'){ctx.strokeStyle=n.border_color;ctx.lineWidth=(isHov?3:2)/zoom;ctx.stroke();}});ctx.globalAlpha=1;ctx.restore();}
function zoomFit(){if(!nodes.length)return;var x0=Infinity,x1=-Infinity,y0=Infinity,y1=-Infinity;nodes.forEach(function(n){var r=(n.radius||10)+4;if(n.x-r<x0)x0=n.x-r;if(n.x+r>x1)x1=n.x+r;if(n.y-r<y0)y0=n.y-r;if(n.y+r>y1)y1=n.y+r;});var W=canvas.width,H=canvas.height,pad=40,sx=(W-pad*2)/(x1-x0||1),sy=(H-pad*2)/(y1-y0||1);zoom=Math.min(sx,sy,3);panX=pad-x0*zoom+((W-pad*2)-(x1-x0)*zoom)/2;panY=pad-y0*zoom+((H-pad*2)-(y1-y0)*zoom)/2;}
function zoomBy(f){var cx=canvas.width/2,cy=canvas.height/2,nz=Math.max(.2,Math.min(5,zoom*f));panX=cx-(cx-panX)*(nz/zoom);panY=cy-(cy-panY)*(nz/zoom);zoom=nz;}
function resetView(){zoom=1;panX=0;panY=0;}
function hit(ox,oy){var wx=(ox-panX)/zoom,wy=(oy-panY)/zoom;for(var i=nodes.length-1;i>=0;i--){var n=nodes[i],r=(n.radius||10)+5;if((wx-n.x)*(wx-n.x)+(wy-n.y)*(wy-n.y)<=r*r)return n;}return null;}
function openPanel(n){selNode=n;document.getElementById('p-type').textContent=(n.type||'').replace(/_/g,' ');document.getElementById('p-label').textContent=n.label||n.id;document.getElementById('p-arn').textContent=n.id;var nb=document.getElementById('p-neighbors');nb.innerHTML='';edges.forEach(function(e){var o=null,dir='';if(e.source===n.id){o=nmap[e.target];dir='→ ';}if(e.target===n.id){o=nmap[e.source];dir='← ';}if(!o)return;var row=document.createElement('div');row.className='p-neighbor';var dot=document.createElement('span');dot.className='ndot';dot.style.background=o.color||'#4a5058';row.appendChild(dot);var txt=document.createElement('span');txt.style.flex='1';txt.textContent=dir+(o.label||o.id).slice(0,30);row.appendChild(txt);nb.appendChild(row);});document.getElementById('p-nbr-wrap').style.display=nb.children.length?'':'none';panel.classList.add('open');}
function closePanel(){panel.classList.remove('open');selNode=null;}
canvas.addEventListener('mousedown',function(e){dragging=true;lmx=e.offsetX;lmy=e.offsetY;});
canvas.addEventListener('mouseup',function(e){if(!dragging)return;var moved=Math.abs(e.offsetX-lmx)+Math.abs(e.offsetY-lmy);dragging=false;if(moved<4){var n=hit(e.offsetX,e.offsetY);if(n)openPanel(n);else closePanel();}});
canvas.addEventListener('mouseleave',function(){dragging=false;hovNode=null;tip.style.display='none';});
canvas.addEventListener('mousemove',function(e){if(dragging){panX+=e.offsetX-lmx;panY+=e.offsetY-lmy;lmx=e.offsetX;lmy=e.offsetY;return;}var n=hit(e.offsetX,e.offsetY);hovNode=n;if(n){canvas.style.cursor='pointer';var tx=Math.min(e.offsetX+14,canvas.offsetWidth-250),ty=Math.max(e.offsetY-50,4);tip.style.left=tx+'px';tip.style.top=ty+'px';tip.style.display='block';tip.innerHTML='<strong style="color:#e8eaed">'+(n.label||n.id).slice(0,48)+'</strong><div class="tip-type">'+(n.type||'').replace(/_/g,' ')+'</div>';}else{canvas.style.cursor=dragging?'grabbing':'grab';tip.style.display='none';}});
canvas.addEventListener('wheel',function(e){e.preventDefault();var f=e.deltaY<0?1.12:1/1.12,nz=Math.max(.15,Math.min(6,zoom*f));panX=e.offsetX-(e.offsetX-panX)*(nz/zoom);panY=e.offsetY-(e.offsetY-panY)*(nz/zoom);zoom=nz;},{passive:false});
window.addEventListener('resize',function(){resize();initPos();});
resize();initPos();for(var pi=0;pi<280;pi++)simulate();zoomFit();
(function loop(){simulate();draw();requestAnimationFrame(loop);})();
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

        env = Environment(loader=BaseLoader(), autoescape=True)
        env.filters["md_bold"] = _md_bold

        graph_path = ""
        if graph_json != "{}":
            graph_page_path = output_path.parent / "graph.html"
            try:
                graph_tmpl = env.from_string(_GRAPH_TEMPLATE)
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

        template = env.from_string(_HTML_TEMPLATE)
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
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")

import os
from datetime import datetime
from jinja2 import Template
from config import (
    TOOL_NAME, TOOL_VERSION, TOOL_AUTHOR,
    STATUS_PASS, STATUS_FAIL, STATUS_WARN, STATUS_INFO, STATUS_ERROR, STATUS_SKIP,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO,
)

REPORT_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ tool_name }} Report &mdash; {{ metadata.domain }}</title>
<style>
:root {
  --bg: #0f1117;
  --surface: #181b23;
  --card: #1e222d;
  --border: #2a2e3a;
  --text: #e2e4ea;
  --text-muted: #8b8fa3;
  --accent: #6c8cff;
  --pass: #2ecc71;
  --fail: #e74c3c;
  --warn: #f39c12;
  --info-clr: #3498db;
  --error-clr: #7f8c8d;
  --skip-clr: #7f8c8d;
  --sev-critical: #c0392b;
  --sev-high: #e74c3c;
  --sev-medium: #e67e22;
  --sev-low: #f1c40f;
  --sev-info: #3498db;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 16px; }
h1 { font-size: 1.8rem; margin-bottom: .25rem; }
h2 { font-size: 1.35rem; color: var(--accent); margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: .5rem; }
h3 { font-size: 1.1rem; margin: 1rem 0 .5rem; }
.header { background: var(--surface); padding: 2rem; border-radius: 12px; margin-bottom: 2rem; border: 1px solid var(--border); }
.header .sub { color: var(--text-muted); font-size: .9rem; }
.meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-top: 1rem; }
.meta-item { background: var(--card); padding: 10px 14px; border-radius: 8px; border: 1px solid var(--border); }
.meta-item .label { font-size: .75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: .05em; }
.meta-item .value { font-size: 1rem; font-weight: 600; margin-top: 2px; }

/* Stats row */
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; margin: 1.5rem 0; }
.stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; text-align: center; }
.stat-card .num { font-size: 2rem; font-weight: 700; }
.stat-card .lbl { font-size: .8rem; color: var(--text-muted); margin-top: 2px; }
.stat-card.pass .num { color: var(--pass); }
.stat-card.fail .num { color: var(--fail); }
.stat-card.warn .num { color: var(--warn); }
.stat-card.info .num { color: var(--info-clr); }
.stat-card.total .num { color: var(--accent); }

/* Severity bar chart */
.sev-chart { margin: 1.5rem 0; }
.sev-row { display: flex; align-items: center; margin-bottom: 8px; }
.sev-row .sev-label { width: 90px; font-size: .85rem; font-weight: 600; }
.sev-row .sev-bar-bg { flex: 1; background: var(--surface); border-radius: 6px; height: 24px; overflow: hidden; }
.sev-row .sev-bar { height: 100%; border-radius: 6px; display: flex; align-items: center; padding-left: 8px; font-size: .75rem; font-weight: 600; color: #fff; min-width: fit-content; transition: width .4s ease; }
.sev-bar.critical { background: var(--sev-critical); }
.sev-bar.high { background: var(--sev-high); }
.sev-bar.medium { background: var(--sev-medium); }
.sev-bar.low { background: var(--sev-low); }
.sev-bar.info { background: var(--sev-info); }

/* Test matrix table */
table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: .88rem; }
thead th { background: var(--surface); color: var(--text-muted); text-align: left; padding: 10px 12px; font-weight: 600; text-transform: uppercase; font-size: .75rem; letter-spacing: .04em; border-bottom: 2px solid var(--border); position: sticky; top: 0; }
tbody td { padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
tbody tr:hover { background: var(--surface); }
.badge { display: inline-block; padding: 2px 10px; border-radius: 4px; font-size: .78rem; font-weight: 600; text-transform: uppercase; letter-spacing: .03em; }
.badge-pass { background: rgba(46,204,113,.15); color: var(--pass); }
.badge-fail { background: rgba(231,76,60,.15); color: var(--fail); }
.badge-warn { background: rgba(243,156,18,.15); color: var(--warn); }
.badge-info { background: rgba(52,152,219,.15); color: var(--info-clr); }
.badge-error { background: rgba(127,140,141,.15); color: var(--error-clr); }
.badge-skip { background: rgba(127,140,141,.15); color: var(--skip-clr); }
.badge-critical { background: rgba(192,57,43,.18); color: var(--sev-critical); }
.badge-high { background: rgba(231,76,60,.15); color: var(--sev-high); }
.badge-medium { background: rgba(230,126,34,.15); color: var(--sev-medium); }
.badge-low { background: rgba(241,196,15,.15); color: var(--sev-low); }
.badge-sev-info { background: rgba(52,152,219,.15); color: var(--sev-info); }

/* Finding cards */
.finding-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; margin-bottom: 16px; }
.finding-card.sev-border-critical { border-left: 4px solid var(--sev-critical); }
.finding-card.sev-border-high { border-left: 4px solid var(--sev-high); }
.finding-card.sev-border-medium { border-left: 4px solid var(--sev-medium); }
.finding-card.sev-border-low { border-left: 4px solid var(--sev-low); }
.finding-card.sev-border-info { border-left: 4px solid var(--sev-info); }
.finding-title { display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 8px; margin-bottom: 10px; }
.finding-title h3 { margin: 0; font-size: 1.05rem; }
.finding-badges { display: flex; gap: 6px; flex-shrink: 0; }
.finding-section { margin-top: 12px; }
.finding-section .sec-title { font-size: .78rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: .04em; margin-bottom: 4px; font-weight: 600; }
.finding-section p, .finding-section pre { font-size: .88rem; }
.finding-section pre { background: var(--surface); padding: 10px 14px; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace; font-size: .82rem; max-height: 300px; overflow-y: auto; }
.affected-list { list-style: none; padding: 0; }
.affected-list li { padding: 3px 0; font-size: .86rem; font-family: 'Cascadia Code', 'Consolas', monospace; }
.affected-list li::before { content: "\25B8 "; color: var(--accent); }
.ref-link { color: var(--accent); text-decoration: none; font-size: .86rem; }
.ref-link:hover { text-decoration: underline; }
.cve-tag { background: rgba(192,57,43,.2); color: #e74c3c; padding: 2px 8px; border-radius: 4px; font-size: .8rem; font-weight: 600; font-family: monospace; }

/* Risk summary */
.risk-group { margin-bottom: 1.5rem; }
.risk-group-header { display: flex; align-items: center; gap: 10px; margin-bottom: .5rem; }
.risk-count { font-size: 1.3rem; font-weight: 700; }

/* Footer */
.footer { margin-top: 3rem; padding: 1.5rem; background: var(--surface); border-radius: 10px; border: 1px solid var(--border); text-align: center; color: var(--text-muted); font-size: .82rem; }

/* Responsive */
@media (max-width: 700px) {
  .container { padding: 8px; }
  .stats { grid-template-columns: repeat(2, 1fr); }
  table { font-size: .8rem; }
  thead th, tbody td { padding: 6px 8px; }
}
@media print {
  body { background: #fff; color: #111; }
  .header, .stat-card, .finding-card, .footer, .meta-item { border-color: #ccc; background: #fafafa; }
  .sev-bar { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
}
</style>
</head>
<body>
<div class="container">

<div class="header">
  <h1>{{ tool_name }} v{{ tool_version }}</h1>
  <div class="sub">Active Directory Security Assessment Report</div>
  <div class="meta-grid">
    <div class="meta-item"><div class="label">Domain</div><div class="value">{{ metadata.domain }}</div></div>
    <div class="meta-item"><div class="label">Domain Controller</div><div class="value">{{ metadata.dc }}</div></div>
    <div class="meta-item"><div class="label">Authenticated As</div><div class="value">{{ metadata.username }}</div></div>
    <div class="meta-item"><div class="label">Scan Date</div><div class="value">{{ metadata.scan_date }}</div></div>
    <div class="meta-item"><div class="label">Duration</div><div class="value">{{ metadata.duration }}</div></div>
    <div class="meta-item"><div class="label">Modules Run</div><div class="value">{{ metadata.modules_run }}</div></div>
  </div>
</div>

<!-- Executive Summary -->
<h2 id="summary">Executive Summary</h2>
<div class="stats">
  <div class="stat-card total"><div class="num">{{ counts.total }}</div><div class="lbl">Total Tests</div></div>
  <div class="stat-card pass"><div class="num">{{ counts.pass }}</div><div class="lbl">Passed</div></div>
  <div class="stat-card fail"><div class="num">{{ counts.fail }}</div><div class="lbl">Failed</div></div>
  <div class="stat-card warn"><div class="num">{{ counts.warn }}</div><div class="lbl">Warnings</div></div>
  <div class="stat-card info"><div class="num">{{ counts.info }}</div><div class="lbl">Informational</div></div>
</div>

<h3>Severity Distribution</h3>
<div class="sev-chart">
{% for sev_name, sev_count, sev_pct, sev_cls in severity_bars %}
  <div class="sev-row">
    <span class="sev-label">{{ sev_name }}</span>
    <div class="sev-bar-bg">
      <div class="sev-bar {{ sev_cls }}" style="width: {{ sev_pct }}%;">{{ sev_count }}</div>
    </div>
  </div>
{% endfor %}
</div>

<!-- Test Case Matrix -->
<h2 id="matrix">Test Case Matrix</h2>
<div style="overflow-x:auto;">
<table>
<thead>
<tr><th>#</th><th>Test ID</th><th>Test Name</th><th>Category</th><th>Status</th><th>Severity</th></tr>
</thead>
<tbody>
{% for i, f in enumerated_findings %}
<tr>
  <td>{{ i }}</td>
  <td style="font-family:monospace;">{{ f.test_id }}</td>
  <td>{{ f.test_name }}</td>
  <td>{{ f.category }}</td>
  <td><span class="badge badge-{{ f.status|lower }}">{{ f.status }}</span></td>
  <td><span class="badge badge-{{ sev_class(f.severity) }}">{{ f.severity }}</span></td>
</tr>
{% endfor %}
</tbody>
</table>
</div>

<!-- Risk Summary -->
<h2 id="risk">Risk Summary</h2>
{% for sev_name, sev_findings, sev_cls in risk_groups %}
{% if sev_findings %}
<div class="risk-group">
  <div class="risk-group-header">
    <span class="badge badge-{{ sev_cls }}" style="font-size:.9rem;padding:4px 14px;">{{ sev_name }}</span>
    <span class="risk-count">{{ sev_findings|length }} finding{{ 's' if sev_findings|length != 1 else '' }}</span>
  </div>
  <ul style="list-style:none;padding:0;">
  {% for f in sev_findings %}
    <li style="padding:4px 0;font-size:.9rem;">&bull; <strong>{{ f.test_id }}</strong> &mdash; {{ f.test_name }}{% if f.cve %} <span class="cve-tag">{{ f.cve }}</span>{% endif %}</li>
  {% endfor %}
  </ul>
</div>
{% endif %}
{% endfor %}

<!-- Detailed Findings -->
<h2 id="findings">Detailed Findings</h2>
{% for f in actionable_findings %}
<div class="finding-card sev-border-{{ f.severity|lower }}">
  <div class="finding-title">
    <h3>{{ f.test_id }} &mdash; {{ f.test_name }}</h3>
    <div class="finding-badges">
      <span class="badge badge-{{ f.status|lower }}">{{ f.status }}</span>
      <span class="badge badge-{{ sev_class(f.severity) }}">{{ f.severity }}</span>
      {% if f.cve %}<span class="cve-tag">{{ f.cve }}</span>{% endif %}
    </div>
  </div>

  <div class="finding-section">
    <div class="sec-title">Description</div>
    <p>{{ f.description }}</p>
  </div>

  {% if f.observation %}
  <div class="finding-section">
    <div class="sec-title">Observation</div>
    <pre>{{ f.observation }}</pre>
  </div>
  {% endif %}

  {% if f.affected_objects %}
  <div class="finding-section">
    <div class="sec-title">Affected Objects ({{ f.affected_objects|length }})</div>
    <ul class="affected-list">
    {% for obj in f.affected_objects[:50] %}
      <li>{{ obj }}</li>
    {% endfor %}
    {% if f.affected_objects|length > 50 %}
      <li style="color:var(--text-muted);">... and {{ f.affected_objects|length - 50 }} more</li>
    {% endif %}
    </ul>
  </div>
  {% endif %}

  {% if f.remediation %}
  <div class="finding-section">
    <div class="sec-title">Remediation</div>
    <p>{{ f.remediation }}</p>
  </div>
  {% endif %}

  {% if f.references %}
  <div class="finding-section">
    <div class="sec-title">References</div>
    {% for ref in f.references %}
      <a class="ref-link" href="{{ ref }}" target="_blank" rel="noopener">{{ ref }}</a><br>
    {% endfor %}
  </div>
  {% endif %}
</div>
{% endfor %}

{% if not actionable_findings %}
<p style="color:var(--text-muted);font-style:italic;">No actionable findings (FAIL/WARN) were detected. All tests passed or returned informational results.</p>
{% endif %}

<!-- Appendix -->
<h2 id="appendix">Appendix</h2>
<div class="meta-grid">
  <div class="meta-item"><div class="label">Tool</div><div class="value">{{ tool_name }} v{{ tool_version }}</div></div>
  <div class="meta-item"><div class="label">Author</div><div class="value">{{ tool_author }}</div></div>
  <div class="meta-item"><div class="label">Report Generated</div><div class="value">{{ metadata.report_time }}</div></div>
  <div class="meta-item"><div class="label">Protocol</div><div class="value">{{ metadata.protocol }}</div></div>
  <div class="meta-item"><div class="label">Domain DN</div><div class="value">{{ metadata.domain_dn }}</div></div>
  <div class="meta-item"><div class="label">Forest</div><div class="value">{{ metadata.forest }}</div></div>
</div>

<div class="footer">
  <p>{{ tool_name }} v{{ tool_version }} &mdash; Active Directory Security Assessment</p>
  <p>This report is confidential and intended solely for the authorized recipient.</p>
  <p>Generated {{ metadata.report_time }}</p>
</div>

</div>
</body>
</html>
"""


def _sev_class(severity):
    mapping = {
        SEVERITY_CRITICAL: "critical",
        SEVERITY_HIGH: "high",
        SEVERITY_MEDIUM: "medium",
        SEVERITY_LOW: "low",
        SEVERITY_INFO: "sev-info",
    }
    return mapping.get(severity, "sev-info")


def generate_report(findings, metadata, output_path):
    counts = {
        "total": len(findings),
        "pass": sum(1 for f in findings if f.status == STATUS_PASS),
        "fail": sum(1 for f in findings if f.status == STATUS_FAIL),
        "warn": sum(1 for f in findings if f.status == STATUS_WARN),
        "info": sum(1 for f in findings if f.status == STATUS_INFO),
        "error": sum(1 for f in findings if f.status == STATUS_ERROR),
        "skip": sum(1 for f in findings if f.status == STATUS_SKIP),
    }

    sev_counts = {}
    for sev in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]:
        sev_counts[sev] = sum(
            1 for f in findings
            if f.severity == sev and f.status in (STATUS_FAIL, STATUS_WARN)
        )

    max_sev = max(sev_counts.values()) if sev_counts.values() and max(sev_counts.values()) > 0 else 1
    sev_class_map = {
        SEVERITY_CRITICAL: "critical",
        SEVERITY_HIGH: "high",
        SEVERITY_MEDIUM: "medium",
        SEVERITY_LOW: "low",
        SEVERITY_INFO: "info",
    }
    severity_bars = []
    for sev in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]:
        c = sev_counts[sev]
        pct = max((c / max_sev) * 100, 4) if c > 0 else 0
        severity_bars.append((sev, c, pct, sev_class_map[sev]))

    risk_groups = []
    for sev in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW]:
        group = [f for f in findings if f.severity == sev and f.status in (STATUS_FAIL, STATUS_WARN)]
        risk_groups.append((sev, group, sev_class_map[sev]))

    actionable_findings = [f for f in findings if f.status in (STATUS_FAIL, STATUS_WARN)]

    metadata.setdefault("report_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    metadata.setdefault("protocol", "LDAP")
    metadata.setdefault("domain_dn", "")
    metadata.setdefault("forest", "")

    class _Meta:
        def __init__(self, d):
            self.__dict__.update(d)

    template = Template(REPORT_TEMPLATE)
    html = template.render(
        tool_name=TOOL_NAME,
        tool_version=TOOL_VERSION,
        tool_author=TOOL_AUTHOR,
        metadata=_Meta(metadata) if isinstance(metadata, dict) else metadata,
        counts=counts,
        severity_bars=severity_bars,
        enumerated_findings=list(enumerate(findings, 1)),
        risk_groups=risk_groups,
        actionable_findings=actionable_findings,
        sev_class=_sev_class,
    )

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True) if os.path.dirname(output_path) else None
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    return output_path

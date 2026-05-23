"""HTML report generator with executive summary and MITRE mapping."""

import os
from datetime import datetime
from jinja2 import Template
from config import REPORT_DIR
from database import Database
from utils.logger import log

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GitGuard Security Report</title>
<style>
  :root { --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3a; --text: #e2e8f0;
           --accent: #00d4aa; --critical: #ff4757; --high: #ff8c42; --medium: #ffd93d; --low: #6bcf7f; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; line-height: 1.6; }
  .container { max-width: 1100px; margin: 0 auto; }
  h1 { color: var(--accent); font-size: 2rem; margin-bottom: 0.5rem; }
  h2 { color: var(--accent); font-size: 1.3rem; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
  .meta { color: #888; margin-bottom: 2rem; }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin: 1.5rem 0; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; text-align: center; }
  .stat-card .value { font-size: 2rem; font-weight: 700; }
  .stat-card .label { color: #888; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; }
  .critical-val { color: var(--critical); }
  .high-val { color: var(--high); }
  .medium-val { color: var(--medium); }
  .low-val { color: var(--low); }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
  th, td { padding: 0.7rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }
  th { background: var(--surface); color: var(--accent); font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }
  td { font-size: 0.9rem; }
  .badge { padding: 2px 10px; border-radius: 12px; font-size: 0.8rem; font-weight: 600; }
  .badge-critical { background: rgba(255,71,87,0.2); color: var(--critical); }
  .badge-high { background: rgba(255,140,66,0.2); color: var(--high); }
  .badge-medium { background: rgba(255,217,61,0.2); color: var(--medium); }
  .badge-conf-high { background: rgba(0,212,170,0.2); color: var(--accent); }
  .badge-conf-med { background: rgba(255,217,61,0.2); color: var(--medium); }
  .badge-conf-low { background: rgba(107,207,127,0.15); color: var(--low); }
  .group-note { color: #888; font-size: 0.8rem; }
  .mitre h3 { color: var(--accent); margin-bottom: 0.5rem; }
  .mitre-item { margin: 0.5rem 0; padding: 0.5rem; background: rgba(0,212,170,0.05); border-radius: 4px; }
  .risk-banner { text-align: center; padding: 1rem; margin: 1rem 0; border-radius: 8px; font-size: 1.1rem; font-weight: 700; }
  .risk-critical { background: rgba(255,71,87,0.15); color: var(--critical); border: 1px solid var(--critical); }
  .risk-high { background: rgba(255,140,66,0.15); color: var(--high); }
  .risk-medium { background: rgba(255,217,61,0.12); color: var(--medium); }
  .risk-low { background: rgba(107,207,127,0.12); color: var(--low); }
  .exec-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.8rem 2rem; margin: 1rem 0; font-size: 0.9rem; }
  .exec-grid div { display: flex; justify-content: space-between; border-bottom: 1px solid var(--border); padding: 0.4rem 0; }
  .header-bar { border-bottom: 2px solid var(--accent); padding-bottom: 1rem; margin-bottom: 1.5rem; }
  .remediation-box { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin: 1rem 0; }
  .remediation-box li { margin: 0.4rem 0; }
  .footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: #666; font-size: 0.8rem; text-align: center; }
  @media print { body { background: #fff; color: #333; } .stat-card { border: 1px solid #ddd; } th { background: #f5f5f5; color: #333; } }
</style>
</head>
<body>
<div class="container">
  <div class="header-bar">
    <h1>🛡️ GitGuard Security Report</h1>
    <p class="meta">Generated: {{ generated_at }} | Report ID: {{ report_id }}</p>
    <p class="meta">Repositories scanned: {{ stats.repos }} | Total scans: {{ stats.scans }} | Scan sources: local paths, allowlisted remotes</p>
  </div>

  <div class="risk-banner risk-{{ executive.risk_color }}">Estimated Organizational Risk: {{ executive.estimated_risk }}</div>

  <h2>Executive Summary</h2>
  <div class="stats-grid">
    <div class="stat-card"><div class="value">{{ stats.total_findings }}</div><div class="label">Total Findings</div></div>
    <div class="stat-card"><div class="value critical-val">{{ stats.critical }}</div><div class="label">Critical</div></div>
    <div class="stat-card"><div class="value high-val">{{ stats.high }}</div><div class="label">High</div></div>
    <div class="stat-card"><div class="value medium-val">{{ stats.medium }}</div><div class="label">Medium</div></div>
    <div class="stat-card"><div class="value low-val">{{ stats.low }}</div><div class="label">Low</div></div>
    <div class="stat-card"><div class="value" style="color:var(--accent)">{{ stats.rotations_completed }}</div><div class="label">Rotated</div></div>
    <div class="stat-card"><div class="value" style="color:#a78bfa">{{ stats.history_leaks }}</div><div class="label">History Leaks</div></div>
    <div class="stat-card"><div class="value" style="color:var(--accent)">{{ stats.high_confidence|default(0) }}</div><div class="label">High Confidence</div></div>
    <div class="stat-card"><div class="value" style="color:#74b9ff">{{ stats.cloud_credentials|default(0) }}</div><div class="label">Cloud Credentials</div></div>
  </div>
  <div class="exec-grid">
    <div><span>Highest-risk secret type</span><span>{{ executive.top_secret_type }} ({{ executive.top_secret_type_count }})</span></div>
    <div><span>Top ATT&CK technique</span><span>{{ executive.top_attack_technique }} — {{ executive.top_attack_count }} findings</span></div>
    <div><span>Grouped duplicate rows</span><span>{{ executive.grouped_findings }}</span></div>
    <div><span>High exposure findings</span><span>{{ executive.high_exposure }}</span></div>
  </div>

  <h2>Remediation Guidance</h2>
  <div class="remediation-box">
    <ol>
      <li><strong>Validate</strong> each critical finding — confirm whether the secret is active (mock validation available in dashboard).</li>
      <li><strong>Rotate</strong> exposed credentials immediately; GitGuard performs mock rotation with audit trail.</li>
      <li><strong>Remove</strong> secrets from Git history where possible; use <code>history-scan</code> to find buried leaks.</li>
      <li><strong>Prevent</strong> re-introduction via pre-commit hooks and allowlist-controlled remote scanning.</li>
      <li><strong>Monitor</strong> repositories continuously with <code>python main.py monitor &lt;path&gt;</code>.</li>
    </ol>
  </div>

  {% if stats.by_attack %}
  <h2>ATT&CK Technique Summary</h2>
  <table>
    <tr><th>Technique</th><th>Name</th><th>Findings</th></tr>
    {% for item in stats.by_attack %}
    <tr><td><code>{{ item.attack_technique }}</code></td><td>{{ item.attack_name or '—' }}</td><td>{{ item.count }}</td></tr>
    {% endfor %}
  </table>
  {% endif %}

  <h2>Findings by Secret Type</h2>
  <table>
    <tr><th>Secret Type</th><th>Count</th></tr>
    {% for item in stats.by_type %}
    <tr><td>{{ item.secret_type }}</td><td>{{ item.count }}</td></tr>
    {% endfor %}
  </table>

  <h2>Grouped Findings (Risk Intelligence)</h2>
  <table>
    <tr><th>Severity</th><th>Type</th><th>File(s)</th><th>Preview</th><th>Confidence</th><th>Exposure</th><th>ATT&CK</th><th>Count</th><th>Remediation</th></tr>
    {% for f in findings %}
    <tr>
      <td><span class="badge badge-{{ f.severity|lower }}">{{ f.severity }}</span></td>
      <td>{{ f.secret_type }}</td>
      <td>{{ f.file_path }}{% if f.occurrence_count and f.occurrence_count > 1 %}<br><span class="group-note">{{ f.occurrence_count }} occurrences</span>{% endif %}</td>
      <td><code>{{ f.masked_preview }}</code></td>
      <td><span class="badge badge-conf-{{ (f.confidence_label or 'medium')|lower }}">{{ f.confidence_label or '—' }}</span> <span class="group-note">({{ f.confidence_score or '—' }})</span></td>
      <td>{{ f.exposure_level or '—' }}<br><span class="group-note">{{ f.exposure_reason or '' }}</span></td>
      <td><code>{{ f.attack_technique or 'T1552' }}</code></td>
      <td>{{ f.occurrence_count or 1 }}</td>
      <td style="max-width:220px;font-size:0.85rem">{{ f.remediation or '—' }}</td>
    </tr>
    {% endfor %}
  </table>

  {% if history %}
  <h2>Commit History Leaks</h2>
  <table>
    <tr><th>Commit</th><th>Author</th><th>File</th><th>Type</th><th>Severity</th><th>ATT&CK</th><th>Confidence</th></tr>
    {% for h in history %}
    <tr>
      <td><code>{{ h.commit_hash }}</code></td>
      <td>{{ h.author }}</td>
      <td>{{ h.file_path }}</td>
      <td>{{ h.secret_type }}</td>
      <td><span class="badge badge-{{ h.severity|lower }}">{{ h.severity }}</span></td>
      <td><code>{{ h.attack_technique or 'T1552' }}</code></td>
      <td>{{ h.confidence_label or '—' }}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}

  {% if rotations %}
  <h2>Rotation / Remediation History</h2>
  <table>
    <tr><th>Finding</th><th>Type</th><th>Old</th><th>New</th><th>Status</th><th>Retries</th></tr>
    {% for r in rotations %}
    <tr>
      <td>#{{ r.finding_id }}</td>
      <td>{{ r.secret_type or '-' }}</td>
      <td><code>{{ r.old_masked }}</code></td>
      <td><code>{{ r.new_masked }}</code></td>
      <td>{{ r.status }}</td>
      <td>{{ r.retries }}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}

  <h2>MITRE ATT&CK Defensive Mapping</h2>
  <div class="mitre">
    <div class="mitre-item"><h3>T1552 — Unsecured Credentials</h3>GitGuard detects hardcoded credentials in source code and configuration files, preventing adversaries from harvesting secrets from repositories.</div>
    <div class="mitre-item"><h3>T1552.001 — Credentials in Files</h3>Regex + entropy scanning identifies API keys, tokens, and passwords stored in plaintext files.</div>
    <div class="mitre-item"><h3>T1078 — Valid Accounts</h3>Mock credential validation and rotation prevents attackers from using leaked valid credentials for initial access.</div>
    <div class="mitre-item"><h3>T1556 — Modify Authentication Process</h3>Automated rotation workflow ensures compromised credentials are replaced before exploitation.</div>
    <div class="mitre-item"><h3>D3-SPM — Secret Pattern Monitoring</h3>Continuous watchdog-based monitoring detects new secrets as they are committed in real time.</div>
  </div>

  <div class="footer">GitGuard — Defensive Secrets Detection &amp; Rotation System | Report generated automatically</div>
</div>
</body>
</html>"""


def generate_report(db: Database) -> tuple[str, dict]:
    """Generate an HTML report. Returns (filepath, s3_export_result)."""
    import json as json_mod

    stats = db.get_stats()
    executive = db.get_executive_summary()
    findings = db.get_findings(limit=1000)
    history = db.get_history_findings(limit=200)
    rotations = db.get_rotations(limit=100)
    last_scan = db.get_last_scan()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    template = Template(REPORT_TEMPLATE)
    html = template.render(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        report_id=ts,
        stats=stats,
        executive=executive,
        findings=findings,
        history=history,
        rotations=rotations,
        last_scan=last_scan,
    )
    filename = f"gitguard_report_{ts}.html"
    filepath = os.path.join(REPORT_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    json_path = os.path.join(REPORT_DIR, f"gitguard_report_{ts}.json")
    with open(json_path, "w", encoding="utf-8") as jf:
        json_mod.dump({
            "generated_at": datetime.now().isoformat(),
            "summary": stats,
            "findings": findings,
            "history": history,
        }, jf, indent=2, default=str)

    log("info", "report", f"Report generated: {filepath}")

    export_result: dict = {"skipped": True, "skip_reason": "disabled"}

    try:
        from cloud_export.export import post_report_exports
        export_result = post_report_exports(filepath, findings, db=db)
        if export_result.get("s3_report"):
            log("info", "aws", f"Report exported to S3: {export_result['s3_report']}")
        if export_result.get("s3_findings"):
            log("info", "aws", f"Findings exported to S3: {export_result['s3_findings']}")
    except Exception as exc:
        log("warning", "aws", f"S3 report export failed (non-blocking): {exc}")
        export_result = {"warning": "S3 export failed gracefully"}

    return filepath, export_result

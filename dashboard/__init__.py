"""Flask dashboard for GitGuard — SOC-style dark theme."""

import os
import json
from typing import Optional
from flask import Flask, render_template, jsonify, request, redirect, url_for, send_file
from database import Database
from rotation import rotate_credential, bulk_rotate_critical, mock_validate
from reports import generate_report
from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG, BASE_DIR

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
app.secret_key = "gitguard-dashboard-local-only"
db = Database()


@app.context_processor
def _inject_globals():
    import os
    demo = os.getenv("GITGUARD_DEMO_MODE", "").strip().lower() in ("1", "true", "yes", "on")
    return {"demo_mode": demo}


def _normalize_finding(row: dict) -> dict:
    """Ensure Phase 4 fields exist for API/templates (backward compatible)."""
    f = dict(row)
    conf = f.get("confidence")
    if f.get("confidence_score") is None and conf is not None:
        try:
            f["confidence_score"] = int(float(conf) * 100)
        except (TypeError, ValueError):
            f["confidence_score"] = 50
    f.setdefault("confidence_score", 50)
    if not f.get("confidence_label"):
        cs = f["confidence_score"]
        f["confidence_label"] = "High" if cs >= 75 else "Medium" if cs >= 45 else "Low"
    f.setdefault("attack_technique", "T1552")
    f.setdefault("attack_name", "Unsecured Credentials")
    f.setdefault("attack_tactic", "Credential Access")
    f.setdefault("exposure_level", "Medium")
    f.setdefault("exposure_score", 30)
    f.setdefault("exposure_reason", "")
    f.setdefault("occurrence_count", 1)
    f.setdefault("remediation", "Review this finding and rotate the credential if it is valid.")
    f.setdefault("severity_score", 0)
    f.setdefault("severity", "Low")
    f.setdefault("entropy", 0)
    return f


def _json_findings(limit: int = 500, severity: Optional[str] = None) -> list[dict]:
    items = [_normalize_finding(f) for f in db.get_findings(limit=limit, severity=severity)]
    return items


@app.route("/")
def index():
    stats = db.get_stats()
    recent = [_normalize_finding(f) for f in db.get_findings(limit=10)]
    executive = db.get_executive_summary()
    last_scan = db.get_last_scan()
    top_repos = db.get_top_repos(limit=5)
    recent_scans = db.get_scans(limit=5)
    return render_template(
        "index.html",
        stats=stats,
        recent=recent,
        executive=executive,
        last_scan=last_scan,
        top_repos=top_repos,
        recent_scans=recent_scans,
        page="overview",
    )


@app.route("/findings")
def findings():
    severity = request.args.get("severity")
    items = _json_findings(limit=500, severity=severity)
    return render_template("findings.html", findings=items, page="findings", filter_severity=severity)


@app.route("/analytics")
def analytics():
    stats = db.get_stats()
    items = _json_findings(limit=1000)
    return render_template("analytics.html", stats=stats, findings=items, page="analytics")


@app.route("/history")
def history():
    items = db.get_history_findings(limit=200)
    return render_template("history.html", history=items, page="history")


@app.route("/rotations")
def rotations():
    items = db.get_rotations(limit=100)
    return render_template("rotations.html", rotations=items, page="rotations")


@app.route("/monitoring")
def monitoring():
    events = db.get_monitor_events(limit=100)
    return render_template("monitoring.html", events=events, page="monitoring")


@app.route("/reports_page")
def reports_page():
    return render_template("reports.html", page="reports")


@app.route("/logs")
def logs_page():
    items = db.get_logs(limit=200)
    return render_template("logs.html", logs=items, page="logs")


@app.route("/repos")
def repos():
    items = db.get_repos()
    scans = db.get_scans(limit=50)
    stats = db.get_stats()
    return render_template("repos.html", repos=items, scans=scans, stats=stats, page="repos")


# --- API Endpoints ---
@app.route("/api/stats")
def api_stats():
    stats = db.get_stats()
    stats.setdefault("high_confidence", 0)
    stats.setdefault("cloud_credentials", 0)
    stats.setdefault("by_attack", [])
    stats.setdefault("by_confidence", [])
    return jsonify(stats)


@app.route("/api/findings")
def api_findings():
    return jsonify(_json_findings(limit=500))


@app.route("/api/rotate/<int:finding_id>", methods=["POST"])
def api_rotate(finding_id):
    result = rotate_credential(finding_id, db)
    return jsonify(result)


@app.route("/api/rotate-critical", methods=["POST"])
def api_rotate_critical():
    results = bulk_rotate_critical(db)
    return jsonify({"rotated": len(results), "results": results})


@app.route("/api/history")
def api_history():
    return jsonify(db.get_history_findings(limit=500))


@app.route("/api/rotations")
def api_rotations():
    return jsonify(db.get_rotations(limit=200))


@app.route("/api/logs")
def api_logs():
    return jsonify(db.get_logs(limit=500))


@app.route("/api/repos")
def api_repos():
    return jsonify(db.get_repos())


@app.route("/api/monitor-events")
def api_monitor_events():
    return jsonify(db.get_monitor_events(limit=50))


@app.route("/api/validate", methods=["POST"])
def api_validate_generic():
    data = request.get_json(silent=True) or {}
    secret_type = data.get("secret_type", "unknown")
    value = data.get("value", "")
    status = mock_validate(secret_type, value)
    return jsonify({"status": status, "detail": f"Mock validation for {secret_type}"})


@app.route("/api/generate-report", methods=["POST"])
def api_generate_report_download():
    filepath, _ = generate_report(db)
    return send_file(filepath, as_attachment=True, download_name="gitguard_report.html")


def run_dashboard():
    """Start the Flask dashboard."""
    print(f"\n  🛡️  GitGuard Dashboard: http://{FLASK_HOST}:{FLASK_PORT}\n")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)

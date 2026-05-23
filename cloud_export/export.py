"""Orchestrate optional AWS exports after scans and report generation.

All exports are best-effort: failures log a warning and local workflow continues.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

from cloud_export.aws_client import get_aws_client
from cloud_export.aws_safe import format_aws_warning
from utils.logger import log

logger = logging.getLogger("gitguard.export")


def describe_s3_export_result(result: dict) -> dict:
    """Map export result to concise CLI message. level: success | warning | info."""
    if result.get("skipped"):
        reason = result.get("skip_reason", "")
        if reason == "disabled":
            return {"level": "info", "message": "Cloud export disabled"}
        if reason == "not_configured":
            return {"level": "info", "message": "S3 export not configured"}
        return {"level": "info", "message": "Cloud export skipped"}

    if result.get("warning"):
        warn = result["warning"].lower()
        if any(x in warn for x in ("localstack", "connection refused", "unreachable", "connect")):
            return {"level": "warning", "message": "S3 export skipped — LocalStack unavailable"}
        if "invalid" in warn or "dns" in warn or "hostname" in warn:
            return {"level": "warning", "message": "S3 export skipped — invalid endpoint"}
        return {"level": "warning", "message": "S3 export failed gracefully"}

    if result.get("s3_report"):
        return {"level": "success", "message": "Report exported to S3"}

    if result.get("error"):
        return {"level": "warning", "message": "S3 export failed gracefully"}

    # Attempted but uploads returned None
    if not result.get("skipped") and result.get("s3_report") is None:
        return {"level": "warning", "message": "S3 export failed gracefully"}

    return {"level": "info", "message": "Cloud export skipped"}


def _aws_status_message(results: dict) -> str:
    if results.get("warning"):
        return results["warning"]
    parts = []
    if results.get("s3_report"):
        parts.append(f"S3 report → {results['s3_report']}")
    if results.get("s3_findings"):
        parts.append(f"S3 findings → {results['s3_findings']}")
    if results.get("sns_alerts", 0):
        parts.append(f"SNS alerts sent: {results['sns_alerts']}")
    if results.get("dynamodb_synced", 0):
        parts.append(f"DynamoDB synced: {results['dynamodb_synced']}")
    if results.get("skipped"):
        return "AWS export skipped (disabled or not configured)"
    if not parts:
        return "AWS export: no actions performed"
    return " | ".join(parts)


def post_scan_exports(
    repo_path: str,
    findings: list[dict],
    *,
    scan_id: Optional[int] = None,
    db=None,
) -> dict[str, Any]:
    """Optional SNS alerts + DynamoDB sync after a scan. Never raises."""
    results: dict[str, Any] = {"skipped": False, "sns_alerts": 0, "dynamodb_synced": 0}

    try:
        client = get_aws_client()
        if not client.enabled:
            results["skipped"] = True
            log("debug", "aws", "Post-scan AWS export skipped (AWS disabled)")
            return results

        if client.is_localstack and not client.is_cloud_ready():
            results["warning"] = client.last_skip_reason or "LocalStack unreachable — skipping AWS exports"
            log("warning", "aws", results["warning"])
            if db:
                db.add_log("WARNING", "aws", "Post-scan export skipped", results["warning"])
            return results

        repo_name = os.path.basename(os.path.abspath(repo_path))

        for finding in findings:
            if not client.is_cloud_ready():
                break

            if finding.get("severity") == "Critical":
                if client.publish_critical_alert(repo_name, finding):
                    results["sns_alerts"] += 1

            if client.is_configured_for("dynamodb"):
                if client.sync_finding_to_dynamodb(finding, repo_path=repo_path, scan_id=scan_id):
                    results["dynamodb_synced"] += 1

        if client.last_skip_reason and not results.get("warning"):
            results["warning"] = client.last_skip_reason

        msg = _aws_status_message(results)
        log("info", "aws", f"Post-scan export for {repo_name}: {msg}")
        if db:
            db.add_log("INFO", "aws", f"Post-scan export: {repo_name}", msg)

    except Exception as exc:
        msg = format_aws_warning("AWS", "post_scan_exports", exc)
        logger.warning(msg)
        results["warning"] = msg
        if db:
            try:
                db.add_log("WARNING", "aws", "Post-scan export failed (non-blocking)", msg)
            except Exception:
                pass

    return results


def post_report_exports(
    report_path: str,
    findings: list[dict],
    *,
    db=None,
) -> dict[str, Any]:
    """Optional S3 export of HTML report and findings JSON. Never raises."""
    results: dict[str, Any] = {"skipped": False}

    try:
        client = get_aws_client()
        if not client.enabled:
            results["skipped"] = True
            results["skip_reason"] = "disabled"
            log("debug", "aws", "Post-report AWS export skipped (AWS disabled)")
            return results

        if not client.is_configured_for("s3"):
            results["skipped"] = True
            results["skip_reason"] = "not_configured"
            log("debug", "aws", "S3 export skipped — GITGUARD_S3_BUCKET not set")
            return results

        if client.is_localstack and not client.is_cloud_ready():
            results["warning"] = "S3 export skipped — LocalStack unavailable"
            results["skip_reason"] = "localstack_unavailable"
            log("warning", "aws", results["warning"])
            if db:
                db.add_log("WARNING", "aws", "Post-report export skipped", results["warning"])
            return results

        prefix = client._report_prefix()
        results["s3_report"] = client.export_report_to_s3(report_path, prefix=prefix)
        results["s3_findings"] = client.export_findings_json_to_s3(findings, prefix=prefix)

        if client.last_skip_reason and not results.get("warning"):
            results["warning"] = client.last_skip_reason

        if results.get("s3_report") is None and not results.get("warning"):
            results["warning"] = "S3 export failed gracefully"

        msg = _aws_status_message(results)
        log("info", "aws", f"Post-report export: {msg}")
        if db:
            db.add_log("INFO", "aws", "Post-report S3 export", msg)

    except Exception as exc:
        msg = format_aws_warning("AWS", "post_report_exports", exc)
        logger.warning(msg)
        results["warning"] = msg
        if db:
            try:
                db.add_log("WARNING", "aws", "Post-report export failed (non-blocking)", msg)
            except Exception:
                pass

    return results

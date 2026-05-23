"""AWS-light client — S3 export, SNS alerts, DynamoDB sync with graceful fallbacks."""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Optional, TypeVar

from config import get_aws_config
from cloud_export.aws_safe import format_aws_warning, is_aws_connection_error, safe_aws_call
from cloud_export.localstack_health import check_localstack_health, localstack_guidance

logger = logging.getLogger("gitguard.aws")

T = TypeVar("T")

_boto3: Any = None
_BotoCoreError: type[Exception] = Exception
_ClientError: type[Exception] = Exception

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

    _boto3 = boto3
    _BotoCoreError = BotoCoreError
    _ClientError = ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

# Short timeouts — fail fast when LocalStack/AWS is down
AWS_CONNECT_TIMEOUT = 3
AWS_READ_TIMEOUT = 5
AWS_MAX_ATTEMPTS = 1


class AWSClient:
    """Thin wrapper around boto3 for optional cloud export and alerting."""

    def __init__(self) -> None:
        self._config = get_aws_config()
        self._session: Any = None
        self._clients: dict[str, Any] = {}
        self._resources: dict[str, Any] = {}
        self._endpoint_reachable: Optional[bool] = None
        self._cloud_unavailable = False
        self._last_skip_reason: str = ""

        if not self._config["enabled"]:
            logger.debug("AWS integration disabled (GITGUARD_AWS_ENABLED=false)")
            return

        if not BOTO3_AVAILABLE:
            logger.warning(
                "GITGUARD_AWS_ENABLED is true but boto3 is not installed — cloud features skipped"
            )
            return

        self._session = _boto3.Session(region_name=self._config["region"])
        mode = "LocalStack" if self.is_localstack else "AWS"
        logger.info(
            "AWS client initialized (%s, region=%s, endpoint=%s)",
            mode,
            self._config["region"],
            self._config["endpoint_url"] or "default",
        )

    @property
    def enabled(self) -> bool:
        return bool(self._config["enabled"] and BOTO3_AVAILABLE and self._session is not None)

    @property
    def config(self) -> dict:
        return dict(self._config)

    @property
    def is_localstack(self) -> bool:
        return bool(self._config.get("endpoint_url"))

    @property
    def last_skip_reason(self) -> str:
        return self._last_skip_reason

    def _client_kwargs(self) -> dict:
        kwargs: dict = {"region_name": self._config["region"]}
        if self._config["endpoint_url"]:
            kwargs["endpoint_url"] = self._config["endpoint_url"]
        try:
            from botocore.config import Config

            kwargs["config"] = Config(
                connect_timeout=AWS_CONNECT_TIMEOUT,
                read_timeout=AWS_READ_TIMEOUT,
                retries={"max_attempts": AWS_MAX_ATTEMPTS},
            )
        except ImportError:
            pass
        return kwargs

    def get_client(self, service_name: str) -> Optional[Any]:
        if not self.enabled:
            return None
        if service_name not in self._clients:
            self._clients[service_name] = self._session.client(service_name, **self._client_kwargs())
        return self._clients[service_name]

    def get_resource(self, service_name: str) -> Optional[Any]:
        if not self.enabled:
            return None
        if service_name not in self._resources:
            self._resources[service_name] = self._session.resource(service_name, **self._client_kwargs())
        return self._resources[service_name]

    def is_configured_for(self, resource: str) -> bool:
        mapping = {
            "s3": self._config.get("s3_bucket"),
            "dynamodb": self._config.get("dynamodb_table"),
            "sns": self._config.get("sns_topic_arn"),
        }
        return bool(mapping.get(resource))

    def check_localstack_ready(self) -> dict:
        """Lightweight LocalStack health check (no boto3 call)."""
        endpoint = self._config.get("endpoint_url") or ""
        if not endpoint:
            return {"reachable": True, "detail": "Not using LocalStack endpoint", "hint": None}
        return check_localstack_health(endpoint, timeout=AWS_CONNECT_TIMEOUT)

    def _mark_cloud_unavailable(self, service: str, operation: str, exc: BaseException) -> None:
        if is_aws_connection_error(exc):
            self._cloud_unavailable = True
            self._last_skip_reason = format_aws_warning(service, operation, exc)
            logger.warning(self._last_skip_reason)

    def is_cloud_ready(self) -> bool:
        """Public check — False when exports should be skipped (e.g. LocalStack down)."""
        return self._cloud_ready()

    def _cloud_ready(self) -> bool:
        """Return False when cloud exports should be skipped for this session."""
        if not self.enabled:
            return False
        if self._cloud_unavailable:
            return False

        if self.is_localstack:
            if self._endpoint_reachable is False:
                return False
            if self._endpoint_reachable is None:
                health = self.check_localstack_ready()
                self._endpoint_reachable = health["reachable"]
                if not self._endpoint_reachable:
                    self._cloud_unavailable = True
                    self._last_skip_reason = health["detail"]
                    logger.warning(
                        "Could not connect to LocalStack (%s). Skipping AWS exports. %s",
                        self._config["endpoint_url"],
                        health.get("hint") or "",
                    )
                    return False
        return True

    def _run(self, fn: Callable[[], T], *, service: str, operation: str, default: T) -> T:
        if not self._cloud_ready():
            return default
        try:
            return fn()
        except Exception as exc:
            self._mark_cloud_unavailable(service, operation, exc)
            if not self._cloud_unavailable:
                logger.warning(format_aws_warning(service, operation, exc))
            return default

    def _report_prefix(self) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return f"reports/{ts}"

    def _ensure_s3_bucket(self) -> bool:
        bucket = self._config["s3_bucket"]
        if not bucket:
            return False
        if not self.is_localstack:
            return True

        def _ensure() -> bool:
            s3 = self.get_client("s3")
            if not s3:
                return False
            try:
                s3.head_bucket(Bucket=bucket)
            except _ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code not in ("404", "NoSuchBucket", "NotFound"):
                    raise
                s3.create_bucket(Bucket=bucket)
                logger.info("Created LocalStack S3 bucket: %s", bucket)
            return True

        return self._run(_ensure, service="LocalStack S3", operation="ensure bucket", default=False)

    def _ensure_dynamodb_table(self) -> bool:
        table_name = self._config["dynamodb_table"]
        if not table_name:
            return False
        if not self.is_localstack:
            return True

        def _ensure() -> bool:
            dynamodb = self.get_client("dynamodb")
            if not dynamodb:
                return False
            try:
                dynamodb.describe_table(TableName=table_name)
            except _ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                    raise
                dynamodb.create_table(
                    TableName=table_name,
                    KeySchema=[{"AttributeName": "finding_id", "KeyType": "HASH"}],
                    AttributeDefinitions=[{"AttributeName": "finding_id", "AttributeType": "S"}],
                    BillingMode="PAY_PER_REQUEST",
                )
                logger.info("Created LocalStack DynamoDB table: %s", table_name)
            return True

        return self._run(_ensure, service="LocalStack DynamoDB", operation="ensure table", default=False)

    def upload_file_to_s3(self, local_path: str, s3_key: str, content_type: str = "application/octet-stream") -> Optional[str]:
        if not self.enabled or not self.is_configured_for("s3"):
            return None
        if not os.path.isfile(local_path):
            logger.warning("S3 upload skipped — file not found: %s", local_path)
            return None
        if not self._ensure_s3_bucket():
            return None

        bucket = self._config["s3_bucket"]

        def _upload() -> Optional[str]:
            s3 = self.get_client("s3")
            if not s3:
                return None
            s3.upload_file(local_path, bucket, s3_key, ExtraArgs={"ContentType": content_type})
            uri = f"s3://{bucket}/{s3_key}"
            logger.info("S3 upload success: %s", uri)
            return uri

        return self._run(_upload, service="S3", operation="upload", default=None)

    def upload_json_to_s3(self, data: Any, s3_key: str) -> Optional[str]:
        if not self.enabled or not self.is_configured_for("s3"):
            return None
        if not self._ensure_s3_bucket():
            return None

        bucket = self._config["s3_bucket"]
        body = json.dumps(data, indent=2, default=str).encode("utf-8")

        def _upload() -> Optional[str]:
            s3 = self.get_client("s3")
            if not s3:
                return None
            s3.put_object(Bucket=bucket, Key=s3_key, Body=body, ContentType="application/json")
            uri = f"s3://{bucket}/{s3_key}"
            logger.info("S3 JSON upload success: %s", uri)
            return uri

        return self._run(_upload, service="S3", operation="put_object", default=None)

    def export_report_to_s3(self, local_path: str, prefix: Optional[str] = None) -> Optional[str]:
        prefix = prefix or self._report_prefix()
        return self.upload_file_to_s3(local_path, f"{prefix}/report.html", content_type="text/html")

    def export_findings_json_to_s3(self, findings: list[dict], prefix: Optional[str] = None) -> Optional[str]:
        prefix = prefix or self._report_prefix()
        safe = [
            {
                "secret_type": f.get("secret_type"),
                "severity": f.get("severity"),
                "file_path": f.get("file_path"),
                "line_number": f.get("line_number"),
                "masked_preview": f.get("masked_preview"),
                "severity_score": f.get("severity_score"),
                "entropy": f.get("entropy"),
            }
            for f in findings
        ]
        return self.upload_json_to_s3(safe, f"{prefix}/findings.json")

    def publish_alert(self, subject: str, message: str) -> bool:
        if not self.enabled or not self.is_configured_for("sns"):
            return False

        def _publish() -> bool:
            sns = self.get_client("sns")
            if not sns:
                return False
            sns.publish(
                TopicArn=self._config["sns_topic_arn"],
                Subject=subject[:100],
                Message=message[:4096],
            )
            logger.info("SNS alert published: %s", subject[:80])
            return True

        return self._run(_publish, service="SNS", operation="publish", default=False)

    def publish_critical_alert(self, repo_name: str, finding: dict) -> bool:
        subject = f"GitGuard CRITICAL: {finding.get('secret_type', 'secret')} in {repo_name}"
        message = (
            f"GitGuard Critical Finding Alert\n"
            f"{'=' * 40}\n"
            f"Repository : {repo_name}\n"
            f"Secret Type: {finding.get('secret_type', 'unknown')}\n"
            f"Severity   : Critical\n"
            f"File       : {finding.get('file_path', 'unknown')}\n"
            f"Line       : {finding.get('line_number', '?')}\n"
            f"Preview    : {finding.get('masked_preview', '[masked]')}\n"
            f"\nAction: Review and rotate this credential immediately."
        )
        return self.publish_alert(subject, message)

    def sync_finding_to_dynamodb(
        self,
        finding: dict,
        *,
        repo_path: str = "",
        scan_id: Optional[int] = None,
    ) -> bool:
        if not self.enabled or not self.is_configured_for("dynamodb"):
            return False
        if not self._cloud_ready():
            return False
        if not self._ensure_dynamodb_table():
            return False

        table_name = self._config["dynamodb_table"]
        finding_id = finding.get("id") or finding.get("finding_id")
        if not finding_id:
            finding_id = str(uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"{repo_path}|{finding.get('file_path')}|{finding.get('line_number')}|{finding.get('secret_type')}",
            ))

        item = {
            "finding_id": str(finding_id),
            "repo_path": repo_path or finding.get("repo_path", ""),
            "scan_id": scan_id if scan_id is not None else finding.get("scan_id"),
            "secret_type": finding.get("secret_type", "unknown"),
            "severity": finding.get("severity", "unknown"),
            "masked_preview": finding.get("masked_preview", ""),
            "file_path": finding.get("file_path", ""),
            "line_number": finding.get("line_number"),
            "found_at": finding.get("found_at") or datetime.now(timezone.utc).isoformat(),
        }
        item = {k: v for k, v in item.items() if v is not None}

        def _put() -> bool:
            table = self.get_resource("dynamodb")
            if not table:
                return False
            table.Table(table_name).put_item(Item=item)
            logger.debug("DynamoDB sync OK: %s", finding_id)
            return True

        return self._run(_put, service="DynamoDB", operation="put_item", default=False)

    def validate_aws_connectivity(self) -> dict:
        """Connectivity check for aws-check CLI."""
        if not self.enabled:
            return {"ok": False, "status": "disabled", "detail": "AWS disabled", "mode": "disabled"}
        if not BOTO3_AVAILABLE:
            return {"ok": False, "status": "unavailable", "detail": "boto3 not installed", "mode": "unavailable"}

        mode = "localstack" if self.is_localstack else "aws"

        if self.is_localstack:
            health = self.check_localstack_ready()
            if not health["reachable"]:
                kind = health.get("error_kind")
                return {
                    "ok": False,
                    "status": "localstack_unreachable",
                    "error_kind": kind,
                    "detail": health["detail"],
                    "hint": health.get("hint"),
                    "guidance": localstack_guidance(self._config["endpoint_url"], kind),
                    "mode": mode,
                }
            return {
                "ok": True,
                "status": "localstack_ready",
                "detail": health["detail"],
                "mode": mode,
            }

        if not self._config["allow_real_aws_validation"]:
            return {
                "ok": False,
                "status": "validation_disabled",
                "detail": "Real AWS STS check disabled (set GITGUARD_ALLOW_REAL_AWS_VALIDATION=true)",
                "mode": mode,
            }

        def _sts() -> dict:
            sts = self.get_client("sts")
            if sts is None:
                return {"ok": False, "status": "sts_unavailable", "detail": "Could not create STS client", "mode": mode}
            identity = sts.get_caller_identity()
            return {
                "ok": True,
                "status": "aws_connected",
                "detail": f"Account {identity.get('Account', 'unknown')}",
                "arn": identity.get("Arn", ""),
                "mode": mode,
            }

        result = safe_aws_call(_sts, default={"ok": False, "status": "connection_failed", "detail": "STS check failed", "mode": mode}, service="STS", operation="get_caller_identity")
        if not result.get("ok") and result.get("status") == "connection_failed":
            result["detail"] = self.last_skip_reason or "Could not reach AWS STS — check credentials and network"
            result["status"] = "credentials_or_network"
        return result


_aws_client: Optional[AWSClient] = None


def get_aws_client() -> AWSClient:
    global _aws_client
    if _aws_client is None:
        _aws_client = AWSClient()
    return _aws_client


def reset_aws_client() -> None:
    global _aws_client
    _aws_client = None

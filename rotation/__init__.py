"""Mock credential validation and rotation workflow."""

import random
import string
import time
from datetime import datetime
from utils.masking import mask_secret
from utils.logger import log
from database import Database


VALIDATION_STATUSES = ["ACTIVE", "EXPIRED", "TEST", "INVALID", "UNKNOWN"]
VALIDATION_WEIGHTS = [0.3, 0.25, 0.2, 0.15, 0.1]


def mock_validate(secret_type: str, masked_preview: str) -> str:
    """Simulate credential validity check. Returns a status string."""
    # Deterministic-ish based on type for demo consistency
    if "test" in masked_preview.lower() or "example" in masked_preview.lower():
        return "TEST"
    if "Private Key" in secret_type:
        return random.choices(["ACTIVE", "EXPIRED"], weights=[0.6, 0.4])[0]
    return random.choices(VALIDATION_STATUSES, weights=VALIDATION_WEIGHTS)[0]


def _generate_replacement(secret_type: str) -> str:
    """Generate a mock replacement credential."""
    charset = string.ascii_letters + string.digits
    if "AWS" in secret_type:
        return "AKIA" + "".join(random.choices(string.ascii_uppercase + string.digits, k=16))
    if "GitHub" in secret_type:
        return "ghp_" + "".join(random.choices(charset, k=36))
    if "Stripe" in secret_type:
        return "sk_live_" + "".join(random.choices(charset, k=24))
    if "Slack" in secret_type:
        return "xoxb-" + "".join(random.choices(string.digits, k=12)) + "-" + "".join(random.choices(charset, k=24))
    return "rotated_" + "".join(random.choices(charset, k=32))


def rotate_credential(finding_id: int, db: Database) -> dict:
    """Execute a mock rotation workflow for a finding."""
    finding = db.get_finding(finding_id)
    if not finding:
        return {"error": "Finding not found"}

    log("info", "rotation", f"Initiating mock rotation for finding #{finding_id} ({finding['secret_type']})")

    # Step 1: Validate
    validation = mock_validate(finding["secret_type"], finding["masked_preview"])
    db.update_finding(finding_id, validation_status=validation)

    # Step 2: Generate replacement
    new_secret = _generate_replacement(finding["secret_type"])
    new_masked = mask_secret(new_secret)

    # Step 3: Create rotation record
    rotation_id = db.add_rotation(finding_id, finding["masked_preview"], new_masked)

    # Step 4: Simulate rotation with possible retry
    retries = 0
    success = random.random() < 0.85  # 85% first-try success
    if not success:
        retries = 1
        db.update_rotation(rotation_id, "retrying", retries)
        time.sleep(0.1)  # brief simulated delay
        success = random.random() < 0.95

    if success:
        db.update_rotation(rotation_id, "completed", retries)
        db.update_finding(finding_id, rotation_status="rotated")
        log("info", "rotation", f"Rotation completed for finding #{finding_id} (retries: {retries})")
        status = "completed"
    else:
        db.update_rotation(rotation_id, "failed", retries)
        db.update_finding(finding_id, rotation_status="failed")
        log("warning", "rotation", f"Rotation failed for finding #{finding_id}")
        status = "failed"

    return {
        "finding_id": finding_id,
        "secret_type": finding["secret_type"],
        "validation_status": validation,
        "old_masked": finding["masked_preview"],
        "new_masked": new_masked,
        "rotation_status": status,
        "retries": retries,
    }


def bulk_rotate_critical(db: Database) -> list[dict]:
    """Rotate all critical findings that haven't been rotated."""
    findings = db.get_findings(severity="Critical")
    results = []
    for f in findings:
        if f["rotation_status"] not in ("rotated", "completed"):
            results.append(rotate_credential(f["id"], db))
    return results

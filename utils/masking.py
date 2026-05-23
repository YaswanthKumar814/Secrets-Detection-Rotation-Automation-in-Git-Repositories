"""Mask secrets so they never appear in full in UI or logs."""


def mask_secret(value: str, show_chars: int = 4) -> str:
    if not value:
        return "***"
    value = value.strip()
    if len(value) <= show_chars + 4:
        return value[:2] + "*" * (len(value) - 2)
    return value[:show_chars] + "*" * 8 + value[-2:]

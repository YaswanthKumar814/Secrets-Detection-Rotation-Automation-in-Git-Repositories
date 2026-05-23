"""Shannon entropy analysis for secret detection support."""

import math
from collections import Counter


def shannon_entropy(data: str) -> float:
    """Compute Shannon entropy of a string (bits per character)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_high_entropy(data: str, threshold: float = 4.5) -> bool:
    """Check if string has suspiciously high entropy."""
    if len(data) < 8:
        return False
    return shannon_entropy(data) >= threshold


def classify_entropy(entropy: float) -> str:
    """Human-readable entropy classification."""
    if entropy >= 5.5:
        return "Very High"
    if entropy >= 4.5:
        return "High"
    if entropy >= 3.5:
        return "Moderate"
    return "Low"

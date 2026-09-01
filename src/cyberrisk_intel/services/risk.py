from __future__ import annotations


def risk_level(likelihood: int, impact: int) -> str:
    """Return the explainable 3x3 scenario risk level."""
    if likelihood not in {1, 2, 3} or impact not in {1, 2, 3}:
        raise ValueError("likelihood and impact must be 1, 2, or 3")
    score = likelihood * impact
    if score <= 2:
        return "low"
    if score <= 4:
        return "medium"
    return "high"

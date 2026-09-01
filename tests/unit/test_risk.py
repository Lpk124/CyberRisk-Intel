import pytest

from cyberrisk_intel.services.risk import risk_level


@pytest.mark.parametrize(
    ("likelihood", "impact", "expected"),
    [
        (1, 1, "low"),
        (1, 2, "low"),
        (2, 2, "medium"),
        (2, 3, "high"),
        (3, 3, "high"),
    ],
)
def test_risk_level(likelihood: int, impact: int, expected: str) -> None:
    assert risk_level(likelihood, impact) == expected


def test_risk_level_rejects_out_of_range() -> None:
    with pytest.raises(ValueError):
        risk_level(0, 3)

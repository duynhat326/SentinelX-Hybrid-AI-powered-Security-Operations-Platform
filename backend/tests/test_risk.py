import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.risk_engine.score import Weights, asset_points, correlation_points, risk_score


def test_formula_with_all_parts_matches_hand_calculation():
    # 0.4*75 + 0.3*66.67 + 0.2*50 + 0.1*100 = 30 + 20 + 10 + 10 = 70
    score, b = risk_score("high", 3, 5, 50.0)
    assert score == 70 and b["missing"] == [] and b["components"]["correlation"]["value"] == 66.7


def test_missing_threat_intel_is_renormalized_not_zeroed():
    score, b = risk_score("high", 3, 5, None)
    # (0.4*75 + 0.3*66.67 + 0.1*100) / 0.8 = 60 / 0.8 = 75
    assert score == 75 and b["missing"] == ["threat_intel"]
    assert b["effective_weights"] == {"severity": 0.5, "correlation": 0.375, "asset": 0.125}
    assert not b["components"]["threat_intel"]["used"]


def test_everything_unknown_still_yields_a_valid_score():
    score, _ = risk_score("low", 1, None, None)  # only severity and correlation known: (0.4*25 + 0) / 0.7
    assert score == 14


@pytest.mark.parametrize("rules,expected", [(1, 0), (2, 33.3), (3, 66.7), (4, 100), (9, 100), (0, 0)])
def test_correlation_points(rules, expected):
    assert round(correlation_points(rules), 1) == expected


@pytest.mark.parametrize("crit,expected", [(1, 0), (3, 50), (5, 100), (0, 0), (9, 100), (None, None)])
def test_asset_points_clamped(crit, expected):
    assert asset_points(crit) == expected


def test_score_is_monotonic_in_each_input():
    base = [risk_score(s, 2, 3, 40.0)[0] for s in ("low", "medium", "high", "critical")]
    assert base == sorted(base) and len(set(base)) == 4
    assert [risk_score("high", n, 3, 40.0)[0] for n in (1, 2, 3, 4)] == sorted(risk_score("high", n, 3, 40.0)[0] for n in (1, 2, 3, 4))
    assert risk_score("high", 2, 5, 40.0)[0] > risk_score("high", 2, 1, 40.0)[0]
    assert risk_score("high", 2, 3, 90.0)[0] > risk_score("high", 2, 3, 10.0)[0]


def test_bounds_and_ti_clamping():
    assert risk_score("critical", 9, 5, 500.0)[0] == 100
    assert 0 <= risk_score("low", 1, 1, -50.0)[0] <= 100


def test_weights_are_configurable():
    heavy_asset = Weights(severity=0.0, correlation=0.0, threat_intel=0.0, asset=1.0)
    assert risk_score("critical", 4, 1, 100.0, heavy_asset)[0] == 0
    assert risk_score("low", 1, 5, 0.0, heavy_asset)[0] == 100


def test_same_input_same_output():
    assert risk_score("high", 3, 4, 20.0) == risk_score("high", 3, 4, 20.0)


def test_weights_must_sum_to_one(monkeypatch):
    monkeypatch.setenv("SENTINELX_API_KEY", "k" * 32)
    monkeypatch.setenv("SENTINELX_RISK_WEIGHT_SEVERITY", "0.9")
    with pytest.raises(ValidationError, match="sum to 1.0"):
        Settings()

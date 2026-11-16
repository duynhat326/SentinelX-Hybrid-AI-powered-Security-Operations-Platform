import pytest

from evaluation.run import auroc, wilson


def test_wilson_interval_known_values():
    assert wilson(0, 0) is None
    lo, hi = wilson(10, 10)  # 10 of 10 is not certainty: the lower bound shows it
    assert hi == 1.0 and lo == pytest.approx(0.722, abs=0.002)
    lo, hi = wilson(5, 10)
    assert lo < 0.5 < hi


def test_auroc_ties_count_half_and_degenerate_is_none():
    assert auroc([3, 2, 1, 0], [1, 1, 0, 0]) == 1.0
    assert auroc([0, 1, 2, 3], [1, 1, 0, 0]) == 0.0
    assert auroc([1, 1, 1, 1], [1, 0, 1, 0]) == 0.5
    assert auroc([1, 2], [1, 1]) is None

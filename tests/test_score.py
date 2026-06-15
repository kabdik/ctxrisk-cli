"""Pin the scoring engine to the worked examples in
``method/Context-Sensitive Risk Score.md`` §6.

If any number here drifts from the formalisation, the test fails and we
notice immediately.
"""

import math
import pytest

from ctxrisk.score import (
    Factors, ScoreResult, score, severity_band,
    DEFAULT_WEIGHTS, DEFAULT_C_MIN, DEFAULT_C_MAX,
)


# -- §6 Example A: context reduces risk --------------------------------------
def test_example_a_reduces_critical_to_medium():
    r = score(base=9.0, factors=Factors(exp=0.0, run=0.0, priv=0.0, mnt=0.0))
    assert math.isclose(r.s, 0.0, abs_tol=1e-9)
    assert math.isclose(r.c, 0.5, abs_tol=1e-9)
    assert math.isclose(r.risk, 4.5, abs_tol=1e-9)
    assert r.severity == "Medium"


# -- §6 Example B: context amplifies risk ------------------------------------
def test_example_b_amplifies_medium_to_high():
    r = score(base=5.0, factors=Factors(exp=1.0, run=1.0, priv=1.0, mnt=1.0))
    assert math.isclose(r.s, 1.0, abs_tol=1e-9)
    assert math.isclose(r.c, 1.5, abs_tol=1e-9)
    assert math.isclose(r.risk, 7.5, abs_tol=1e-9)
    assert r.severity == "High"


# -- §6 Example C₁: runtime says "never observed" → High ---------------------
def test_example_c1_runtime_never_observed():
    r = score(base=9.0, factors=Factors(exp=1.0, run=0.0, priv=0.25, mnt=0.0))
    assert math.isclose(r.s, 0.45, abs_tol=1e-9)
    assert math.isclose(r.c, 0.95, abs_tol=1e-9)
    assert math.isclose(r.risk, 8.55, abs_tol=1e-9)
    assert r.severity == "High"


# -- §6 Example C₂: runtime says "symbol executing" → clamped Critical -------
def test_example_c2_runtime_observed_executing_clamps_at_10():
    r = score(base=9.0, factors=Factors(exp=1.0, run=1.0, priv=0.25, mnt=0.0))
    assert math.isclose(r.s, 0.70, abs_tol=1e-9)
    assert math.isclose(r.c, 1.20, abs_tol=1e-9)
    # B·C = 10.8 → clamped to 10.0
    assert math.isclose(r.risk, 10.0, abs_tol=1e-9)
    assert r.severity == "Critical"


# -- Generalisation property: S=0.5 → C=1 → R=B ------------------------------
def test_neutral_context_reduces_to_plain_cvss():
    """method §4 'Generalisation of CVSS'."""
    for b in (1.0, 3.5, 7.0, 9.8):
        r = score(base=b, factors=Factors(exp=0.5, run=0.5, priv=0.5, mnt=0.5))
        assert math.isclose(r.c, 1.0, abs_tol=1e-9)
        assert math.isclose(r.risk, b, abs_tol=1e-9)


# -- Bounded deviation property: R ∈ [0.5B, 1.5B] ∩ [0, 10] -----------------
@pytest.mark.parametrize("b", [0.0, 1.0, 5.0, 9.5, 10.0])
def test_bounded_deviation(b):
    """method §4 'Bounded deviation'."""
    # extreme low
    r_lo = score(base=b, factors=Factors(exp=0.0, run=0.0, priv=0.0, mnt=0.0))
    # extreme high
    r_hi = score(base=b, factors=Factors(exp=1.0, run=1.0, priv=1.0, mnt=1.0))
    assert math.isclose(r_lo.risk, max(0.0, min(10.0, 0.5 * b)), abs_tol=1e-9)
    assert math.isclose(r_hi.risk, max(0.0, min(10.0, 1.5 * b)), abs_tol=1e-9)


# -- Monotonicity in B ------------------------------------------------------
def test_monotone_in_base():
    """method §4 'Monotonicity'."""
    f = Factors(exp=0.3, run=0.7, priv=0.2, mnt=0.4)
    rs = [score(base=b, factors=f).risk for b in (1.0, 3.0, 5.0, 8.0, 9.5)]
    assert rs == sorted(rs)


# -- Monotonicity in each factor --------------------------------------------
@pytest.mark.parametrize("axis", ["exp", "run", "priv", "mnt"])
def test_monotone_in_each_factor(axis):
    """method §4 'Monotonicity'."""
    base = {"exp": 0.0, "run": 0.0, "priv": 0.0, "mnt": 0.0}
    risks = []
    for v in (0.0, 0.25, 0.5, 0.75, 1.0):
        f = Factors(**{**base, axis: v})
        risks.append(score(base=7.0, factors=f).risk)
    assert risks == sorted(risks)


# -- Severity bands match the CVSS thresholds in the method spec -------------
@pytest.mark.parametrize("r, band", [
    (0.0,  "None"),
    (0.1,  "Low"),
    (3.9,  "Low"),
    (4.0,  "Medium"),
    (6.9,  "Medium"),
    (7.0,  "High"),
    (8.9,  "High"),
    (9.0,  "Critical"),
    (10.0, "Critical"),
])
def test_severity_bands(r, band):
    assert severity_band(r) == band


# -- Weights validated ------------------------------------------------------
def test_weights_must_sum_to_one():
    with pytest.raises(ValueError):
        score(base=5.0, factors=Factors(0, 0, 0, 0),
              weights={"exp": 0.3, "run": 0.3, "priv": 0.3, "mnt": 0.3})


# -- Factor values validated ------------------------------------------------
@pytest.mark.parametrize("bad", [-0.1, 1.1, 2.0])
def test_factor_value_validated(bad):
    with pytest.raises(ValueError):
        Factors(exp=bad, run=0, priv=0, mnt=0)


# -- Default weights sum to 1 -----------------------------------------------
def test_default_weights_sum_to_one():
    assert math.isclose(sum(DEFAULT_WEIGHTS.values()), 1.0, abs_tol=1e-9)


# -- Range default ----------------------------------------------------------
def test_default_range():
    assert DEFAULT_C_MIN == 0.5
    assert DEFAULT_C_MAX == 1.5

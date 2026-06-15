"""Scoring engine: aggregate context factors into a final risk score R.

Implements method/Context-Sensitive Risk Score.md §2.3–§2.5 exactly:

    S = w_exp·x_exp + w_run·x_run + w_priv·x_priv + w_mnt·x_mnt    (Σ w = 1)
    C = C_min + (C_max - C_min) · S                                (default [0.5, 1.5])
    R = clamp(B · C, 0, 10)

Default weights and range are the ones agreed in the formalisation; they are
intentionally exposed as parameters so the evaluation (Ch. 6) can vary them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

DEFAULT_WEIGHTS: dict[str, float] = {
    "exp":  0.40,
    "run":  0.25,
    "priv": 0.20,
    "mnt":  0.15,
}

DEFAULT_C_MIN = 0.5
DEFAULT_C_MAX = 1.5


@dataclass(frozen=True)
class Factors:
    """The four context factor readings for one CVE × workload."""
    exp:  float
    run:  float
    priv: float
    mnt:  float

    def __post_init__(self):
        for name in ("exp", "run", "priv", "mnt"):
            v = getattr(self, name)
            if not (0.0 <= v <= 1.0):
                raise ValueError(f"factor x_{name} = {v} out of [0, 1]")


@dataclass(frozen=True)
class ScoreResult:
    base: float          # B — CVSS base score
    factors: Factors
    weights: dict[str, float]
    s: float             # weighted sum of factors, in [0, 1]
    c: float             # multiplier, in [C_min, C_max]
    risk: float          # R = clamp(B·C, 0, 10), final score

    @property
    def severity(self) -> str:
        return severity_band(self.risk)


def score(base: float,
          factors: Factors,
          weights: dict[str, float] | None = None,
          c_min: float = DEFAULT_C_MIN,
          c_max: float = DEFAULT_C_MAX) -> ScoreResult:
    """Compute the context-sensitive risk score for one CVE × workload.

    Parameters
    ----------
    base : float
        CVSS Base Score B in [0, 10] for the vulnerability.
    factors : Factors
        The four normalised context factor readings in [0, 1].
    weights : dict[str, float], optional
        Mapping of "exp"/"run"/"priv"/"mnt" → weight. Must sum to 1.
        Defaults to DEFAULT_WEIGHTS.
    c_min, c_max : float
        Multiplier range. Default [0.5, 1.5] places the neutral point at S=0.5.
    """
    if not (0.0 <= base <= 10.0):
        raise ValueError(f"base score {base} out of [0, 10]")
    if c_min >= c_max:
        raise ValueError(f"c_min ({c_min}) must be < c_max ({c_max})")

    w = weights or DEFAULT_WEIGHTS
    total = w["exp"] + w["run"] + w["priv"] + w["mnt"]
    if abs(total - 1.0) > 1e-9:
        raise ValueError(f"weights must sum to 1, got {total}")

    s = (
        w["exp"]  * factors.exp
        + w["run"]  * factors.run
        + w["priv"] * factors.priv
        + w["mnt"]  * factors.mnt
    )
    c = c_min + (c_max - c_min) * s
    r = max(0.0, min(10.0, base * c))

    return ScoreResult(
        base=base, factors=factors, weights=dict(w),
        s=s, c=c, risk=r,
    )


def severity_band(score: float) -> str:
    """Map a score in [0, 10] to CVSS severity bands."""
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"

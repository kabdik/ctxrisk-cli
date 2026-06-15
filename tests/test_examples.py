"""Integration test: load the example K8s manifests and verify they produce
the factor values that the worked examples in
``method/Context-Sensitive Risk Score.md`` §6 are pinned to.

If this test fails it means either the YAML examples drifted from the
formalisation, or the extractors did.
"""

from pathlib import Path

import math
import yaml

from ctxrisk.factors import exposure_level, privilege_level, mount_sensitivity
from ctxrisk.score import Factors, score

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _load_all(path: Path) -> list[dict]:
    return [d for d in yaml.safe_load_all(path.read_text()) if d]


def _split(objs: list[dict]) -> tuple[dict, list[dict], list[dict]]:
    """Return (first Pod found, all Services, all Ingresses)."""
    pod = next(o for o in objs if o.get("kind") == "Pod")
    services = [o for o in objs if o.get("kind") == "Service"]
    ingresses = [o for o in objs if o.get("kind") == "Ingress"]
    return pod, services, ingresses


def test_scenario_a_factors_match_method_section_6():
    pod, svcs, ings = _split(_load_all(EXAMPLES / "scenario-a-hardened-internal.yaml"))
    assert exposure_level(pod, svcs, ings) == 0.0
    assert privilege_level(pod) == 0.0
    assert mount_sensitivity(pod) == 0.0

    # End-to-end: with x_run=0 (vulnerable package never observed) → R=4.5
    r = score(base=9.0, factors=Factors(exp=0.0, run=0.0, priv=0.0, mnt=0.0))
    assert math.isclose(r.risk, 4.5)
    assert r.severity == "Medium"


def test_scenario_b_factors_match_method_section_6():
    pod, svcs, ings = _split(_load_all(EXAMPLES / "scenario-b-privileged-exposed.yaml"))
    # public_hint=True because of the AWS internet-facing annotation
    assert exposure_level(pod, svcs, ings, public_hint=True) == 1.0
    assert privilege_level(pod) == 1.0
    assert mount_sensitivity(pod) == 1.0

    r = score(base=5.0, factors=Factors(exp=1.0, run=1.0, priv=1.0, mnt=1.0))
    assert math.isclose(r.risk, 7.5)
    assert r.severity == "High"


def test_scenario_c_factors_match_method_section_6():
    pod, svcs, ings = _split(_load_all(EXAMPLES / "scenario-c-public-nonroot.yaml"))
    assert exposure_level(pod, svcs, ings, public_hint=True) == 1.0
    assert privilege_level(pod) == 0.25
    assert mount_sensitivity(pod) == 0.0

    # C1: vulnerable code never observed
    r1 = score(base=9.0, factors=Factors(exp=1.0, run=0.0, priv=0.25, mnt=0.0))
    assert math.isclose(r1.risk, 8.55)
    assert r1.severity == "High"

    # C2: vulnerable symbol observed → clamps at 10.0
    r2 = score(base=9.0, factors=Factors(exp=1.0, run=1.0, priv=0.25, mnt=0.0))
    assert math.isclose(r2.risk, 10.0)
    assert r2.severity == "Critical"

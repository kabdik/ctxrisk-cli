"""Tests for the Trivy parser. Uses a real Trivy JSON output saved as a
fixture so the test does not require network access or a Trivy install.
"""

import json
from pathlib import Path

import pytest

from ctxrisk.scan import (
    CVSS_SOURCE_PREFERENCE,
    SEVERITY_FALLBACK,
    Vulnerability,
    parse_trivy_json,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures-trivy-rabbitmq.json"


def test_fixture_parses_to_nonempty_list():
    data = json.loads(FIXTURE.read_text())
    vulns = parse_trivy_json(data)
    assert vulns, "fixture should contain at least one CVE"
    assert all(isinstance(v, Vulnerability) for v in vulns)


def test_every_finding_has_a_base_score():
    data = json.loads(FIXTURE.read_text())
    vulns = parse_trivy_json(data)
    for v in vulns:
        assert 0.0 <= v.cvss_base <= 10.0
        assert v.cvss_source  # always populated, even if fallback


def test_cvss_source_prefers_nvd_when_present():
    """If a record has nvd CVSS, that one wins over julia / redhat."""
    record = {"Results": [{"Vulnerabilities": [{
        "VulnerabilityID": "CVE-X",
        "PkgName": "p", "InstalledVersion": "1",
        "Severity": "HIGH",
        "CVSS": {
            "nvd":    {"V3Score": 6.0},
            "redhat": {"V3Score": 9.8},
            "julia":  {"V3Score": 9.9},
        },
    }]}]}
    v = parse_trivy_json(record)[0]
    assert v.cvss_base == 6.0
    assert v.cvss_source == "nvd"


def test_cvss_falls_back_to_severity_when_no_numeric():
    record = {"Results": [{"Vulnerabilities": [{
        "VulnerabilityID": "CVE-X",
        "PkgName": "p", "InstalledVersion": "1",
        "Severity": "CRITICAL",
        # no CVSS field at all
    }]}]}
    v = parse_trivy_json(record)[0]
    assert v.cvss_base == SEVERITY_FALLBACK["CRITICAL"]
    assert v.cvss_source.startswith("fallback:")


def test_preference_order_documented_constant_consistent():
    """The CVSS source order must include 'nvd' as first — see method §2.1
    ('B(v) ∈ [0,10] — CVSS v3.1 Base Score of v, from the NVD')."""
    assert CVSS_SOURCE_PREFERENCE[0] == "nvd"


def test_empty_results_returns_empty_list():
    assert parse_trivy_json({"Results": []}) == []
    assert parse_trivy_json({}) == []

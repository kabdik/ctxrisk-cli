"""End-to-end CLI smoke test using Click's test runner. No network.

Confirms the demo pipeline runs and produces the expected ranking shape:
loading a Trivy fixture + a K8s workload + a runtime observation, and printing
both raw-CVSS and context-sensitive rankings.
"""

from pathlib import Path

from click.testing import CliRunner

from ctxrisk.cli import main

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures-trivy-rabbitmq.json"


def test_score_runs_end_to_end_on_scenario_c():
    runner = CliRunner()
    result = runner.invoke(main, [
        "score",
        "--scan-json", str(FIXTURE),
        "--workload",  str(ROOT / "examples" / "scenario-c-public-nonroot.yaml"),
        "--runtime",   str(ROOT / "examples" / "scenario-c-runtime.json"),
        "--public-hint",
        "--top", "5",
    ])
    assert result.exit_code == 0, result.output
    assert "Top 5 by raw CVSS Base" in result.output
    assert "Top 5 by context-sensitive R" in result.output
    assert "x_exp=" in result.output
    assert "Critical" in result.output or "High" in result.output


def test_score_requires_image_or_scan_json():
    runner = CliRunner()
    result = runner.invoke(main, [
        "score",
        "--workload", str(ROOT / "examples" / "scenario-a-hardened-internal.yaml"),
    ])
    assert result.exit_code != 0
    assert "image" in result.output.lower() or "scan-json" in result.output.lower()


def test_score_with_scenario_a_reports_low_x_factors():
    runner = CliRunner()
    result = runner.invoke(main, [
        "score",
        "--scan-json", str(FIXTURE),
        "--workload",  str(ROOT / "examples" / "scenario-a-hardened-internal.yaml"),
        "--top", "3",
    ])
    assert result.exit_code == 0, result.output
    # Hardened, unreachable workload — static factors all zero
    assert "x_exp=0.00" in result.output
    assert "x_priv=0.00" in result.output
    assert "x_mnt=0.00" in result.output

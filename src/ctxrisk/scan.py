"""Invoke Trivy and normalise its JSON output into a flat list of CVEs.

Why a dedicated layer:
- Trivy's JSON has multiple CVSS sources (``nvd``, ``redhat``, ``julia``, ...);
  we pick one with a deterministic preference so the score is reproducible.
- Different Trivy versions / image types may reshape the JSON; isolating the
  parsing here keeps the rest of the codebase stable.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

# Order in which we trust CVSS sources when a vulnerability lists several.
# NVD first — it is what the formalisation calls ``B(v) ∈ [0,10]``; other
# vendors fall back in order of consensus reliability.
CVSS_SOURCE_PREFERENCE = ("nvd", "redhat", "ghsa", "julia")

# Coarse fallback when no numeric CVSS is present in the record.
SEVERITY_FALLBACK = {
    "CRITICAL": 9.5,
    "HIGH":     7.5,
    "MEDIUM":   5.0,
    "LOW":      2.5,
    "UNKNOWN":  0.0,
}


@dataclass(frozen=True)
class Vulnerability:
    """One CVE × package finding, normalised for scoring."""
    cve: str
    package: str
    installed_version: str
    fixed_version: str | None
    cvss_base: float
    cvss_source: str           # which CVSS field we used ("nvd" / "redhat" / "fallback:HIGH")
    severity: str              # Trivy's coarse rating
    title: str

    @property
    def package_lower(self) -> str:
        return self.package.lower()


def scan_image(image: str,
               severities: Iterable[str] = ("HIGH", "CRITICAL"),
               timeout: int = 300) -> list[Vulnerability]:
    """Run ``trivy image --format json`` and return parsed findings.

    Raises ``RuntimeError`` if Trivy is not installed or the scan fails.
    """
    if shutil.which("trivy") is None:
        raise RuntimeError(
            "trivy is not installed or not on PATH. "
            "Install with `brew install trivy` (macOS) or see https://trivy.dev."
        )
    cmd = [
        "trivy", "image",
        "--format", "json",
        "--severity", ",".join(severities),
        "--quiet",
        image,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"trivy failed (exit {proc.returncode}): {proc.stderr.strip()}")
    data = json.loads(proc.stdout)
    return parse_trivy_json(data)


def parse_trivy_json(data: dict) -> list[Vulnerability]:
    """Convert a Trivy JSON document into a flat list of ``Vulnerability``.

    Pure function — used by tests with fixture data and by the CLI.
    """
    out: list[Vulnerability] = []
    for block in data.get("Results") or []:
        for v in block.get("Vulnerabilities") or []:
            base, source = _pick_cvss(v)
            out.append(Vulnerability(
                cve=v.get("VulnerabilityID", "?"),
                package=v.get("PkgName", "?"),
                installed_version=v.get("InstalledVersion", "?"),
                fixed_version=v.get("FixedVersion") or None,
                cvss_base=base,
                cvss_source=source,
                severity=v.get("Severity", "UNKNOWN"),
                title=(v.get("Title") or "").strip(),
            ))
    return out


def load_trivy_json_file(path: Path) -> list[Vulnerability]:
    """Read a previously-saved Trivy JSON file."""
    return parse_trivy_json(json.loads(Path(path).read_text()))


def _pick_cvss(v: dict) -> tuple[float, str]:
    cvss = v.get("CVSS") or {}
    # Preferred sources, in order
    for src in CVSS_SOURCE_PREFERENCE:
        entry = cvss.get(src) or {}
        score = entry.get("V3Score") or entry.get("V4Score") or entry.get("V2Score")
        if isinstance(score, (int, float)):
            return float(score), src
    # Any remaining source
    for src, entry in cvss.items():
        score = (entry or {}).get("V3Score") or (entry or {}).get("V4Score") or (entry or {}).get("V2Score")
        if isinstance(score, (int, float)):
            return float(score), src
    # Last-ditch fallback based on the coarse Severity string
    sev = (v.get("Severity") or "UNKNOWN").upper()
    return SEVERITY_FALLBACK.get(sev, 0.0), f"fallback:{sev}"

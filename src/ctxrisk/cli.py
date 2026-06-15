"""ctxrisk CLI — the live-demo entry point.

End-to-end flow::

    ctxrisk score --image IMG --workload WORKLOAD.yaml [--runtime RUNTIME.json] [--symbols SYM.json]

reads:
  1. Trivy scan of the image (or a cached JSON via --scan-json),
  2. K8s manifest(s) → static context factors x_exp, x_priv, x_mnt,
  3. Optional runtime observation JSON → x_run (default 0.5 if absent),
  4. Optional CVE → vulnerable-symbol mapping JSON,

and prints two ranked tables: raw CVSS Base vs the context-sensitive R, plus
a per-CVE explanation of how the score moved.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

import click
import yaml

from .factors import (
    exposure_level, mount_sensitivity, privilege_level, runtime_reachability,
)
from .scan import Vulnerability, load_trivy_json_file, scan_image
from .score import (
    DEFAULT_C_MAX, DEFAULT_C_MIN, DEFAULT_WEIGHTS,
    Factors, ScoreResult, score, severity_band,
)


# ---------------------------------------------------------------------------
# Data plumbing
# ---------------------------------------------------------------------------

@dataclass
class Workload:
    pod: dict
    services: list
    ingresses: list


def load_workload(path: Path) -> Workload:
    objs = [d for d in yaml.safe_load_all(Path(path).read_text()) if d]
    pods = [o for o in objs if o.get("kind") == "Pod"]
    # Deployment / StatefulSet / DaemonSet — extract embedded pod template
    for o in objs:
        if o.get("kind") in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}:
            tmpl = (((o.get("spec") or {}).get("template")) or {})
            if tmpl:
                # Surface labels onto the synthesized pod for service matching
                meta = dict(tmpl.get("metadata") or {})
                meta_labels = meta.get("labels") or (o.get("spec", {}).get("selector", {}).get("matchLabels") or {})
                pod = {"metadata": {"labels": meta_labels}, "spec": tmpl.get("spec") or {}}
                pods.append(pod)
    if not pods:
        raise click.UsageError(f"No Pod/Deployment-like workload found in {path}")
    return Workload(
        pod=pods[0],
        services=[o for o in objs if o.get("kind") == "Service"],
        ingresses=[o for o in objs if o.get("kind") == "Ingress"],
    )


def load_runtime(path: Path | None) -> dict | None:
    if path is None:
        return None
    return json.loads(Path(path).read_text())


def load_symbols(path: Path | None) -> dict:
    if path is None:
        return {}
    raw = json.loads(Path(path).read_text())
    return {k: (v if isinstance(v, str) else v.get("symbol")) for k, v in raw.items()}


def parse_weights(s: str | None) -> dict:
    if not s:
        return DEFAULT_WEIGHTS
    parts = [p.strip() for p in s.split(",") if p.strip()]
    out = {}
    for p in parts:
        k, _, v = p.partition("=")
        if not k or not v:
            raise click.UsageError(f"Bad --weights entry: {p!r}, expected key=value")
        out[k.strip()] = float(v)
    missing = set(DEFAULT_WEIGHTS) - set(out)
    if missing:
        raise click.UsageError(f"--weights missing keys: {sorted(missing)}")
    return out


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

SEVERITY_COLOUR = {
    "Critical": "bright_red",
    "High":     "red",
    "Medium":   "yellow",
    "Low":      "green",
    "None":     "white",
}


def _fmt_sev(sev: str) -> str:
    return click.style(f"{sev:8s}", fg=SEVERITY_COLOUR.get(sev, "white"))


def print_comparison(scored: list[tuple[Vulnerability, ScoreResult]], top: int) -> None:
    """Print: raw-CVSS top-N | context-R top-N | rank-change explanation."""
    by_base = sorted(scored, key=lambda x: x[0].cvss_base, reverse=True)[:top]
    by_risk = sorted(scored, key=lambda x: x[1].risk, reverse=True)[:top]
    base_rank = {v.cve: i + 1 for i, (v, _) in enumerate(sorted(scored, key=lambda x: x[0].cvss_base, reverse=True))}
    risk_rank = {v.cve: i + 1 for i, (v, _) in enumerate(sorted(scored, key=lambda x: x[1].risk, reverse=True))}

    click.echo()
    click.secho(f"Top {top} by raw CVSS Base                              "
                f"Top {top} by context-sensitive R", bold=True)
    click.secho("-" * 110, dim=True)
    for i in range(top):
        if i < len(by_base):
            v, r = by_base[i]
            left = f"{i+1:2d}. {v.cve:18s} {v.cvss_base:4.1f} {_fmt_sev(severity_band(v.cvss_base))}"
        else:
            left = " " * 50
        if i < len(by_risk):
            v, r = by_risk[i]
            move = base_rank[v.cve] - (i + 1)
            arrow = (click.style(f"↑{move}", fg="bright_green") if move > 0
                     else click.style(f"↓{-move}", fg="bright_red") if move < 0
                     else click.style(" =", fg="white"))
            right = f"{i+1:2d}. {v.cve:18s} {r.risk:4.1f} {_fmt_sev(r.severity)} {arrow}"
        else:
            right = ""
        click.echo(f"{left}     {right}")

    # Per-CVE factor breakdown for the new top
    click.echo()
    click.secho("Why the context-sensitive ranking moved (top results):", bold=True)
    click.secho("-" * 110, dim=True)
    for i, (v, r) in enumerate(by_risk):
        f = r.factors
        click.echo(
            f"  {v.cve}  ({v.package} {v.installed_version})"
            f"  B={r.base:.1f} [{v.cvss_source}]"
        )
        click.echo(
            f"     x_exp={f.exp:.2f} · x_run={f.run:.2f} · x_priv={f.priv:.2f} · x_mnt={f.mnt:.2f}"
            f"  →  S={r.s:.3f}  C={r.c:.3f}  R={r.risk:.2f} ({r.severity})"
        )
        if v.fixed_version:
            click.secho(f"     fix available in: {v.fixed_version}", dim=True)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

@click.group()
@click.version_option()
def main():
    """ctxrisk — context-sensitive container risk scoring."""


@main.command("score")
@click.option("--image", help="Docker image to scan with Trivy (e.g. nginx:1.25).")
@click.option("--scan-json", type=click.Path(exists=True, path_type=Path),
              help="Use a previously-saved Trivy JSON instead of running a scan.")
@click.option("--workload", required=True, type=click.Path(exists=True, path_type=Path),
              help="Path to a K8s manifest (Pod/Deployment/StatefulSet/etc.).")
@click.option("--runtime", type=click.Path(exists=True, path_type=Path),
              help="Path to a runtime observation JSON (Falco-style). If absent, x_run defaults to 0.5.")
@click.option("--symbols", type=click.Path(exists=True, path_type=Path),
              help='Optional CVE → vulnerable-symbol map JSON (e.g. {"CVE-2023-1": "openssl.RAND_bytes"}).')
@click.option("--public-hint/--no-public-hint", default=False,
              help="Force x_exp=1.0 (use when the service is known internet-facing).")
@click.option("--weights", default=None,
              help="Override weights, e.g. 'exp=0.4,run=0.25,priv=0.2,mnt=0.15'.")
@click.option("--top", default=10, show_default=True, help="Show top-N entries.")
@click.option("--severity", default="HIGH,CRITICAL", show_default=True,
              help="Comma-separated Trivy severities to include.")
def cmd_score(image, scan_json, workload, runtime, symbols, public_hint, weights, top, severity):
    """Scan an image and re-rank its CVEs by the context-sensitive risk score."""
    if not image and not scan_json:
        raise click.UsageError("Provide --image to scan, or --scan-json with a cached scan.")

    # 1. Vulnerabilities
    if scan_json:
        click.secho(f"Loading scan from {scan_json} …", dim=True, err=True)
        vulns = load_trivy_json_file(scan_json)
    else:
        click.secho(f"Scanning image {image} with Trivy …", dim=True, err=True)
        vulns = scan_image(image, severities=severity.split(","))
    if not vulns:
        click.secho("No vulnerabilities found at the requested severity.", fg="green")
        return
    click.secho(f"Found {len(vulns)} CVEs.", dim=True, err=True)

    # 2. Static context from K8s manifest
    wl = load_workload(workload)
    x_exp = exposure_level(wl.pod, wl.services, wl.ingresses, public_hint=public_hint)
    x_priv = privilege_level(wl.pod)
    x_mnt = mount_sensitivity(wl.pod)
    click.secho(
        f"Static context from {workload.name}:  "
        f"x_exp={x_exp:.2f}  x_priv={x_priv:.2f}  x_mnt={x_mnt:.2f}",
        dim=True, err=True,
    )

    # 3. Runtime observation + CVE→symbol map
    obs = load_runtime(runtime)
    sym_map = load_symbols(symbols)
    if obs is None:
        click.secho("No runtime observation provided — x_run defaults to 0.5 per fallback rule.",
                    dim=True, err=True)

    # 4. Score each CVE
    w = parse_weights(weights)
    scored: list[tuple[Vulnerability, ScoreResult]] = []
    for v in vulns:
        x_run = runtime_reachability(v.package, sym_map.get(v.cve), obs)
        factors = Factors(exp=x_exp, run=x_run, priv=x_priv, mnt=x_mnt)
        r = score(base=v.cvss_base, factors=factors, weights=w)
        scored.append((v, r))

    # 5. Present
    print_comparison(scored, top=top)


@main.command("scan")
@click.argument("image")
@click.option("--out", type=click.Path(path_type=Path), default=Path("scan.json"),
              show_default=True, help="Where to save the Trivy JSON.")
@click.option("--severity", default="HIGH,CRITICAL", show_default=True)
def cmd_scan(image, out, severity):
    """Just run a Trivy scan and save the JSON (cache for later --scan-json runs)."""
    click.secho(f"Scanning {image} …", err=True)
    import subprocess
    proc = subprocess.run(
        ["trivy", "image", "--format", "json", "--severity", severity, "--quiet", image],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        click.secho(proc.stderr, fg="red", err=True)
        sys.exit(proc.returncode)
    out.write_text(proc.stdout)
    click.secho(f"Saved {out}", fg="green")


if __name__ == "__main__":
    main()

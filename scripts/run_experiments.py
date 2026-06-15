#!/usr/bin/env python3
"""Run the empirical evaluation reported in Chapter 6.

Produces CSV artefacts in `prototype/experiments/`:
- e1_factor_coverage.csv      — scenarios × (x_run states) → R for fixed B
- e2_real_images.csv          — per-CVE rows for every (image × scenario) pair
- e3_runtime_ablation.csv     — runtime-on vs runtime-off scoring per image
- e4_baseline_correlation.csv — Spearman ρ and Kendall τ vs raw-CVSS ranking
- e5_weight_sensitivity.csv   — top-K stability under ±20% weight perturbation

The script is intentionally self-contained: it reads the prototype's own
modules and the example manifests, scans images on demand via Trivy (or
uses a saved JSON), and writes plain CSV for downstream tabulation.
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from statistics import mean, stdev

import yaml

# Ensure src/ on path when running from prototype/
SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

from ctxrisk.factors import (
    exposure_level,
    mount_sensitivity,
    privilege_level,
    runtime_reachability,
)
from ctxrisk.scan import Vulnerability, load_trivy_json_file, parse_trivy_json
from ctxrisk.score import (
    DEFAULT_C_MAX,
    DEFAULT_C_MIN,
    DEFAULT_WEIGHTS,
    Factors,
    score,
    severity_band,
)

PROTO = Path(__file__).resolve().parent.parent
EXAMPLES = PROTO / "examples"
EXPERIMENTS = PROTO / "experiments"
EXPERIMENTS.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Scenarios — eight K8s manifests covering the factor space
# ---------------------------------------------------------------------------

SCENARIOS = [
    # (id,  filename,                              public_hint)
    ("A", "scenario-a-hardened-internal.yaml",     False),
    ("B", "scenario-b-privileged-exposed.yaml",    True),
    ("C", "scenario-c-public-nonroot.yaml",        True),
    ("D", "scenario-d-default-internal.yaml",      False),
    ("E", "scenario-e-hardened-public.yaml",       True),
    ("F", "scenario-f-root-exposed-clean.yaml",    True),
    ("G", "scenario-g-clusterip-defaults.yaml",    False),
    ("H", "scenario-h-hostpath-internal.yaml",     False),
]


def load_scenario(filename: str):
    objs = [o for o in yaml.safe_load_all((EXAMPLES / filename).read_text()) if o]
    pod = next(o for o in objs if o.get("kind") == "Pod")
    services = [o for o in objs if o.get("kind") == "Service"]
    ingresses = [o for o in objs if o.get("kind") == "Ingress"]
    return pod, services, ingresses


def factors_for_scenario(sid: str):
    """Return (x_exp, x_priv, x_mnt) for a scenario id."""
    fname, hint = next((f, h) for (s, f, h) in SCENARIOS if s == sid)
    pod, svcs, ings = load_scenario(fname)
    return (
        exposure_level(pod, svcs, ings, public_hint=hint),
        privilege_level(pod),
        mount_sensitivity(pod),
    )


# ---------------------------------------------------------------------------
# Images — three already-cached Docker images, diverse in base OS and role
# ---------------------------------------------------------------------------

IMAGES = [
    "rabbitmq:3.13-management-alpine",
    "postgres:17",
    "redis:7-alpine",
]


def scan_image(image: str, cache_dir: Path) -> list[Vulnerability]:
    """Scan with Trivy, caching the JSON to ``cache_dir``."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    safe = image.replace("/", "_").replace(":", "_")
    cache_file = cache_dir / f"trivy-{safe}.json"

    if cache_file.exists():
        print(f"  [cache] {image} → {cache_file.name}")
        return load_trivy_json_file(cache_file)

    print(f"  [scan]  {image} (saving to {cache_file.name})")
    proc = subprocess.run(
        ["trivy", "image", "--format", "json",
         "--severity", "HIGH,CRITICAL", "--quiet", image],
        capture_output=True, text=True, timeout=600,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"trivy failed on {image}: {proc.stderr.strip()}")
    cache_file.write_text(proc.stdout)
    return parse_trivy_json(json.loads(proc.stdout))


# ---------------------------------------------------------------------------
# E1 — factor-space coverage
# ---------------------------------------------------------------------------

def e1_factor_coverage(base_score: float = 9.0) -> None:
    """For each of the 8 scenarios × 3 runtime states, tabulate R."""
    rows = []
    for sid, fname, hint in SCENARIOS:
        xe, xp, xm = factors_for_scenario(sid)
        for run_label, x_run in (("never", 0.0), ("inconclusive", 0.5), ("observed", 1.0)):
            r = score(base=base_score, factors=Factors(exp=xe, run=x_run, priv=xp, mnt=xm))
            rows.append({
                "scenario": sid,
                "x_exp": xe,
                "x_priv": xp,
                "x_mnt": xm,
                "x_run_state": run_label,
                "x_run": x_run,
                "base": base_score,
                "S": round(r.s, 4),
                "C": round(r.c, 4),
                "R": round(r.risk, 4),
                "severity": r.severity,
            })

    out = EXPERIMENTS / "e1_factor_coverage.csv"
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"  → {out.name}  ({len(rows)} rows)")


# ---------------------------------------------------------------------------
# E2 — real images × scenarios
# ---------------------------------------------------------------------------

def _rank_cves(vulns: list[Vulnerability], image: str, sid: str, hint: bool,
               obs: dict | None, weights: dict, c_min: float, c_max: float):
    """Score every CVE in `vulns` against scenario `sid`. Return list of dicts."""
    fname = dict((s, f) for (s, f, _) in SCENARIOS)[sid]
    pod, svcs, ings = load_scenario(fname)
    xe = exposure_level(pod, svcs, ings, public_hint=hint)
    xp = privilege_level(pod)
    xm = mount_sensitivity(pod)

    out = []
    for v in vulns:
        x_run = runtime_reachability(v.package, None, obs)
        r = score(
            base=v.cvss_base,
            factors=Factors(exp=xe, run=x_run, priv=xp, mnt=xm),
            weights=weights, c_min=c_min, c_max=c_max,
        )
        out.append({
            "image": image, "scenario": sid,
            "cve": v.cve, "package": v.package,
            "version": v.installed_version,
            "base": round(v.cvss_base, 2),
            "cvss_source": v.cvss_source,
            "x_exp": round(xe, 2), "x_priv": round(xp, 2),
            "x_mnt": round(xm, 2), "x_run": round(x_run, 2),
            "S": round(r.s, 4), "C": round(r.c, 4),
            "R": round(r.risk, 4), "severity": r.severity,
        })
    out.sort(key=lambda d: d["R"], reverse=True)
    for i, d in enumerate(out, 1):
        d["rank_R"] = i
    out.sort(key=lambda d: d["base"], reverse=True)
    for i, d in enumerate(out, 1):
        d["rank_B"] = i
    return out


def e2_real_images(cache: Path) -> dict:
    """Score every CVE found in every image against every scenario."""
    rows = []
    per_pair = {}
    for image in IMAGES:
        vulns = scan_image(image, cache_dir=cache)
        for sid, _, hint in SCENARIOS:
            scored = _rank_cves(
                vulns, image, sid, hint, obs=None,
                weights=DEFAULT_WEIGHTS,
                c_min=DEFAULT_C_MIN, c_max=DEFAULT_C_MAX,
            )
            rows.extend(scored)
            per_pair[(image, sid)] = scored

    out = EXPERIMENTS / "e2_real_images.csv"
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"  → {out.name}  ({len(rows)} rows across {len(IMAGES)} images × {len(SCENARIOS)} scenarios)")
    return per_pair


# ---------------------------------------------------------------------------
# E3 — runtime ablation
# ---------------------------------------------------------------------------

def e3_runtime_ablation(cache: Path) -> None:
    """For each image, compare scoring with x_run=0 (never loaded) vs
    x_run=0.5 (inconclusive default) vs x_run=1 (observed). We do this in
    aggregate, simulating three population-level runtime regimes."""
    rows = []
    for image in IMAGES:
        vulns = scan_image(image, cache_dir=cache)
        for sid, _, hint in SCENARIOS:
            fname = dict((s, f) for (s, f, _) in SCENARIOS)[sid]
            pod, svcs, ings = load_scenario(fname)
            xe = exposure_level(pod, svcs, ings, public_hint=hint)
            xp = privilege_level(pod)
            xm = mount_sensitivity(pod)
            for state_label, x_run in (("never", 0.0), ("inconclusive", 0.5), ("observed", 1.0)):
                rs = []
                for v in vulns:
                    r = score(base=v.cvss_base,
                              factors=Factors(exp=xe, run=x_run, priv=xp, mnt=xm))
                    rs.append(r.risk)
                rows.append({
                    "image": image, "scenario": sid,
                    "x_run_state": state_label,
                    "x_run": x_run,
                    "n_cves": len(rs),
                    "R_mean": round(mean(rs), 3),
                    "R_stdev": round(stdev(rs), 3) if len(rs) > 1 else 0.0,
                    "R_max": round(max(rs), 3),
                    "R_min": round(min(rs), 3),
                    "n_critical": sum(1 for x in rs if x >= 9.0),
                    "n_high": sum(1 for x in rs if 7.0 <= x < 9.0),
                    "n_medium": sum(1 for x in rs if 4.0 <= x < 7.0),
                    "n_low_or_none": sum(1 for x in rs if x < 4.0),
                })

    out = EXPERIMENTS / "e3_runtime_ablation.csv"
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"  → {out.name}  ({len(rows)} rows)")


# ---------------------------------------------------------------------------
# E4 — Spearman / Kendall correlation with baseline (CVSS Base) ranking
# ---------------------------------------------------------------------------

def _spearman(rank_a: list[int], rank_b: list[int]) -> float:
    """Spearman rank correlation. Plain numpy-free impl."""
    n = len(rank_a)
    if n < 2:
        return float("nan")
    # average ranks
    def _avg_rank(xs):
        sorted_xs = sorted(range(n), key=lambda i: xs[i], reverse=True)
        ranks = [0.0] * n
        i = 0
        while i < n:
            j = i
            while j + 1 < n and xs[sorted_xs[j + 1]] == xs[sorted_xs[i]]:
                j += 1
            avg = (i + j) / 2 + 1
            for k in range(i, j + 1):
                ranks[sorted_xs[k]] = avg
            i = j + 1
        return ranks
    ra = _avg_rank(rank_a)
    rb = _avg_rank(rank_b)
    mean_a = sum(ra) / n
    mean_b = sum(rb) / n
    num = sum((ra[i] - mean_a) * (rb[i] - mean_b) for i in range(n))
    den_a = (sum((x - mean_a) ** 2 for x in ra)) ** 0.5
    den_b = (sum((x - mean_b) ** 2 for x in rb)) ** 0.5
    if den_a == 0 or den_b == 0:
        return float("nan")
    return num / (den_a * den_b)


def _kendall_tau(xs: list[float], ys: list[float]) -> float:
    """Kendall's tau-b correlation (handles ties).
    Sufficient for small n; O(n^2)."""
    n = len(xs)
    if n < 2:
        return float("nan")
    concordant = discordant = ties_x = ties_y = 0
    for i in range(n):
        for j in range(i + 1, n):
            dx = xs[i] - xs[j]
            dy = ys[i] - ys[j]
            if dx == 0 and dy == 0:
                continue
            if dx == 0:
                ties_x += 1; continue
            if dy == 0:
                ties_y += 1; continue
            if (dx > 0 and dy > 0) or (dx < 0 and dy < 0):
                concordant += 1
            else:
                discordant += 1
    n0 = concordant + discordant + ties_x + ties_y
    if n0 == 0:
        return float("nan")
    denom = ((concordant + discordant + ties_x) * (concordant + discordant + ties_y)) ** 0.5
    if denom == 0:
        return float("nan")
    return (concordant - discordant) / denom


def e4_baseline_correlation(per_pair: dict) -> None:
    """For each (image × scenario), measure how much the new ranking
    differs from the CVSS-base ranking."""
    rows = []
    for (image, sid), scored in per_pair.items():
        b_values = [d["base"] for d in scored]
        r_values = [d["R"] for d in scored]
        rho = _spearman(b_values, r_values)
        tau = _kendall_tau(b_values, r_values)
        # Top-K agreement (Jaccard) over rank-by-B vs rank-by-R sets
        scored_by_R = sorted(scored, key=lambda d: d["R"], reverse=True)
        scored_by_B = sorted(scored, key=lambda d: d["base"], reverse=True)
        def jacc(k):
            sR = {d["cve"] + ":" + d["package"] for d in scored_by_R[:k]}
            sB = {d["cve"] + ":" + d["package"] for d in scored_by_B[:k]}
            u = sR | sB
            return len(sR & sB) / len(u) if u else float("nan")
        rows.append({
            "image": image, "scenario": sid,
            "n_cves": len(scored),
            "spearman_rho_R_vs_B": round(rho, 4) if rho == rho else None,
            "kendall_tau_R_vs_B":  round(tau, 4) if tau == tau else None,
            "top5_jaccard":  round(jacc(5),  4),
            "top10_jaccard": round(jacc(10), 4),
        })
    out = EXPERIMENTS / "e4_baseline_correlation.csv"
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"  → {out.name}  ({len(rows)} rows)")


# ---------------------------------------------------------------------------
# E6 — Real images × scenarios WITH synthetic runtime observation
# ---------------------------------------------------------------------------

def _synthesize_runtime_for_image(vulns: list[Vulnerability]) -> dict:
    """Generate a plausible runtime observation for an image.

    Strategy: take the distinct vulnerable package names sorted
    alphabetically; mark the first half as "loaded". This gives a
    deterministic but per-CVE-varying x_run signal (0.0 for non-loaded
    packages, 0.5 for loaded ones — no symbol-level info supplied), which
    is sufficient to demonstrate runtime-driven rank changes without
    fabricating symbol-level observations.
    """
    distinct = sorted({v.package for v in vulns})
    half = len(distinct) // 2
    loaded = distinct[:half]
    return {
        "loaded_packages": loaded,
        "observed_symbols": [],
        "_note": "synthetic — alphabetical first-half of distinct packages",
    }


def e6_real_images_with_runtime(cache: Path) -> dict:
    """Same shape as E2 but with a per-image synthetic runtime observation."""
    rows = []
    per_pair = {}
    for image in IMAGES:
        vulns = scan_image(image, cache_dir=cache)
        obs = _synthesize_runtime_for_image(vulns)
        for sid, _, hint in SCENARIOS:
            scored = _rank_cves(
                vulns, image, sid, hint, obs=obs,
                weights=DEFAULT_WEIGHTS,
                c_min=DEFAULT_C_MIN, c_max=DEFAULT_C_MAX,
            )
            rows.extend(scored)
            per_pair[(image, sid)] = scored

    out = EXPERIMENTS / "e6_real_images_with_runtime.csv"
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"  → {out.name}  ({len(rows)} rows; runtime obs covers half of distinct packages per image)")
    return per_pair


def e7_correlation_with_runtime(per_pair: dict) -> None:
    """E4 redone on the runtime-aware rankings from E6."""
    rows = []
    for (image, sid), scored in per_pair.items():
        b_values = [d["base"] for d in scored]
        r_values = [d["R"] for d in scored]
        rho = _spearman(b_values, r_values)
        tau = _kendall_tau(b_values, r_values)
        scored_by_R = sorted(scored, key=lambda d: d["R"], reverse=True)
        scored_by_B = sorted(scored, key=lambda d: d["base"], reverse=True)
        def jacc(k):
            sR = {d["cve"] + ":" + d["package"] for d in scored_by_R[:k]}
            sB = {d["cve"] + ":" + d["package"] for d in scored_by_B[:k]}
            u = sR | sB
            return len(sR & sB) / len(u) if u else float("nan")
        # Count how many CVEs had x_run > 0 (i.e. package on loaded list)
        n_loaded = sum(1 for d in scored if d["x_run"] > 0)
        rows.append({
            "image": image, "scenario": sid,
            "n_cves": len(scored),
            "n_cves_loaded": n_loaded,
            "spearman_rho_R_vs_B": round(rho, 4) if rho == rho else None,
            "kendall_tau_R_vs_B":  round(tau, 4) if tau == tau else None,
            "top5_jaccard":  round(jacc(5),  4),
            "top10_jaccard": round(jacc(10), 4),
        })
    out = EXPERIMENTS / "e7_correlation_with_runtime.csv"
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"  → {out.name}  ({len(rows)} rows)")


# ---------------------------------------------------------------------------
# E5 — weight sensitivity (±20%)
# ---------------------------------------------------------------------------

def e5_weight_sensitivity(cache: Path) -> None:
    """For one fixed image (rabbitmq), measure how top-10 ranking stability
    changes when each weight is perturbed ±20% (re-normalised to Σ=1).
    Uses the synthetic runtime observation from E6 so that x_run varies per
    CVE — without it, weights do not change the ranking (the multiplier is
    uniform across CVEs of the same workload)."""
    image = IMAGES[0]
    vulns = scan_image(image, cache_dir=cache)
    obs = _synthesize_runtime_for_image(vulns)
    rows = []
    base_w = DEFAULT_WEIGHTS

    # baseline ranking (default weights, with runtime obs) for each scenario
    base_top10 = {}
    for sid, _, hint in SCENARIOS:
        scored = _rank_cves(vulns, image, sid, hint, obs=obs,
                            weights=base_w, c_min=DEFAULT_C_MIN, c_max=DEFAULT_C_MAX)
        scored.sort(key=lambda d: d["R"], reverse=True)
        base_top10[sid] = {d["cve"] + ":" + d["package"] for d in scored[:10]}

    perturbations = []
    for axis in ("exp", "run", "priv", "mnt"):
        for delta in (-0.2, +0.2):
            new = dict(base_w)
            new[axis] = base_w[axis] * (1 + delta)
            # Re-normalise to sum to 1
            total = sum(new.values())
            new = {k: v / total for k, v in new.items()}
            perturbations.append((axis, delta, new))

    for axis, delta, w in perturbations:
        for sid, _, hint in SCENARIOS:
            scored = _rank_cves(vulns, image, sid, hint, obs=obs,
                                weights=w, c_min=DEFAULT_C_MIN, c_max=DEFAULT_C_MAX)
            scored.sort(key=lambda d: d["R"], reverse=True)
            new_top10 = {d["cve"] + ":" + d["package"] for d in scored[:10]}
            jacc = len(base_top10[sid] & new_top10) / len(base_top10[sid] | new_top10)
            rows.append({
                "image": image, "scenario": sid,
                "perturbed_weight": axis,
                "delta_pct": int(delta * 100),
                "w_exp":  round(w["exp"],  3),
                "w_run":  round(w["run"],  3),
                "w_priv": round(w["priv"], 3),
                "w_mnt":  round(w["mnt"],  3),
                "top10_jaccard_vs_default": round(jacc, 4),
            })
    out = EXPERIMENTS / "e5_weight_sensitivity.csv"
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"  → {out.name}  ({len(rows)} rows)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache", type=Path,
                        default=PROTO / "experiments" / "trivy-cache",
                        help="Directory for Trivy JSON caches.")
    parser.add_argument("--skip-scan", action="store_true",
                        help="Refuse to scan; use cached JSON only.")
    args = parser.parse_args()

    print("E1 — Factor-space coverage")
    e1_factor_coverage()
    print()
    print("E2 — Real images × scenarios")
    per_pair = e2_real_images(cache=args.cache)
    print()
    print("E3 — Runtime ablation")
    e3_runtime_ablation(cache=args.cache)
    print()
    print("E4 — Baseline correlation")
    e4_baseline_correlation(per_pair)
    print()
    print("E6 — Real images × scenarios WITH synthetic runtime observation")
    per_pair_rt = e6_real_images_with_runtime(cache=args.cache)
    print()
    print("E7 — Baseline correlation under runtime-aware scoring")
    e7_correlation_with_runtime(per_pair_rt)
    print()
    print("E5 — Weight sensitivity (±20%)")
    e5_weight_sensitivity(cache=args.cache)
    print()
    print("Done. CSV artefacts in", EXPERIMENTS)


if __name__ == "__main__":
    main()

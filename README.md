# ctxrisk — context-sensitive container risk scoring (prototype)

Reference implementation of the method specified in
[`../method/Context-Sensitive Risk Score.md`](../method/Context-Sensitive%20Risk%20Score.md).

Reads a Kubernetes workload manifest and a vulnerability scan, computes the
context-sensitive risk score `R = clamp(B · C, 0, 10)` for each CVE, and prints
a re-ranked list compared with raw CVSS Base.

> Purpose: validate the method on real workloads, generate numbers for the
> evaluation chapter, and provide the live demo for the defense.

## Status

| Component | State |
|---|---|
| Factor extractors (`x_exp`, `x_priv`, `x_mnt`) from K8s YAML | scaffolded |
| Scoring engine (`S`, `C`, `R`) | scaffolded |
| Trivy integration | planned |
| Runtime reachability (`x_run`) from Falco JSON | planned |
| CLI | planned |

## Layout

```
prototype/
├── pyproject.toml
├── README.md
├── src/ctxrisk/
│   ├── __init__.py
│   ├── factors.py       # x_exp, x_priv, x_mnt, x_run extractors
│   ├── score.py         # S, C, R calculations
│   ├── scan.py          # Trivy invocation + JSON parser (TODO)
│   └── cli.py           # `ctxrisk` command (TODO)
├── tests/               # pytest — unit tests pinned to the formalisation
└── examples/            # K8s manifests for demo scenarios
```

## Run

```bash
cd prototype
pip install -e .
pytest                                    # unit tests
ctxrisk score examples/scenario-a.yaml    # (planned)
```

## Why macOS-friendly

Falco/eBPF require a Linux kernel and don't run natively on macOS. Runtime
reachability (`x_run`) is therefore fed from a JSON file of observation events.
For the demo, that file is recorded ahead of time on a Linux machine (or hand-
authored for controlled scenarios). The method itself is platform-agnostic; the
JSON shape mirrors what a Falco/eBPF collector would emit.

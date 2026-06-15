"""Extract the four context factors x_exp, x_priv, x_mnt, x_run from K8s data.

The ordinal level tables here mirror exactly the tables in
``method/Context-Sensitive Risk Score.md`` §2.2. Every change to those tables
must be reflected here, and every change here must be reflected there.

All extractors are pure functions taking parsed dictionaries (already loaded
from YAML/JSON) and returning a float in [0.0, 1.0].
"""

from __future__ import annotations

from typing import Iterable

# Capabilities considered dangerous when explicitly added to a container
# (subset commonly flagged by CIS / Falco / k8s pod-security defaults).
DANGEROUS_CAPS = frozenset({
    "SYS_ADMIN",
    "SYS_PTRACE",
    "SYS_MODULE",
    "NET_ADMIN",
    "NET_RAW",
    "DAC_OVERRIDE",
    "DAC_READ_SEARCH",
    "SETUID",
    "SETGID",
})

# Host paths that, if mounted, give the container effective control of the host
HOST_TAKEOVER_PATHS = frozenset({
    "/",
    "/var/run/docker.sock",
    "/var/run/containerd.sock",
    "/proc",
    "/etc",
    "/root",
    "/var/lib/kubelet",
})


# ---------------------------------------------------------------------------
# x_exp — exposure
# ---------------------------------------------------------------------------

def exposure_level(pod: dict, services: Iterable[dict] = (),
                   ingresses: Iterable[dict] = (),
                   public_hint: bool = False) -> float:
    """Compute x_exp ∈ [0, 1] for the workload represented by ``pod``.

    Levels (matches §2.2):
        0.00  no listening service / not reachable
        0.25  cluster-internal only (ClusterIP, no Ingress)
        0.50  reachable across trusted network / other namespaces (NodePort)
        0.75  exposed via Ingress / LoadBalancer to the internal org network
        1.00  exposed to the public Internet
    """
    pod_labels = (pod.get("metadata", {}) or {}).get("labels", {}) or {}
    matched_services = [s for s in services if _service_matches(s, pod_labels)]
    if not matched_services:
        return 0.0

    # Any Ingress referencing one of the matched Services?
    matched_service_names = {(s.get("metadata", {}) or {}).get("name") for s in matched_services}
    has_ingress = any(_ingress_references(i, matched_service_names) for i in ingresses)

    # Public hint (e.g. cloud-LB annotation) tops everything
    if public_hint:
        return 1.0

    types = {s.get("spec", {}).get("type", "ClusterIP") for s in matched_services}
    if "LoadBalancer" in types or has_ingress:
        return 0.75
    if "NodePort" in types:
        return 0.5
    # Only ClusterIP, no Ingress
    return 0.25


def _service_matches(svc: dict, pod_labels: dict) -> bool:
    selector = (svc.get("spec", {}) or {}).get("selector") or {}
    if not selector:
        return False
    return all(pod_labels.get(k) == v for k, v in selector.items())


def _ingress_references(ing: dict, service_names: set) -> bool:
    rules = (ing.get("spec", {}) or {}).get("rules", []) or []
    for rule in rules:
        http = (rule or {}).get("http", {}) or {}
        for path in http.get("paths", []) or []:
            backend = (path or {}).get("backend", {}) or {}
            svc = backend.get("service", {}) or {}
            if svc.get("name") in service_names:
                return True
            # legacy v1beta1 shape
            if backend.get("serviceName") in service_names:
                return True
    return False


# ---------------------------------------------------------------------------
# x_priv — privilege level
# ---------------------------------------------------------------------------

def privilege_level(pod: dict) -> float:
    """Compute x_priv ∈ [0, 1] for the pod (max severity across containers).

    Levels (matches §2.2):
        0.00  non-root + read-only rootfs + drop ALL + no privilege escalation
        0.25  non-root, default capabilities
        0.50  root inside container, default capabilities         ← K8s default
        0.75  added dangerous capabilities
        1.00  privileged: true
    """
    spec = pod.get("spec", {}) or {}
    pod_sc = spec.get("securityContext", {}) or {}
    containers = (spec.get("containers", []) or []) + (spec.get("initContainers", []) or [])
    if not containers:
        return 0.5  # pessimistic default
    return max(_container_privilege(c, pod_sc) for c in containers)


def _container_privilege(container: dict, pod_sc: dict) -> float:
    sc = container.get("securityContext", {}) or {}

    # Effective values: container-level wins, falls back to pod-level
    privileged = sc.get("privileged", pod_sc.get("privileged", False))
    run_as_non_root = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
    run_as_user = sc.get("runAsUser", pod_sc.get("runAsUser"))
    allow_priv_esc = sc.get("allowPrivilegeEscalation", True)
    read_only_root = sc.get("readOnlyRootFilesystem", False)
    caps = sc.get("capabilities", {}) or {}
    added = {c.upper() for c in (caps.get("add") or [])}
    dropped = {c.upper() for c in (caps.get("drop") or [])}

    if privileged:
        return 1.0
    if added & DANGEROUS_CAPS:
        return 0.75

    effectively_non_root = (
        run_as_non_root is True
        or (isinstance(run_as_user, int) and run_as_user != 0)
    )
    if not effectively_non_root:
        return 0.5

    hardened = (
        read_only_root
        and ("ALL" in dropped)
        and allow_priv_esc is False
    )
    return 0.0 if hardened else 0.25


# ---------------------------------------------------------------------------
# x_mnt — sensitive mounts
# ---------------------------------------------------------------------------

def mount_sensitivity(pod: dict) -> float:
    """Compute x_mnt ∈ [0, 1] for the pod (max severity across volumes).

    Levels (matches §2.2):
        0.00  no host mounts, no secret mounts
        0.25  mounted secrets only (ordinary)
        0.50  hostPath, read-only
        0.75  hostPath, read-write
        1.00  Docker socket / host root / host /proc mounted
    """
    spec = pod.get("spec", {}) or {}
    volumes = spec.get("volumes", []) or []
    if not volumes:
        return 0.0

    # Build a map name -> "read_only" for the host path volumes from container mounts
    read_only_by_volume: dict[str, bool] = {}
    for c in (spec.get("containers", []) or []) + (spec.get("initContainers", []) or []):
        for vm in c.get("volumeMounts", []) or []:
            name = vm.get("name")
            if name is None:
                continue
            # If any container mounts the volume RW, treat as RW
            mounted_ro = bool(vm.get("readOnly", False))
            if name in read_only_by_volume:
                read_only_by_volume[name] = read_only_by_volume[name] and mounted_ro
            else:
                read_only_by_volume[name] = mounted_ro

    score = 0.0
    for v in volumes:
        score = max(score, _volume_severity(v, read_only_by_volume))
    return score


def _volume_severity(volume: dict, read_only_by_name: dict[str, bool]) -> float:
    name = volume.get("name")
    if "hostPath" in volume:
        path = ((volume.get("hostPath") or {}).get("path") or "").rstrip("/") or "/"
        if path in HOST_TAKEOVER_PATHS or any(path.startswith(p + "/") for p in HOST_TAKEOVER_PATHS if p != "/"):
            return 1.0
        return 0.5 if read_only_by_name.get(name, False) else 0.75
    if "secret" in volume:
        return 0.25
    # configMap, emptyDir, persistentVolumeClaim, projected, downwardAPI, ...
    return 0.0


# ---------------------------------------------------------------------------
# x_run — runtime reachability
# ---------------------------------------------------------------------------

def runtime_reachability(vulnerable_package: str,
                         vulnerable_symbol: str | None,
                         observation: dict | None) -> float:
    """Compute x_run ∈ [0, 1] from a runtime observation record.

    Observation shape (mirrors what a Falco/eBPF collector would emit)::

        {
          "workload": "<deploy/name or pod/name>",
          "observation_window_days": 7,
          "loaded_packages": ["openssl", "libxml2", ...],
          "observed_symbols": ["openssl.RAND_bytes", ...]
        }

    Levels (matches §2.2):
        0.00  package present, never observed loaded
        0.25  package loaded but vulnerable symbol never observed
        0.50  observation inconclusive — DEFAULT when telemetry is missing
        0.75  package loaded and likely-vulnerable code path observed
        1.00  vulnerable symbol directly observed executing
    """
    # No observation → graceful fallback (formalisation §2.2, §4 "graceful fallback")
    if observation is None:
        return 0.5
    loaded = {p.lower() for p in (observation.get("loaded_packages") or [])}
    observed_symbols = {s.lower() for s in (observation.get("observed_symbols") or [])}

    pkg = (vulnerable_package or "").lower()
    if pkg and pkg not in loaded:
        return 0.0

    sym = (vulnerable_symbol or "").lower()
    if not sym:
        # Package loaded but we have no symbol info to be more specific
        return 0.5
    # Match either the fully-qualified observed symbol, or any observed symbol
    # whose suffix equals ".<sym>" — vulnerability databases often record only
    # the function name, while Falco/eBPF emits "<package>.<function>".
    suffix = "." + sym
    if any(o == sym or o.endswith(suffix) for o in observed_symbols):
        return 1.0
    # Symbol-level info available but our specific symbol not seen — partial signal
    return 0.25

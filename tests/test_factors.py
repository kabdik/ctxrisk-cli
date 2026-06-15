"""Pin factor extractors to the level tables in
``method/Context-Sensitive Risk Score.md`` §2.2.
"""

import pytest

from ctxrisk.factors import (
    exposure_level,
    privilege_level,
    mount_sensitivity,
    runtime_reachability,
)


# ----------------------------------------------------------------------------
# x_exp — Exposure
# ----------------------------------------------------------------------------

def _pod_with_labels(**labels):
    return {"metadata": {"labels": labels}, "spec": {"containers": [{"name": "c"}]}}


def _svc(name, selector, type_="ClusterIP"):
    return {"metadata": {"name": name}, "spec": {"type": type_, "selector": selector}}


def _ingress(svc_name):
    return {"spec": {"rules": [{"http": {"paths": [
        {"backend": {"service": {"name": svc_name}}}
    ]}}]}}


def test_x_exp_no_service_is_zero():
    pod = _pod_with_labels(app="api")
    assert exposure_level(pod, services=[], ingresses=[]) == 0.0


def test_x_exp_clusterip_no_ingress_is_025():
    pod = _pod_with_labels(app="api")
    svc = _svc("api", {"app": "api"}, type_="ClusterIP")
    assert exposure_level(pod, services=[svc], ingresses=[]) == 0.25


def test_x_exp_nodeport_no_ingress_is_05():
    pod = _pod_with_labels(app="api")
    svc = _svc("api", {"app": "api"}, type_="NodePort")
    assert exposure_level(pod, services=[svc], ingresses=[]) == 0.5


def test_x_exp_loadbalancer_is_075():
    pod = _pod_with_labels(app="api")
    svc = _svc("api", {"app": "api"}, type_="LoadBalancer")
    assert exposure_level(pod, services=[svc], ingresses=[]) == 0.75


def test_x_exp_ingress_on_clusterip_is_075():
    pod = _pod_with_labels(app="api")
    svc = _svc("api", {"app": "api"}, type_="ClusterIP")
    ing = _ingress("api")
    assert exposure_level(pod, services=[svc], ingresses=[ing]) == 0.75


def test_x_exp_public_hint_is_10():
    pod = _pod_with_labels(app="api")
    svc = _svc("api", {"app": "api"}, type_="LoadBalancer")
    assert exposure_level(pod, services=[svc], ingresses=[], public_hint=True) == 1.0


# ----------------------------------------------------------------------------
# x_priv — Privilege
# ----------------------------------------------------------------------------

def _pod_with_security(securityContext=None, container_sc=None):
    spec = {"containers": [{"name": "c", "securityContext": container_sc or {}}]}
    if securityContext is not None:
        spec["securityContext"] = securityContext
    return {"spec": spec}


def test_x_priv_no_securitycontext_is_05():
    """K8s default = root with default caps."""
    pod = {"spec": {"containers": [{"name": "c"}]}}
    assert privilege_level(pod) == 0.5


def test_x_priv_privileged_true_is_10():
    pod = _pod_with_security(container_sc={"privileged": True})
    assert privilege_level(pod) == 1.0


def test_x_priv_dangerous_cap_is_075():
    pod = _pod_with_security(container_sc={
        "runAsNonRoot": True,
        "capabilities": {"add": ["SYS_ADMIN"]},
    })
    assert privilege_level(pod) == 0.75


def test_x_priv_non_root_default_caps_is_025():
    pod = _pod_with_security(container_sc={"runAsNonRoot": True})
    assert privilege_level(pod) == 0.25


def test_x_priv_fully_hardened_is_00():
    pod = _pod_with_security(container_sc={
        "runAsNonRoot": True,
        "readOnlyRootFilesystem": True,
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
    })
    assert privilege_level(pod) == 0.0


def test_x_priv_takes_max_across_containers():
    pod = {"spec": {"containers": [
        {"name": "a", "securityContext": {"runAsNonRoot": True}},  # 0.25
        {"name": "b", "securityContext": {"privileged": True}},    # 1.00
    ]}}
    assert privilege_level(pod) == 1.0


def test_x_priv_pod_level_inherited():
    pod = _pod_with_security(securityContext={"runAsNonRoot": True})
    # Container has no securityContext but inherits non-root from pod
    assert privilege_level(pod) == 0.25


# ----------------------------------------------------------------------------
# x_mnt — Sensitive mounts
# ----------------------------------------------------------------------------

def _pod_with_volume(volume, vm=None):
    container = {"name": "c"}
    if vm:
        container["volumeMounts"] = [vm]
    return {"spec": {"containers": [container], "volumes": [volume]}}


def test_x_mnt_no_volumes_is_00():
    pod = {"spec": {"containers": [{"name": "c"}]}}
    assert mount_sensitivity(pod) == 0.0


def test_x_mnt_emptydir_only_is_00():
    pod = _pod_with_volume({"name": "tmp", "emptyDir": {}})
    assert mount_sensitivity(pod) == 0.0


def test_x_mnt_secret_only_is_025():
    pod = _pod_with_volume({"name": "creds", "secret": {"secretName": "db-pw"}})
    assert mount_sensitivity(pod) == 0.25


def test_x_mnt_hostpath_readonly_is_05():
    pod = _pod_with_volume(
        {"name": "data", "hostPath": {"path": "/var/data"}},
        vm={"name": "data", "mountPath": "/data", "readOnly": True},
    )
    assert mount_sensitivity(pod) == 0.5


def test_x_mnt_hostpath_readwrite_is_075():
    pod = _pod_with_volume(
        {"name": "data", "hostPath": {"path": "/var/data"}},
        vm={"name": "data", "mountPath": "/data"},
    )
    assert mount_sensitivity(pod) == 0.75


def test_x_mnt_docker_socket_is_10():
    pod = _pod_with_volume(
        {"name": "sock", "hostPath": {"path": "/var/run/docker.sock"}},
        vm={"name": "sock", "mountPath": "/var/run/docker.sock"},
    )
    assert mount_sensitivity(pod) == 1.0


def test_x_mnt_host_root_is_10():
    pod = _pod_with_volume(
        {"name": "rootfs", "hostPath": {"path": "/"}},
        vm={"name": "rootfs", "mountPath": "/host"},
    )
    assert mount_sensitivity(pod) == 1.0


# ----------------------------------------------------------------------------
# x_run — Runtime reachability
# ----------------------------------------------------------------------------

def test_x_run_no_observation_falls_back_to_05():
    """Graceful fallback per method §2.2, §4."""
    assert runtime_reachability("openssl", "RAND_bytes", observation=None) == 0.5


def test_x_run_package_never_observed_is_00():
    obs = {"loaded_packages": ["nginx"], "observed_symbols": []}
    assert runtime_reachability("openssl", "RAND_bytes", obs) == 0.0


def test_x_run_package_loaded_no_symbol_info_is_05():
    obs = {"loaded_packages": ["openssl"], "observed_symbols": []}
    assert runtime_reachability("openssl", None, obs) == 0.5


def test_x_run_package_loaded_other_symbols_is_025():
    obs = {"loaded_packages": ["openssl"], "observed_symbols": ["openssl.SHA256"]}
    assert runtime_reachability("openssl", "RAND_bytes", obs) == 0.25


def test_x_run_specific_symbol_observed_is_10():
    obs = {"loaded_packages": ["openssl"], "observed_symbols": ["openssl.RAND_bytes"]}
    assert runtime_reachability("openssl", "RAND_bytes", obs) == 1.0

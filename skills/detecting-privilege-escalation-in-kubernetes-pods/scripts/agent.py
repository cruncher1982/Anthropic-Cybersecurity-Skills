#!/usr/bin/env python3
"""
Kubernetes Pod Privilege Escalation Detection Agent
Audits Kubernetes pods for privilege escalation risks including privileged
containers, host namespace access, and dangerous capabilities.
Authorized security monitoring use only.
"""

import argparse
import json
import sys
from datetime import datetime, timezone

from kubernetes import client, config


DANGEROUS_CAPABILITIES = [
    "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "NET_RAW",
    "DAC_OVERRIDE", "SETUID", "SETGID", "SYS_RAWIO",
]


def load_k8s_config(kubeconfig=None, in_cluster=False):
    """Load Kubernetes configuration."""
    if in_cluster:
        config.load_incluster_config()
    else:
        config.load_kube_config(config_file=kubeconfig)


def audit_pod_security(namespace=None):
    """Audit pods for privilege escalation vectors."""
    v1 = client.CoreV1Api()
    if namespace:
        pods = v1.list_namespaced_pod(namespace)
    else:
        pods = v1.list_pod_for_all_namespaces()

    findings = []
    for pod in pods.items:
        pod_name = pod.metadata.name
        pod_ns = pod.metadata.namespace
        for container in (pod.spec.containers or []):
            sc = container.security_context
            if not sc:
                findings.append({
                    "pod": pod_name, "namespace": pod_ns,
                    "container": container.name,
                    "issue": "no_security_context",
                    "severity": "medium",
                    "detail": "Container has no security context defined",
                })
                continue
            if sc.privileged:
                findings.append({
                    "pod": pod_name, "namespace": pod_ns,
                    "container": container.name,
                    "issue": "privileged_container",
                    "severity": "critical",
                    "detail": "Container runs in privileged mode",
                })
            if sc.allow_privilege_escalation is not False:
                findings.append({
                    "pod": pod_name, "namespace": pod_ns,
                    "container": container.name,
                    "issue": "allow_privilege_escalation",
                    "severity": "high",
                    "detail": "allowPrivilegeEscalation is not explicitly set to false",
                })
            if sc.run_as_user == 0 or (sc.run_as_non_root is not True and not sc.run_as_user):
                findings.append({
                    "pod": pod_name, "namespace": pod_ns,
                    "container": container.name,
                    "issue": "runs_as_root",
                    "severity": "high",
                    "detail": "Container may run as root",
                })
            if sc.capabilities and sc.capabilities.add:
                dangerous = [c for c in sc.capabilities.add if c in DANGEROUS_CAPABILITIES]
                if dangerous:
                    findings.append({
                        "pod": pod_name, "namespace": pod_ns,
                        "container": container.name,
                        "issue": "dangerous_capabilities",
                        "severity": "high",
                        "detail": f"Dangerous capabilities: {dangerous}",
                    })
        spec = pod.spec
        if spec.host_pid:
            findings.append({
                "pod": pod_name, "namespace": pod_ns,
                "issue": "host_pid_namespace", "severity": "critical",
                "detail": "Pod shares host PID namespace",
            })
        if spec.host_network:
            findings.append({
                "pod": pod_name, "namespace": pod_ns,
                "issue": "host_network", "severity": "high",
                "detail": "Pod shares host network namespace",
            })
        if spec.host_ipc:
            findings.append({
                "pod": pod_name, "namespace": pod_ns,
                "issue": "host_ipc", "severity": "high",
                "detail": "Pod shares host IPC namespace",
            })
        for vol in (spec.volumes or []):
            if vol.host_path:
                findings.append({
                    "pod": pod_name, "namespace": pod_ns,
                    "issue": "host_path_volume",
                    "severity": "high",
                    "detail": f"hostPath volume: {vol.host_path.path}",
                })
    return findings


def audit_rbac_escalation(namespace=None):
    """Check RBAC for privilege escalation paths."""
    rbac = client.RbacAuthorizationV1Api()
    findings = []
    if namespace:
        bindings = rbac.list_namespaced_role_binding(namespace)
    else:
        bindings = rbac.list_cluster_role_binding()
    for binding in bindings.items:
        role_ref = binding.role_ref
        if role_ref.name in ("cluster-admin", "admin", "edit"):
            for subject in (binding.subjects or []):
                if subject.kind == "ServiceAccount":
                    findings.append({
                        "binding": binding.metadata.name,
                        "role": role_ref.name,
                        "subject": f"{subject.namespace}/{subject.name}",
                        "issue": "overprivileged_service_account",
                        "severity": "high",
                        "detail": f"ServiceAccount bound to {role_ref.name}",
                    })
    return findings


def generate_report(pod_findings, rbac_findings):
    """Generate Kubernetes privilege escalation report."""
    all_findings = pod_findings + rbac_findings
    return {
        "report_title": "Kubernetes Privilege Escalation Detection",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(all_findings),
        "critical": len([f for f in all_findings if f.get("severity") == "critical"]),
        "high": len([f for f in all_findings if f.get("severity") == "high"]),
        "pod_findings": pod_findings,
        "rbac_findings": rbac_findings,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect K8s pod privilege escalation")
    parser.add_argument("--namespace", "-n", help="Kubernetes namespace to audit")
    parser.add_argument("--kubeconfig", help="Path to kubeconfig file")
    parser.add_argument("--in-cluster", action="store_true", help="Use in-cluster config")
    parser.add_argument("--output", default="k8s_privesc_audit.json", help="Output file")
    args = parser.parse_args()

    load_k8s_config(args.kubeconfig, args.in_cluster)
    print("[*] Auditing pod security contexts...")
    pod_findings = audit_pod_security(args.namespace)
    print("[*] Auditing RBAC bindings...")
    rbac_findings = audit_rbac_escalation(args.namespace)

    report = generate_report(pod_findings, rbac_findings)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    print(json.dumps(report, indent=2))

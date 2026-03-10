# API Reference: Detecting Privilege Escalation in Kubernetes Pods

## Kubernetes Python Client API

| Method | Description |
|--------|-------------|
| `CoreV1Api().list_pod_for_all_namespaces()` | List all pods across namespaces |
| `CoreV1Api().list_namespaced_pod(namespace)` | List pods in a specific namespace |
| `RbacAuthorizationV1Api().list_cluster_role_binding()` | List all ClusterRoleBindings |
| `RbacAuthorizationV1Api().list_namespaced_role_binding(ns)` | List RoleBindings in namespace |

## Pod SecurityContext Fields

| Field | Risk |
|-------|------|
| `privileged: true` | Full host access, container escape |
| `allowPrivilegeEscalation: true` | Enables setuid/setgid binaries |
| `runAsUser: 0` | Container runs as root |
| `hostPID: true` | Access to host process namespace |
| `hostNetwork: true` | Access to host network stack |
| `capabilities.add: [SYS_ADMIN]` | Near-root capabilities |

## Key Libraries

- **kubernetes** (`pip install kubernetes`): Official Python client for Kubernetes API
- **config.load_kube_config()**: Load kubeconfig from file for external access
- **config.load_incluster_config()**: Load service account config when running inside a pod

## Configuration

| Variable | Description |
|----------|-------------|
| `DANGEROUS_CAPABILITIES` | Linux capabilities that enable privilege escalation |
| `kubeconfig` | Path to Kubernetes configuration file |

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [MITRE ATT&CK T1611 - Escape to Host](https://attack.mitre.org/techniques/T1611/)
- [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [kubernetes-client/python](https://github.com/kubernetes-client/python)

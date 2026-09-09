/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR)
 *
 * NATIVE-ACTUATOR LEAST-PRIVILEGE RBAC.
 *
 * The native actuator writes core/networking/discovery objects DIRECTLY — a materially
 * wider blast radius than the Phoenix-adapter path (which held only phorvex.ai CRD verbs).
 * CONTAINMENT (security review item): bind these verbs to a SEPARATE, NAMESPACED,
 * least-privilege Role (NOT a ClusterRole) per protected tenant namespace — a stolen
 * actuator token is then bounded to mutating protected workloads in granted namespaces:
 * NO secrets-read beyond bound SA tokens, NO node/cluster-admin. The decision SA keeps its
 * minimal phorvex.ai-only Role. The markers below are the exact, minimal verb set each
 * native handler uses (controller-gen emits the Role from them); they are intentionally
 * scoped per-resource to the verbs actually called — nothing broader.
 *
 * pods                          : rotate (get/delete), quarantine/identity/route/kv/endpoint (get/update), warm-swap (list/update/delete)
 * pods/ephemeralcontainers      : debugger / custom-inject / inject-carrier kv-reset (update)
 * networkpolicies               : quarantine deny-all + orphan GC (create/get/list/delete)
 * replicasets/statefulsets/daemonsets, jobs : quarantine reads the owning controller's selector to detach (get)
 * services                      : route-rotate / endpoint-rotate selector restitch (get/update);
 *                                 quarantine lists Services to break their selector keys when no
 *                                 owner selector is readable (list)
 *
 * Identity-rotate deliberately receives no ServiceAccount/Secret permission: projected tokens
 * cannot be revoked by a pod-scoped action. EndpointSlices also remain denied.
 */

package actuator

// +kubebuilder:rbac:namespace=phorvex-tenant,groups="",resources=pods,verbs=get;list;delete;update
// +kubebuilder:rbac:namespace=phorvex-tenant,groups="",resources=pods/ephemeralcontainers,verbs=update
// +kubebuilder:rbac:namespace=phorvex-tenant,groups=networking.k8s.io,resources=networkpolicies,verbs=create;get;list;delete
// +kubebuilder:rbac:namespace=phorvex-tenant,groups=apps,resources=replicasets;statefulsets;daemonsets;deployments,verbs=get
// +kubebuilder:rbac:namespace=phorvex-tenant,groups="",resources=replicationcontrollers,verbs=get
// +kubebuilder:rbac:namespace=phorvex-tenant,groups=batch,resources=jobs,verbs=get
// +kubebuilder:rbac:namespace=phorvex-tenant,groups="",resources=services,verbs=get;list;update

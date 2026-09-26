/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-ACTUATOR)
 *
 * NATIVE-ACTUATOR LEAST-PRIVILEGE RBAC.
 *
 * The native actuator writes core/networking objects DIRECTLY — a materially
 * wider blast radius than the Phoenix-adapter path (which held only phorvex.ai CRD verbs).
 * CONTAINMENT (security review item): bind these verbs to a SEPARATE, NAMESPACED,
 * least-privilege Role (NOT a ClusterRole) per protected tenant namespace — a stolen
 * actuator token is then bounded to mutating protected workloads in granted namespaces:
 * NO secrets-read beyond bound SA tokens, NO node/cluster-admin. The Helm profile currently binds routine roles to the manager SA. The raw manifest
 * uses a dedicated actuator SA. The markers below include native handlers and GC
 * (the generated union is an unbound review artifact); they are intentionally
 * scoped per-resource to the verbs actually called — nothing broader.
 *
 * pods                          : rotate (get/delete), quarantine/identity/route/kv/endpoint (get/update), warm-swap (list/update/delete)
 * pods/ephemeralcontainers      : debugger / fixed custom-inject marker profile (update)
 * networkpolicies               : quarantine create/reconcile + migration/cleanup (create/get/list/delete/update)
 * replicasets/statefulsets/daemonsets, jobs : quarantine reads the owning controller's selector to detach (get)
 * services                      : route-rotate / endpoint-rotate selector restitch (get/update);
 *                                 quarantine/request-drain inspect Services, scalar warm actions bind one (get/list)
 * endpointslices                : request-drain and scalar warm actions observe exact routes only (list)
 * configmaps                    : fixed Pod-bound output policy source activation (get/update)
 *
 * Identity-rotate deliberately receives no ServiceAccount/Secret permission: projected tokens
 * cannot be revoked by a pod-scoped action. EndpointSlice mutation remains denied.
 */

package actuator

// +kubebuilder:rbac:namespace=phorvex-tenant,groups="",resources=pods,verbs=get;list;delete;update;patch
// +kubebuilder:rbac:namespace=phorvex-tenant,groups="",resources=pods/eviction,verbs=create
// +kubebuilder:rbac:namespace=phorvex-tenant,groups="",resources=pods/ephemeralcontainers,verbs=update
// +kubebuilder:rbac:namespace=phorvex-tenant,groups=networking.k8s.io,resources=networkpolicies,verbs=create;get;list;delete;update
// +kubebuilder:rbac:namespace=phorvex-tenant,groups=apps,resources=replicasets;statefulsets;daemonsets;deployments,verbs=get
// +kubebuilder:rbac:namespace=phorvex-tenant,groups="",resources=replicationcontrollers,verbs=get
// +kubebuilder:rbac:namespace=phorvex-tenant,groups=batch,resources=jobs,verbs=get
// +kubebuilder:rbac:namespace=phorvex-tenant,groups="",resources=services,verbs=get;list;update
// +kubebuilder:rbac:namespace=phorvex-tenant,groups="",resources=configmaps,verbs=get;update
// +kubebuilder:rbac:namespace=phorvex-tenant,groups=discovery.k8s.io,resources=endpointslices,verbs=list

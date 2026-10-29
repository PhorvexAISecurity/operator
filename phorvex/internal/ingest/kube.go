/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package ingest

import (
	"context"
	appsv1 "k8s.io/api/apps/v1"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuationbrake"
	"github.com/phorvex/phorvex/internal/gpudevice"
	"github.com/phorvex/phorvex/internal/graph"
	"github.com/phorvex/phorvex/internal/identityfixture"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/ownership"
	"github.com/phorvex/phorvex/internal/servingcontext"
	"github.com/phorvex/phorvex/internal/statefulrotation"
)

func ownedMetadataValue(values map[string]string, key string) model.OwnedValue {
	value, present := values[key]
	return model.OwnedValue{Present: present, Value: value}
}

// Snapshot is one cluster-wide ingest pass shared by all tenants in a tick: the
// projected pods, the built blast-radius graph, namespace labels, and the
// SecurityEvent stream. Built once per tick (NFR1: <1s for <=1000 pods) so per-tenant
// processing is cheap.
type Snapshot struct {
	// M-34 observation substrate, separate from the numerical physics projection.
	NamespaceLabels      map[string]map[string]string
	Policies             []v1alpha1.PhorvexPolicy
	PodInventoryComplete bool
	// ServiceAccountInventoryComplete is separate from Pod inventory. A failed or
	// partial list leaves Pod-bound API-token capability witnesses absent.
	ServiceAccountInventoryComplete bool
	PolicyInventoryComplete         bool
	EventInventoryComplete          bool
	// PhoenixReceiptInventoryComplete is true only when the same cluster-wide
	// SecurityEvent list used for this snapshot succeeded. Receipts remain outside
	// detector belief even though they share the API list.
	PhoenixReceiptInventoryComplete bool
	Pods                            []model.Pod
	PodByKey                        map[string]*model.Pod
	Graph                           *graph.Graph
	Events                          []model.SecurityEventInfo
	EventByPod                      map[string][]model.SecurityEventInfo
	PhoenixReceipts                 map[string]model.PhoenixExecutionReceipt // keyed by event name; UID is rechecked by consumers
	// NamespaceDryRun records the normalized annotation observation for every
	// namespace, including malformed values which conservatively suppress work.
	NamespaceDryRun map[string]model.ActuationBrakeObservation
	Now             time.Time

	// --- P-PHYSICS (UCW) additive scan products: node capacity + live PodDisruptionBudgets,
	// the substrate the platform scanner turns into PhysicsWitness. ---
	Nodes []NodeInfo
	PDBs  []PDBInfo
	// PDBInventoryComplete distinguishes an observed empty PDB set from a list
	// failure. Replica-removing planning must never call the latter healthy.
	PDBInventoryAttempted bool
	PDBInventoryComplete  bool
	// Services are projected read-only so capability status can verify that request-drain's
	// target Service actually selects on phorvex.ai/serving.
	Services []ServiceInfo
	// ServiceAvailabilityComplete is true only when both the Service and
	// EndpointSlice inventories succeeded for this snapshot.
	ServiceAvailabilityComplete bool

	// GPUWitness is the live DCGM-via-Prometheus GPU half ("ns/pod" -> witness GPU fields:
	// GPUPresent + VRAMFraction/SMOccupancy/LinkBandwidth). Populated by PopulateGPUWitness when
	// a Prometheus/dcgm-exporter feed is configured; nil/empty is honest-absent and a GPU
	// platform adapter leaves those floats at 0.
	GPUWitness map[string]model.PhysicsWitness
}

// NodeInfo and ServiceInfo are the node and Service projections the sensor shares
// with the dispatcher; see model.NodeInfo and model.ServiceInfo.
type (
	NodeInfo    = model.NodeInfo
	ServiceInfo = model.ServiceInfo
)

// PDBInfo is a live PodDisruptionBudget projection (Layer-A availability law, replacing
// the static policy proxy as an ADDITIVE veto).
type PDBInfo struct {
	Namespace, Name, UID                                             string
	Generation, ObservedGeneration                                   int64
	Selector                                                         labels.Selector
	SelectorValid                                                    bool
	MinAvailable                                                     int
	MinAvailableText, MaxUnavailableText                             string
	DisruptionsAllowed, CurrentHealthy, DesiredHealthy, ExpectedPods int
}

// gpuPrefix marks NVIDIA device-plugin resources (GPU / MIG slices).
const gpuPrefix = "nvidia.com/"

// CollectSnapshot reads pods, Services, NetworkPolicies, RBAC, namespaces and SecurityEvents
// cluster-wide and projects them into a Snapshot. Read-only (least privilege).
func CollectSnapshot(ctx context.Context, c client.Client, now time.Time, assetValue func(p *model.Pod) float64, ownerReaders ...client.Reader) (*Snapshot, error) {
	var reader client.Reader
	if len(ownerReaders) > 0 {
		reader = ownerReaders[0]
	}
	return collectSnapshot(ctx, c, now, assetValue, reader, reader, nil)
}

// CollectSnapshotForRotationTargets limits owner API reads to this tick's protected
// targets while retaining the full Pod inventory for graph and availability inputs.
func CollectSnapshotForRotationTargets(ctx context.Context, c client.Client, now time.Time, assetValue func(*model.Pod) float64, reader client.Reader, relevant func(*corev1.Pod) bool) (*Snapshot, error) {
	return collectSnapshot(ctx, c, now, assetValue, reader, reader, relevant)
}

// CollectSnapshotForRotationTargetsWithReceiptReader keeps controller ownership
// reads and Phoenix execution receipt inventory independent. Phoenix does not need
// native owner eligibility reads, but its terminal SecurityEvent evidence must be
// read through the direct boundary reader so a deleted/recreated cached object
// cannot authorize learning.
func CollectSnapshotForRotationTargetsWithReceiptReader(ctx context.Context, c client.Client, now time.Time, assetValue func(*model.Pod) float64, ownerReader, receiptReader client.Reader, relevant func(*corev1.Pod) bool) (*Snapshot, error) {
	snap, err := collectSnapshot(ctx, c, now, assetValue, ownerReader, receiptReader, relevant)
	if err == nil && receiptReader == nil {
		// The normal cached event stream may still feed detector belief, but it is
		// insufficient to prove that a receipt object remains present now.
		snap.PhoenixReceiptInventoryComplete = false
		snap.PhoenixReceipts = map[string]model.PhoenixExecutionReceipt{}
	}
	return snap, err
}

func collectSnapshot(ctx context.Context, c client.Client, now time.Time, assetValue func(*model.Pod) float64, ownerBoundary, receiptBoundary client.Reader, relevant func(*corev1.Pod) bool) (*Snapshot, error) {
	ownerReader := newSnapshotOwnerReader(ownerBoundary)
	var podList corev1.PodList
	if err := c.List(ctx, &podList); err != nil {
		return nil, err
	}
	var serviceAccounts corev1.ServiceAccountList
	// The production receipt boundary is a direct APIReader. Never ask the
	// controller-runtime cached client to start a new ServiceAccount informer:
	// missing list RBAC could otherwise wait until the whole tick expires. This
	// optional witness gets at most a quarter of the remaining tick budget so
	// a blocked read still leaves time for the required core inventory.
	serviceAccountsComplete := false
	saBudget := 250 * time.Millisecond
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if quarter := remaining / 4; quarter < saBudget {
			saBudget = quarter
		}
	}
	if receiptBoundary != nil && ctx.Err() == nil && saBudget > 0 {
		saCtx, cancel := context.WithTimeout(ctx, saBudget)
		err := receiptBoundary.List(saCtx, &serviceAccounts)
		cancel()
		serviceAccountsComplete = err == nil && serviceAccounts.Continue == "" && serviceAccounts.RemainingItemCount == nil
	}
	var nsList corev1.NamespaceList
	if err := c.List(ctx, &nsList); err != nil {
		return nil, err
	}
	var npList networkingv1.NetworkPolicyList
	if err := c.List(ctx, &npList); err != nil {
		return nil, err
	}

	nsLabels := map[string]map[string]string{}
	dryRunNS := map[string]model.ActuationBrakeObservation{}
	for i := range nsList.Items {
		nsLabels[nsList.Items[i].Name] = nsList.Items[i].Labels
		dryRunNS[nsList.Items[i].Name] = actuationbrake.NamespaceObject(&nsList.Items[i])
	}

	// First pass: project pods and count per-owner replicas for the availability floor.
	type ownerCount struct{ desired, ready int }
	owners := map[string]*ownerCount{}
	pods := make([]model.Pod, 0, len(podList.Items))
	for i := range podList.Items {
		p := projectPod(&podList.Items[i], now)
		if o := metav1.GetControllerOf(&podList.Items[i]); o != nil && o.APIVersion == "apps/v1" && o.Kind == "ReplicaSet" && len(podList.Items[i].OwnerReferences) == 1 {
			p.WarmPoolOwnerUID = string(o.UID)
		}
		if relevant == nil || relevant(&podList.Items[i]) {
			p.RotationOwnership = ownership.Check(ctx, ownerReader, &podList.Items[i])
			p.StatefulRotation = statefulrotation.Observe(ctx, ownerReader, &podList.Items[i])
		} else {
			p.RotationOwnership.Reason = "outside-rotation-targets"
		}
		ownerKey := p.Namespace + "/" + p.OwnerKind + "/" + p.OwnerName
		if p.OwnerName != "" {
			oc := owners[ownerKey]
			if oc == nil {
				oc = &ownerCount{}
				owners[ownerKey] = oc
			}
			oc.desired++
			if p.Ready {
				oc.ready++
			}
		}
		pods = append(pods, p)
	}
	for i := range pods {
		ownerKey := pods[i].Namespace + "/" + pods[i].OwnerKind + "/" + pods[i].OwnerName
		if oc, ok := owners[ownerKey]; ok {
			pods[i].DesiredReplicas = oc.desired
			pods[i].ReadyReplicas = oc.ready
		}
	}
	if serviceAccountsComplete {
		bindPodBoundKubeAPIAuth(pods, podList.Items, serviceAccounts.Items)
	}

	// RBAC projection.
	roles, bindings, err := collectRBAC(ctx, c)
	if err != nil {
		return nil, err
	}
	perms := graph.ResolveRBAC(roles, bindings)

	// Build the graph input.
	gin := graph.Input{
		NamespaceLabels: nsLabels,
		SubjectPerms:    perms,
	}
	for i := range pods {
		av := 0.0
		if assetValue != nil {
			av = assetValue(&pods[i])
		}
		gin.Pods = append(gin.Pods, graph.PodNode{
			Namespace:      pods[i].Namespace,
			Name:           pods[i].Name,
			Labels:         pods[i].Labels,
			ServiceAccount: pods[i].ServiceAccount,
			Node:           pods[i].Node,
			AssetValue:     av,
		})
	}
	gin.NetPols = projectNetPols(npList.Items)
	g := graph.Build(gin)

	snap := &Snapshot{
		Pods:                            pods,
		PodByKey:                        map[string]*model.Pod{},
		Graph:                           g,
		EventByPod:                      map[string][]model.SecurityEventInfo{},
		PhoenixReceipts:                 map[string]model.PhoenixExecutionReceipt{},
		NamespaceDryRun:                 dryRunNS,
		Now:                             now,
		NamespaceLabels:                 nsLabels,
		PodInventoryComplete:            true,
		ServiceAccountInventoryComplete: serviceAccountsComplete,
	}
	for i := range snap.Pods {
		snap.PodByKey[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name] = &snap.Pods[i]
	}
	// Bind catalogue events against the very Pod list projected into this
	// decision snapshot. A separate live GET could disagree with this list and
	// accidentally attach an old event to a same-name replacement.
	currentPodUIDs := make(map[string]string, len(snap.Pods))
	for i := range snap.Pods {
		key := snap.Pods[i].Namespace + "/" + snap.Pods[i].Name
		if _, duplicate := currentPodUIDs[key]; duplicate {
			currentPodUIDs[key] = "" // ambiguous inventory cannot admit bound evidence
		} else {
			currentPodUIDs[key] = snap.Pods[i].UID
		}
	}

	// SecurityEvent stream.
	eventReader := client.Reader(c)
	if receiptBoundary != nil {
		eventReader = receiptBoundary
	}
	events, byPod, receipts, err := collectEventsAndReceipts(ctx, eventReader, now, currentPodUIDs)
	if err == nil {
		snap.EventInventoryComplete = true
		snap.PhoenixReceiptInventoryComplete = true
		snap.Events = events
		snap.EventByPod = byPod
		snap.PhoenixReceipts = receipts
		for i := range snap.Pods {
			bindAdapterObservation(&snap.Pods[i], byPod[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name])
			bindK8sObjectRevertObservation(&snap.Pods[i], byPod[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name])
			bindImageObservation(&snap.Pods[i], byPod[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name])
			bindSensitiveOutputObservation(ctx, eventReader, &snap.Pods[i], byPod[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name])
			bindVoiceMemoryObservation(ctx, eventReader, &snap.Pods[i], byPod[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name])
			bindVoiceRefundObservation(ctx, eventReader, &snap.Pods[i], byPod[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name])
			bindVoiceMCPObservation(ctx, eventReader, &snap.Pods[i], byPod[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name])
			bindVoiceOutputObservation(ctx, eventReader, &snap.Pods[i], byPod[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name])
			bindVoiceAdmissionObservation(ctx, eventReader, &snap.Pods[i], byPod[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name])
			bindLiteLLMClientObservation(ctx, eventReader, &snap.Pods[i], byPod[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name])
			bindCRMRefundObservation(ctx, eventReader, &snap.Pods[i], byPod[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name])
			bindDatastoreRestoreObservation(ctx, eventReader, &snap.Pods[i], byPod[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name])
			bindAgentActionDenyObservation(ctx, eventReader, &snap.Pods[i], byPod[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name])
			bindEndpointLeaseObservation(ctx, eventReader, &snap.Pods[i], byPod[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name])
			bindPersistenceObservation(ctx, eventReader, &snap.Pods[i], byPod[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name])
			bindServingRateBudgetObservation(ctx, eventReader, &snap.Pods[i], byPod[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name])
			bindNodeEscapeObservation(ctx, eventReader, &snap.Pods[i], byPod[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name])
			bindNetworkIsolateObservation(ctx, eventReader, &snap.Pods[i], byPod[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name])
			bindCredentialRevokeObservation(ctx, eventReader, &snap.Pods[i], byPod[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name])
		}
	}

	// Best effort: failure is UNKNOWN for M-34, not an empty policy inventory.
	var policies v1alpha1.PhorvexPolicyList
	if err := c.List(ctx, &policies); err == nil {
		snap.Policies = policies.Items
		snap.PolicyInventoryComplete = true
	}

	// Explicit CONSOLE/TEST admission only: the authoritative dedicated-SA external-theft
	// observation for identity-rotate. It is built by reading the cluster directly
	// (identityfixture.Observe, active=true requires the short-lived positive-control marker
	// the producer writes only after a stolen bearer actually authenticated, and proves no
	// EKS Pod Identity federation), never inferred from tenant labels. Ordinary production/
	// tenant pods get no observation; an API failure leaves the capability absent.
	if fixture, err := identityfixture.Load(); err == nil && receiptBoundary != nil {
		for i := range snap.Pods {
			p := &snap.Pods[i]
			if p.Namespace != fixture.Namespace || !strings.HasPrefix(p.ServiceAccount, identityfixture.RunPrefix) {
				continue
			}
			probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			observed, readErr := identityfixture.Observe(probeCtx, receiptBoundary, fixture, p.Name, p.UID, true)
			cancel()
			if readErr == nil && observed.Pod.ResourceVersion == p.PodResourceVersion {
				p.PodBoundKubeAPIAuth = observed.Projection
				p.IdentityRotationObservation = observed.Observation
			}
		}
	}

	// P-PHYSICS additive scan: node capacity + live PodDisruptionBudgets. The read
	// is least-privilege, but its failure is retained separately from an observed
	// empty inventory so replica-removing planning can fail closed.
	snap.Nodes = collectNodes(ctx, c)
	snap.PDBInventoryAttempted = true
	snap.PDBs, snap.PDBInventoryComplete = collectPDBs(ctx, c)
	services, servicesComplete := collectServicesInventory(ctx, c)
	slices, slicesComplete := collectEndpointSlices(ctx, c)
	snap.Services = services
	snap.ServiceAvailabilityComplete = servicesComplete && slicesComplete
	bindServiceAvailability(snap.Pods, services, slices, snap.ServiceAvailabilityComplete)
	warmConfig := newWarmPoolSnapshotCache(ownerReader, snap.Services)
	for i := range snap.Pods {
		p := &snap.Pods[i]
		if p.WarmPoolOwnerUID == "" || p.OwnerKind != "ReplicaSet" || p.RouteService == "" {
			continue
		}
		if warmConfig.Configured(ctx, *p) {
			p.WarmPoolConfigured = true
		}
	}
	return snap, nil
}

// Snapshot checks are deliberately conservative and bounded. One immutable
// controller/template fact is fetched per distinct namespace/RS identity; each
// Pod still gets its own selector, group and route check. Dispatch uses the
// authoritative Reader again and never trusts this cache for mutation.
const warmPoolSnapshotMaxControllers = 128

type warmPoolSnapshotController struct {
	valid    bool
	uid      string
	selector labels.Selector
	template corev1.PodTemplateSpec
	route    string
}
type warmPoolSnapshotCache struct {
	reader      client.Reader
	controllers map[string]warmPoolSnapshotController
	services    map[string]ServiceInfo
}

func newWarmPoolSnapshotCache(r client.Reader, services []ServiceInfo) *warmPoolSnapshotCache {
	c := &warmPoolSnapshotCache{reader: r, controllers: map[string]warmPoolSnapshotController{}, services: map[string]ServiceInfo{}}
	for _, svc := range services {
		c.services[svc.Namespace+"\x00"+svc.Name] = svc
	}
	return c
}
func (c *warmPoolSnapshotCache) Configured(ctx context.Context, p model.Pod) bool {
	if c == nil || c.reader == nil || p.WarmPoolOwnerUID == "" || p.OwnerKind != "ReplicaSet" || p.OwnerName == "" || p.RouteService == "" {
		return false
	}
	key := p.Namespace + "\x00" + p.OwnerName + "\x00" + p.WarmPoolOwnerUID
	fact, ok := c.controllers[key]
	if !ok {
		if len(c.controllers) >= warmPoolSnapshotMaxControllers {
			return false
		}
		fact = c.loadController(ctx, p)
		c.controllers[key] = fact
	}
	if !fact.valid || fact.uid != p.WarmPoolOwnerUID || fact.route != p.RouteService || !fact.selector.Matches(labels.Set(p.Labels)) {
		return false
	}
	groupPresent := false
	for _, key := range []string{"phorvex.ai/swap-group", "phorvex.ai/model-shard"} {
		if p.Labels[key] == "" {
			continue
		}
		groupPresent = true
		if fact.template.Labels[key] != p.Labels[key] {
			return false
		}
	}
	if !groupPresent {
		return false
	}
	svc, ok := c.services[p.Namespace+"\x00"+p.RouteService]
	if !ok || svc.Selector["phorvex.ai/role"] != "leader" {
		return false
	}
	for _, key := range []string{"phorvex.ai/swap-group", "phorvex.ai/model-shard"} {
		if p.Labels[key] != "" && svc.Selector[key] != p.Labels[key] {
			return false
		}
	}
	roleSelector := labels.SelectorFromSet(svc.Selector)
	for _, actual := range []map[string]string{p.Labels, fact.template.Labels} {
		for _, role := range []string{"leader", "warm-shadow", "retiring"} {
			projected := make(map[string]string, len(actual))
			for k, v := range actual {
				projected[k] = v
			}
			projected["phorvex.ai/role"] = role
			if roleSelector.Matches(labels.Set(projected)) != (role == "leader") {
				return false
			}
		}
	}
	return true
}
func (c *warmPoolSnapshotCache) loadController(ctx context.Context, p model.Pod) warmPoolSnapshotController {
	var out warmPoolSnapshotController
	rs := &appsv1.ReplicaSet{}
	if err := c.reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: p.OwnerName}, rs); err != nil || string(rs.UID) != p.WarmPoolOwnerUID || rs.DeletionTimestamp != nil || rs.Spec.Replicas == nil || *rs.Spec.Replicas < 2 || *rs.Spec.Replicas > 128 || rs.Status.ObservedGeneration != rs.Generation || rs.Spec.Selector == nil {
		return out
	}
	if parent := metav1.GetControllerOf(rs); parent != nil {
		if len(rs.OwnerReferences) != 1 || parent.APIVersion != "apps/v1" || parent.Kind != "Deployment" || parent.UID == "" {
			return out
		}
		d := &appsv1.Deployment{}
		if err := c.reader.Get(ctx, client.ObjectKey{Namespace: p.Namespace, Name: parent.Name}, d); err != nil || d.UID != parent.UID || d.DeletionTimestamp != nil {
			return out
		}
	} else if len(rs.OwnerReferences) != 0 {
		return out
	}
	for _, key := range []string{"phorvex.ai/role", "phorvex.ai/model-loaded"} {
		if _, ok := rs.Spec.Selector.MatchLabels[key]; ok {
			return out
		}
	}
	for _, req := range rs.Spec.Selector.MatchExpressions {
		if req.Key == "phorvex.ai/role" || req.Key == "phorvex.ai/model-loaded" {
			return out
		}
	}
	sel, err := metav1.LabelSelectorAsSelector(rs.Spec.Selector)
	if err != nil || sel.Empty() || !sel.Matches(labels.Set(rs.Spec.Template.Labels)) || rs.Spec.Template.Labels["phorvex.ai/role"] != "warm-shadow" || rs.Spec.Template.Labels["phorvex.ai/model-loaded"] != "false" || len(rs.Spec.Template.Spec.EphemeralContainers) != 0 {
		return out
	}
	route := rs.Spec.Template.Annotations["phorvex.ai/route-service"]
	if route == "" {
		return out
	}
	return warmPoolSnapshotController{valid: true, uid: string(rs.UID), selector: sel, template: *rs.Spec.Template.DeepCopy(), route: route}
}

// collectNodes projects node allocatable capacity (CPU/mem/GPU/MIG) — the conservation
// substrate for scheduler-slack and GPU-conservation. Best-effort.
func collectNodes(ctx context.Context, c client.Client) []NodeInfo {
	var nodeList corev1.NodeList
	if err := c.List(ctx, &nodeList); err != nil {
		return nil
	}
	out := make([]NodeInfo, 0, len(nodeList.Items))
	for i := range nodeList.Items {
		n := &nodeList.Items[i]
		ni := NodeInfo{Name: n.Name, MIGResources: map[string]int64{}, Labels: n.Labels}
		for _, condition := range n.Status.Conditions {
			if condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue && !n.Spec.Unschedulable {
				ni.Schedulable = true
				break
			}
		}
		alloc := n.Status.Allocatable
		ni.AllocatableCPUMilli = alloc.Cpu().MilliValue()
		ni.AllocatableMemBytes = alloc.Memory().Value()
		for name, q := range alloc {
			s := string(name)
			if strings.HasPrefix(s, gpuPrefix) {
				if strings.Contains(s, "mig") {
					ni.MIGResources[s] = q.Value()
				} else {
					ni.AllocatableGPU += q.Value()
				}
			}
		}
		out = append(out, ni)
	}
	return out
}

// collectServices projects selectors best-effort. Missing Service read permission must
// degrade ActionsSupported status, never stop decision ingest or reject a policy.
func collectServices(ctx context.Context, c client.Client) []ServiceInfo {
	out, _ := collectServicesInventory(ctx, c)
	return out
}

func collectServicesInventory(ctx context.Context, c client.Client) ([]ServiceInfo, bool) {
	var serviceList corev1.ServiceList
	if err := c.List(ctx, &serviceList); err != nil {
		return nil, false
	}
	out := make([]ServiceInfo, 0, len(serviceList.Items))
	for i := range serviceList.Items {
		svc := &serviceList.Items[i]
		selector := make(map[string]string, len(svc.Spec.Selector))
		for key, value := range svc.Spec.Selector {
			selector[key] = value
		}
		out = append(out, ServiceInfo{Namespace: svc.Namespace, Name: svc.Name, UID: string(svc.UID), Selector: selector})
	}
	return out, true
}

func collectEndpointSlices(ctx context.Context, c client.Client) ([]discoveryv1.EndpointSlice, bool) {
	var list discoveryv1.EndpointSliceList
	if err := c.List(ctx, &list); err != nil {
		return nil, false
	}
	return list.Items, true
}

// bindServiceAvailability projects only scopes whose target membership and
// service-wide Ready endpoint population are attributable to one immutable
// controller UID. Multi-controller Services remain explicitly unsupported: a
// per-controller resource key would otherwise let two owners spend the same
// Service headroom independently.
func bindServiceAvailability(pods []model.Pod, services []ServiceInfo, slices []discoveryv1.EndpointSlice, inventoryComplete bool) {
	podByUID := make(map[string]*model.Pod, len(pods))
	for i := range pods {
		pod := &pods[i]
		pod.ServiceAvailabilityKnown = inventoryComplete
		if !inventoryComplete {
			pod.ServiceAvailabilityReason = "service-or-endpointslice-inventory-unavailable"
		}
		if pod.UID != "" {
			podByUID[pod.UID] = pod
		}
	}
	if !inventoryComplete {
		return
	}

	for _, service := range services {
		selector := labels.SelectorFromSet(service.Selector)
		if service.Namespace == "" || service.Name == "" || service.UID == "" || selector.Empty() {
			continue
		}
		matchingTargets := make([]*model.Pod, 0)
		for i := range pods {
			pod := &pods[i]
			if pod.Namespace == service.Namespace && selector.Matches(labels.Set(pod.Labels)) {
				matchingTargets = append(matchingTargets, pod)
			}
		}
		if len(matchingTargets) == 0 {
			continue
		}

		readyUIDs := map[string]struct{}{}
		controllerUIDs := map[string]struct{}{}
		complete, reason := true, ""
		for i := range slices {
			slice := &slices[i]
			if slice.Namespace != service.Namespace || slice.Labels[discoveryv1.LabelServiceName] != service.Name {
				continue
			}
			owner := metav1.GetControllerOf(slice)
			if slice.UID == "" || slice.DeletionTimestamp != nil || owner == nil || owner.APIVersion != "v1" || owner.Kind != "Service" || owner.Name != service.Name || string(owner.UID) != service.UID {
				complete, reason = false, "endpointslice-service-identity-mismatch"
				break
			}
			for _, endpoint := range slice.Endpoints {
				if endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready {
					continue
				}
				ref := endpoint.TargetRef
				if ref == nil || ref.Kind != "Pod" || ref.Namespace != service.Namespace || ref.UID == "" {
					complete, reason = false, "ready-endpoint-pod-identity-unavailable"
					break
				}
				pod := podByUID[string(ref.UID)]
				if pod == nil || pod.Name != ref.Name || !pod.Ready || !selector.Matches(labels.Set(pod.Labels)) || pod.ControllerUID == "" {
					complete, reason = false, "ready-endpoint-pod-or-controller-mismatch"
					break
				}
				readyUIDs[pod.UID] = struct{}{}
				controllerUIDs[pod.ControllerUID] = struct{}{}
			}
			if !complete {
				break
			}
		}
		if complete && len(controllerUIDs) != 1 {
			complete, reason = false, "service-ready-members-do-not-have-one-controller-uid"
		}
		controllerUID := ""
		if complete {
			for uid := range controllerUIDs {
				controllerUID = uid
			}
		}
		for _, target := range matchingTargets {
			_, targetReady := readyUIDs[target.UID]
			// A selector match alone is not routed membership. When the Service
			// inventory is complete, only the exact Ready EndpointSlice target
			// consumes this Service's unavailable-replica capacity.
			if complete && !targetReady {
				continue
			}
			targetComplete, targetReason := complete && targetReady && target.ControllerUID == controllerUID, reason
			if complete && target.ControllerUID != controllerUID {
				targetReason = "target-controller-does-not-own-service-ready-set"
			}
			target.ServiceAvailability = append(target.ServiceAvailability, model.ServiceAvailabilityObservation{
				Scope:        model.ResourceScope{Kind: model.ResourceUnavailableReadyReplica, Namespace: service.Namespace, ServiceName: service.Name, ServiceUID: service.UID, ControllerUID: controllerUID},
				ReadyMembers: len(readyUIDs), TargetReady: targetReady, Complete: targetComplete, Reason: targetReason,
			})
		}
	}
}

// collectPDBs projects live PodDisruptionBudgets (Layer-A availability law).
func collectPDBs(ctx context.Context, c client.Client) ([]PDBInfo, bool) {
	var pdbList policyv1.PodDisruptionBudgetList
	if err := c.List(ctx, &pdbList); err != nil {
		return nil, false
	}
	out := make([]PDBInfo, 0, len(pdbList.Items))
	for i := range pdbList.Items {
		pdb := &pdbList.Items[i]
		info := PDBInfo{Namespace: pdb.Namespace, Name: pdb.Name, UID: string(pdb.UID), Generation: pdb.Generation, ObservedGeneration: pdb.Status.ObservedGeneration, MinAvailable: -1, DisruptionsAllowed: int(pdb.Status.DisruptionsAllowed), CurrentHealthy: int(pdb.Status.CurrentHealthy), DesiredHealthy: int(pdb.Status.DesiredHealthy), ExpectedPods: int(pdb.Status.ExpectedPods)}
		if pdb.Spec.MinAvailable != nil && pdb.Spec.MinAvailable.Type == 0 { // IntValue
			info.MinAvailable = int(pdb.Spec.MinAvailable.IntVal)
		}
		if pdb.Spec.MinAvailable != nil {
			info.MinAvailableText = pdb.Spec.MinAvailable.String()
		}
		if pdb.Spec.MaxUnavailable != nil {
			info.MaxUnavailableText = pdb.Spec.MaxUnavailable.String()
		}
		if sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector); err == nil {
			info.Selector = sel
			info.SelectorValid = true
		} else {
			info.Selector = labels.Nothing()
		}
		out = append(out, info)
	}
	return out, true
}

func projectPod(p *corev1.Pod, now time.Time) model.Pod {
	out := model.Pod{
		Namespace:          p.Namespace,
		Name:               p.Name,
		UID:                string(p.UID),
		PodResourceVersion: p.ResourceVersion,
		Labels:             p.Labels,
		OptOut:             actuationbrake.Pod(p.Annotations),
		Node:               p.Spec.NodeName,
		Phase:              string(p.Status.Phase),
		ServiceAccount:     p.Spec.ServiceAccountName,
	}
	if out.ServiceAccount == "" {
		out.ServiceAccount = "default"
	}
	if p.Status.StartTime != nil {
		out.StartedAt = p.Status.StartTime.Time
		out.Age = now.Sub(out.StartedAt)
	} else {
		out.StartedAt = p.CreationTimestamp.Time
		out.Age = now.Sub(out.StartedAt)
	}
	out.Ready = podReady(p)
	if out.Ready {
		for i := range p.Status.Conditions {
			c := p.Status.Conditions[i]
			if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
				out.ReadyAt = c.LastTransitionTime.Time
				break
			}
		}
	}
	out.MountedSecrets = mountedSecrets(p)
	out.OwnerKind, out.OwnerName = topOwner(p)
	if controller := metav1.GetControllerOf(p); controller != nil {
		out.ControllerUID = string(controller.UID)
	}
	out.HasGPU, out.MIGDevice = gpuInfo(p)
	out.Stateful = isStateful(p)
	out.ImageID = primaryImageID(p)
	out.CPURequestMilli, out.MemRequestBytes, out.GPURequestCount = podRequests(p)
	// AI/inference identity (P-CONTEXT): a served-model fingerprint + inference endpoint
	// are declared via annotations (a NIM/serving operator stamps these); honest-absent
	// ("") for non-AI workloads so the generic kill-chain path is unchanged.
	serving := servingcontext.FromAnnotations(p.Annotations)
	out.ModelID = serving.ModelID
	// Session epoch: either flush bumps it, and either resets the session exposure clock (PHVX-67).
	out.SessionEpoch = p.Annotations["phorvex.ai/kv-reset-epoch"] + "|" + p.Annotations["phorvex.ai/kv-migrate-epoch"]
	out.KVResetEpoch = ownedMetadataValue(p.Annotations, "phorvex.ai/kv-reset-epoch")
	out.KVMigrateEpoch = ownedMetadataValue(p.Annotations, "phorvex.ai/kv-migrate-epoch")
	out.KVLocalEffectEpoch = ownedMetadataValue(p.Annotations, "phorvex.ai/kv-local-effect-epoch")
	// M-23 per-action exposure epochs: the `phorvex.ai/*-epoch` labels the pod-alive rotation
	// handlers stamp (= pod.ResourceVersion at actuation). "" when the marker is absent (never
	// actuated, or stripped by a rollback) — ExposureFingerprints absent-skips those so the
	// variable stays unclocked and the guard fail-OPENs the first actuation. VarRouteKey reads
	// the `route-key` label both endpoint-rotate and route-rotate re-key.
	out.QuarantineEpoch = p.Labels["phorvex.ai/quarantine-epoch"]
	out.RouteKeyEpoch = p.Labels["phorvex.ai/route-key"]
	out.IdentityEpoch = p.Labels["phorvex.ai/identity-epoch"]
	out.AdapterEpoch = p.Labels["phorvex.ai/adapter-epoch"]
	out.DrainEpoch = p.Labels["phorvex.ai/drain-epoch"]
	out.GuardrailEpoch = p.Labels["phorvex.ai/guardrail-epoch"]
	out.GuardrailEpochObservation = ownedMetadataValue(p.Labels, "phorvex.ai/guardrail-epoch")
	out.EndpointPath = p.Annotations["phorvex.ai/endpoint"]
	out.RouteService = p.Annotations["phorvex.ai/route-service"]
	out.ParallelSize, _ = strconv.Atoi(p.Annotations["phorvex.ai/parallel-size"])
	// MIG device and desired profile authority are resolved at the capability and
	// actuation boundaries from kubelet PodResources and operator-owned policy.
	out.GuardrailVariants = distinctGuardrailVariants(
		p.Annotations["phorvex.ai/guardrail-variant"],
		p.Annotations["phorvex.ai/guardrail-variants"],
	)
	out.OutputPolicyConfigMap = p.Annotations["phorvex.ai/output-policy-configmap"]
	out.OutputPolicyRuleSHA256 = p.Annotations["phorvex.ai/output-policy-rule-sha256"]
	out.OutputProxySourceSHA256 = p.Annotations["phorvex.ai/output-proxy-source-sha256"]
	out.OutputSupportSourceSHA256 = p.Annotations["phorvex.ai/output-support-source-sha256"]
	out.OutputEventCreator = p.Annotations["phorvex.ai/output-event-creator"]
	out.VoiceMemoryConfigMap = p.Annotations["phorvex.ai/voice-memory-policy-configmap"]
	out.VoiceMemorySourceSHA256 = p.Annotations["phorvex.ai/voice-memory-source-sha256"]
	out.VoiceMemoryEventCreator = p.Annotations["phorvex.ai/voice-memory-event-creator"]
	out.VoiceRefundConfigMap = p.Annotations["phorvex.ai/voice-refund-policy-configmap"]
	out.VoiceRefundSourceSHA256 = p.Annotations["phorvex.ai/voice-refund-source-sha256"]
	out.VoiceRefundEventCreator = p.Annotations["phorvex.ai/voice-refund-event-creator"]
	out.VoiceMCPConfigMap = p.Annotations["phorvex.ai/voice-mcp-policy-configmap"]
	out.VoiceMCPSourceSHA256 = p.Annotations["phorvex.ai/voice-mcp-source-sha256"]
	out.VoiceMCPEventCreator = p.Annotations["phorvex.ai/voice-mcp-event-creator"]
	out.VoiceOutputConfigMap = p.Annotations["phorvex.ai/voice-output-policy-configmap"]
	out.VoiceAdmissionConfigMap = p.Annotations["phorvex.ai/voice-admission-policy-configmap"]
	out.VoiceOutputSourceSHA256 = p.Annotations["phorvex.ai/voice-output-source-sha256"]
	out.VoiceAdmissionSourceSHA256 = p.Annotations["phorvex.ai/voice-admission-source-sha256"]
	out.VoiceOutputEventCreator = p.Annotations["phorvex.ai/voice-output-event-creator"]
	out.VoiceAdmissionEventCreator = p.Annotations["phorvex.ai/voice-admission-event-creator"]
	// Serving is an explicit workload declaration, never inferred from a GPU allocation.
	// A model-id is itself a serving declaration; otherwise serving-port must be a valid
	// TCP port. Readiness and PodIP are separate structural prerequisites and do not prove
	// that a protocol answered or that the declared model is loaded.
	out.ServingDeclared = serving.Declared()
	out.ServingEndpointReady = out.ServingDeclared && out.Ready && p.Status.PodIP != ""
	// lora-adapter is operational tenant configuration, never an integrity assertion.
	return out
}

func distinctGuardrailVariants(current, alternatives string) int {
	roster, err := servingcontext.ParseGuardrailRoster(current, alternatives)
	if err != nil {
		return 0
	}
	return len(roster.Variants)
}

// primaryImageID returns the running image digest of the primary container — spec
// container 0 — resolved in Status.ContainerStatuses by exact Name (image-rarity +
// CVE/EPSS keying). The kubelet does not keep the status slice in spec order, so a
// positional read handed a sidecar digest to those consumers (M-173). "" when the
// primary has no spec name, no matching status or no reported ImageID yet: the running
// identity is unknown until observed — never another container's digest and never the
// declared spec tag. Runtime prefixes/digest normalization stay with the consumers.
func primaryImageID(p *corev1.Pod) string {
	if len(p.Spec.Containers) == 0 {
		return ""
	}
	name := p.Spec.Containers[0].Name
	if name == "" {
		return ""
	}
	for i := range p.Status.ContainerStatuses {
		if cs := &p.Status.ContainerStatuses[i]; cs.Name == name {
			return cs.ImageID
		}
	}
	return ""
}

// podRequests sums container CPU(milli)/memory(bytes)/GPU(count) requests — the
// scheduler-slack + GPU-conservation conservation inputs.
func podRequests(p *corev1.Pod) (cpuMilli, memBytes, gpu int64) {
	for _, ct := range p.Spec.Containers {
		req := ct.Resources.Requests
		cpuMilli += req.Cpu().MilliValue()
		memBytes += req.Memory().Value()
		for name, q := range req {
			n := string(name)
			if strings.HasPrefix(n, gpuPrefix) && !strings.Contains(n, "mig") {
				gpu += q.Value()
			}
		}
	}
	return
}

func podReady(p *corev1.Pod) bool {
	if p.DeletionTimestamp != nil {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func mountedSecrets(p *corev1.Pod) []string {
	seen := map[string]struct{}{}
	add := func(n string) {
		if n != "" {
			seen[n] = struct{}{}
		}
	}
	for _, v := range p.Spec.Volumes {
		if v.Secret != nil {
			add(v.Secret.SecretName)
		}
		if v.Projected != nil {
			for _, src := range v.Projected.Sources {
				if src.Secret != nil {
					add(src.Secret.Name)
				}
			}
		}
	}
	containers := append([]corev1.Container{}, p.Spec.Containers...)
	containers = append(containers, p.Spec.InitContainers...)
	for _, ct := range containers {
		for _, ef := range ct.EnvFrom {
			if ef.SecretRef != nil {
				add(ef.SecretRef.Name)
			}
		}
		for _, e := range ct.Env {
			if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
				add(e.ValueFrom.SecretKeyRef.Name)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	return out
}

// topOwner returns the (kind,name) of the controlling owner. ReplicaSets are
// reported under their Deployment name when the RS name encodes it; otherwise the
// direct owner is used.
func topOwner(p *corev1.Pod) (string, string) {
	for _, o := range p.OwnerReferences {
		if o.Controller != nil && *o.Controller {
			return o.Kind, o.Name
		}
	}
	if len(p.OwnerReferences) > 0 {
		return p.OwnerReferences[0].Kind, p.OwnerReferences[0].Name
	}
	return "", ""
}

func gpuInfo(p *corev1.Pod) (bool, string) {
	return gpudevice.HasGPUResource(p), gpudevice.MIGResourceName(p)
}

func isStateful(p *corev1.Pod) bool {
	kind, _ := topOwner(p)
	if kind == "StatefulSet" || kind == "Job" {
		return true
	}
	for _, v := range p.Spec.Volumes {
		if v.PersistentVolumeClaim != nil {
			return true
		}
	}
	return false
}

func collectRBAC(ctx context.Context, c client.Client) ([]graph.Role, []graph.RoleBinding, error) {
	var roleList rbacv1.RoleList
	if err := c.List(ctx, &roleList); err != nil {
		return nil, nil, err
	}
	var crList rbacv1.ClusterRoleList
	if err := c.List(ctx, &crList); err != nil {
		return nil, nil, err
	}
	var rbList rbacv1.RoleBindingList
	if err := c.List(ctx, &rbList); err != nil {
		return nil, nil, err
	}
	var crbList rbacv1.ClusterRoleBindingList
	if err := c.List(ctx, &crbList); err != nil {
		return nil, nil, err
	}

	roles := make([]graph.Role, 0, len(roleList.Items)+len(crList.Items))
	for i := range roleList.Items {
		roles = append(roles, graph.Role{Namespace: roleList.Items[i].Namespace, Name: roleList.Items[i].Name, Rules: projectRules(roleList.Items[i].Rules)})
	}
	for i := range crList.Items {
		roles = append(roles, graph.Role{Name: crList.Items[i].Name, Cluster: true, Rules: projectRules(crList.Items[i].Rules)})
	}
	bindings := make([]graph.RoleBinding, 0, len(rbList.Items)+len(crbList.Items))
	for i := range rbList.Items {
		bindings = append(bindings, graph.RoleBinding{
			Namespace:   rbList.Items[i].Namespace,
			Name:        rbList.Items[i].Name,
			RoleRefKind: rbList.Items[i].RoleRef.Kind,
			RoleRefName: rbList.Items[i].RoleRef.Name,
			Subjects:    projectSubjects(rbList.Items[i].Subjects),
		})
	}
	for i := range crbList.Items {
		bindings = append(bindings, graph.RoleBinding{
			Name:        crbList.Items[i].Name,
			Cluster:     true,
			RoleRefKind: crbList.Items[i].RoleRef.Kind,
			RoleRefName: crbList.Items[i].RoleRef.Name,
			Subjects:    projectSubjects(crbList.Items[i].Subjects),
		})
	}
	return roles, bindings, nil
}

func projectRules(rules []rbacv1.PolicyRule) []graph.PolicyRule {
	out := make([]graph.PolicyRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, graph.PolicyRule{APIGroups: r.APIGroups, Resources: r.Resources, Verbs: r.Verbs})
	}
	return out
}

func projectSubjects(subs []rbacv1.Subject) []graph.Subject {
	out := make([]graph.Subject, 0, len(subs))
	for _, s := range subs {
		out = append(out, graph.Subject{Kind: s.Kind, Namespace: s.Namespace, Name: s.Name})
	}
	return out
}

func projectNetPols(items []networkingv1.NetworkPolicy) []graph.NetPol {
	out := make([]graph.NetPol, 0, len(items))
	for i := range items {
		np := &items[i]
		sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
		if err != nil {
			sel = labels.Everything()
		}
		gp := graph.NetPol{Namespace: np.Namespace, Selector: sel}
		for _, t := range np.Spec.PolicyTypes {
			switch t {
			case networkingv1.PolicyTypeIngress:
				gp.HasIngressType = true
			case networkingv1.PolicyTypeEgress:
				gp.HasEgressType = true
			}
		}
		// A NetworkPolicy with no explicit policyTypes implies Ingress (k8s default),
		// and Egress too if any egress rules are present.
		if len(np.Spec.PolicyTypes) == 0 {
			gp.HasIngressType = true
			if len(np.Spec.Egress) > 0 {
				gp.HasEgressType = true
			}
		}
		for _, r := range np.Spec.Ingress {
			gp.Ingress = append(gp.Ingress, projectNetRule(peersFromIngress(r), len(r.From) == 0))
		}
		for _, r := range np.Spec.Egress {
			gp.Egress = append(gp.Egress, projectNetRule(peersFromEgress(r), len(r.To) == 0))
		}
		out = append(out, gp)
	}
	return out
}

func peersFromIngress(r networkingv1.NetworkPolicyIngressRule) []networkingv1.NetworkPolicyPeer {
	return r.From
}
func peersFromEgress(r networkingv1.NetworkPolicyEgressRule) []networkingv1.NetworkPolicyPeer {
	return r.To
}

func projectNetRule(peers []networkingv1.NetworkPolicyPeer, allowAll bool) graph.NetRule {
	rule := graph.NetRule{AllowAll: allowAll}
	for _, p := range peers {
		gp := graph.NetPeer{}
		if p.IPBlock != nil {
			gp.IPBlock = true
		}
		if p.PodSelector != nil {
			if s, err := metav1.LabelSelectorAsSelector(p.PodSelector); err == nil {
				gp.HasPodSelector = true
				gp.PodSelector = s
			}
		}
		if p.NamespaceSelector != nil {
			if s, err := metav1.LabelSelectorAsSelector(p.NamespaceSelector); err == nil {
				gp.HasNamespaceSel = true
				gp.NamespaceSelector = s
			}
		}
		rule.Peers = append(rule.Peers, gp)
	}
	return rule
}

// PhaseOf derives the cost-relevant workload phase from pod status + telemetry.
func PhaseOf(p model.Pod, t model.Telemetry) model.WorkloadPhase {
	ph, _ := model.ClassifyPhase(p, t)
	return ph
}

// Phase reason strings recorded alongside the phase; see model.ClassifyPhase.
const (
	PhaseReasonColdStart     = model.PhaseReasonColdStart
	PhaseReasonUnknown       = model.PhaseReasonUnknown
	PhaseReasonDraining      = model.PhaseReasonDraining
	PhaseReasonIdleMeasured  = model.PhaseReasonIdleMeasured
	PhaseReasonWarmNoApp     = model.PhaseReasonWarmNoApp
	PhaseReasonWarmUncertain = model.PhaseReasonWarmUncertain
	PhaseReasonBusyMeasured  = model.PhaseReasonBusyMeasured
)

// PhaseReasonOf returns the auditable reason for PhaseOf's verdict on the same inputs.
func PhaseReasonOf(p model.Pod, t model.Telemetry) string {
	_, reason := model.ClassifyPhase(p, t)
	return reason
}

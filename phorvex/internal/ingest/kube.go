/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package ingest

import (
	"context"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/phorvex/phorvex/internal/graph"
	"github.com/phorvex/phorvex/internal/model"
)

// Snapshot is one cluster-wide ingest pass shared by all tenants in a tick: the
// projected pods, the built blast-radius graph, namespace labels, and the
// SecurityEvent stream. Built once per tick (NFR1: <1s for <=1000 pods) so per-tenant
// processing is cheap.
type Snapshot struct {
	Pods       []model.Pod
	PodByKey   map[string]*model.Pod
	Graph      *graph.Graph
	Events     []model.SecurityEventInfo
	EventByPod map[string][]model.SecurityEventInfo
	// DryRunNamespaces are namespaces annotated phorvex.ai/dry-run=true|1|yes — a
	// per-namespace actuation freeze independent of any policy's mode (FR8).
	DryRunNamespaces map[string]bool
	Now              time.Time

	// --- P-PHYSICS (UCW) additive scan products: node capacity + live PodDisruptionBudgets,
	// the substrate the platform scanner turns into PhysicsWitness. ---
	Nodes []NodeInfo
	PDBs  []PDBInfo
	// Services are projected read-only so capability status can verify that request-drain's
	// target Service actually selects on phorvex.ai/serving.
	Services []ServiceInfo

	// GPUWitness is the live DCGM-via-Prometheus GPU half ("ns/pod" -> witness GPU fields:
	// GPUPresent + VRAMFraction/SMOccupancy/LinkBandwidth). Populated by PopulateGPUWitness when
	// a Prometheus/dcgm-exporter feed is configured; nil/empty is honest-absent and a GPU
	// platform adapter leaves those floats at 0.
	GPUWitness map[string]model.PhysicsWitness
}

// NodeInfo is the conservation-law substrate per node (allocatable vs the pods bound to
// it). GPU/MIG resource counts are integer device-plugin resources (measurable on kind
// with the device plugin; absent => 0).
type NodeInfo struct {
	Name                string
	AllocatableCPUMilli int64
	AllocatableMemBytes int64
	AllocatableGPU      int64
	MIGResources        map[string]int64  // nvidia.com/mig-* -> count (legal-partition geometry)
	Labels              map[string]string // node labels (instance-type / cloud markers; within the existing `list nodes` RBAC — no privilege delta)
	Schedulable         bool              // Ready and not spec.unschedulable
}

// ServiceInfo is the minimum read-only Service projection needed by capability status.
type ServiceInfo struct {
	Namespace string
	Name      string
	Selector  map[string]string
}

// PDBInfo is a live PodDisruptionBudget projection (Layer-A availability law, replacing
// the static policy proxy as an ADDITIVE veto).
type PDBInfo struct {
	Namespace          string
	Selector           labels.Selector
	MinAvailable       int
	DisruptionsAllowed int
}

// gpuPrefix marks NVIDIA device-plugin resources (GPU / MIG slices).
const gpuPrefix = "nvidia.com/"

// CollectSnapshot reads pods, Services, NetworkPolicies, RBAC, namespaces and SecurityEvents
// cluster-wide and projects them into a Snapshot. Read-only (least privilege).
func CollectSnapshot(ctx context.Context, c client.Client, now time.Time, assetValue func(p *model.Pod) float64) (*Snapshot, error) {
	var podList corev1.PodList
	if err := c.List(ctx, &podList); err != nil {
		return nil, err
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
	dryRunNS := map[string]bool{}
	for i := range nsList.Items {
		nsLabels[nsList.Items[i].Name] = nsList.Items[i].Labels
		switch nsList.Items[i].Annotations["phorvex.ai/dry-run"] {
		case "true", "True", "1", "yes":
			dryRunNS[nsList.Items[i].Name] = true
		}
	}

	// First pass: project pods and count per-owner replicas for the availability floor.
	type ownerCount struct{ desired, ready int }
	owners := map[string]*ownerCount{}
	pods := make([]model.Pod, 0, len(podList.Items))
	for i := range podList.Items {
		p := projectPod(&podList.Items[i], now)
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
		Pods:             pods,
		PodByKey:         map[string]*model.Pod{},
		Graph:            g,
		EventByPod:       map[string][]model.SecurityEventInfo{},
		DryRunNamespaces: dryRunNS,
		Now:              now,
	}
	for i := range snap.Pods {
		snap.PodByKey[snap.Pods[i].Namespace+"/"+snap.Pods[i].Name] = &snap.Pods[i]
	}

	// SecurityEvent stream.
	events, byPod, err := collectEvents(ctx, c, now)
	if err == nil {
		snap.Events = events
		snap.EventByPod = byPod
	}

	// P-PHYSICS additive scan: node capacity + live PodDisruptionBudgets. Best-effort
	// (read-only, least-privilege); absence degrades the witness to honest-neutral.
	snap.Nodes = collectNodes(ctx, c)
	snap.PDBs = collectPDBs(ctx, c)
	snap.Services = collectServices(ctx, c)
	return snap, nil
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
	var serviceList corev1.ServiceList
	if err := c.List(ctx, &serviceList); err != nil {
		return nil
	}
	out := make([]ServiceInfo, 0, len(serviceList.Items))
	for i := range serviceList.Items {
		svc := &serviceList.Items[i]
		selector := make(map[string]string, len(svc.Spec.Selector))
		for key, value := range svc.Spec.Selector {
			selector[key] = value
		}
		out = append(out, ServiceInfo{Namespace: svc.Namespace, Name: svc.Name, Selector: selector})
	}
	return out
}

// collectPDBs projects live PodDisruptionBudgets (Layer-A availability law).
func collectPDBs(ctx context.Context, c client.Client) []PDBInfo {
	var pdbList policyv1.PodDisruptionBudgetList
	if err := c.List(ctx, &pdbList); err != nil {
		return nil
	}
	out := make([]PDBInfo, 0, len(pdbList.Items))
	for i := range pdbList.Items {
		pdb := &pdbList.Items[i]
		info := PDBInfo{Namespace: pdb.Namespace, MinAvailable: -1, DisruptionsAllowed: int(pdb.Status.DisruptionsAllowed)}
		if pdb.Spec.MinAvailable != nil && pdb.Spec.MinAvailable.Type == 0 { // IntValue
			info.MinAvailable = int(pdb.Spec.MinAvailable.IntVal)
		}
		if sel, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector); err == nil {
			info.Selector = sel
		} else {
			info.Selector = labels.Nothing()
		}
		out = append(out, info)
	}
	return out
}

func projectPod(p *corev1.Pod, now time.Time) model.Pod {
	out := model.Pod{
		Namespace:      p.Namespace,
		Name:           p.Name,
		UID:            string(p.UID),
		Labels:         p.Labels,
		Node:           p.Spec.NodeName,
		Phase:          string(p.Status.Phase),
		ServiceAccount: p.Spec.ServiceAccountName,
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
	out.HasGPU, out.MIGDevice = gpuInfo(p)
	out.Stateful = isStateful(p)
	out.ImageID = primaryImageID(p)
	out.CPURequestMilli, out.MemRequestBytes, out.GPURequestCount = podRequests(p)
	// AI/inference identity (P-CONTEXT): a served-model fingerprint + inference endpoint
	// are declared via annotations (a NIM/serving operator stamps these); honest-absent
	// ("") for non-AI workloads so the generic kill-chain path is unchanged.
	out.ModelID = p.Annotations["phorvex.ai/model-id"]
	// Session epoch: either flush bumps it, and either resets the session exposure clock (PHVX-67).
	out.SessionEpoch = p.Annotations["phorvex.ai/kv-reset-epoch"] + "|" + p.Annotations["phorvex.ai/kv-migrate-epoch"]
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
	out.EndpointPath = p.Annotations["phorvex.ai/endpoint"]
	out.RouteService = p.Annotations["phorvex.ai/route-service"]
	out.ParallelSize, _ = strconv.Atoi(p.Annotations["phorvex.ai/parallel-size"])
	out.MIGGPUID = p.Annotations["phorvex.ai/gpu-id"]
	out.MIGTargetProfile = p.Annotations["phorvex.ai/mig-target-profile"]
	out.GuardrailVariants = distinctGuardrailVariants(
		p.Annotations["phorvex.ai/guardrail-variant"],
		p.Annotations["phorvex.ai/guardrail-variants"],
	)
	out.ServingEndpointReady = out.Ready && p.Status.PodIP != "" &&
		(out.HasGPU || out.ModelID != "" || p.Annotations["phorvex.ai/serving-port"] != "")
	// A detector flags a poisoned/unauthorized LoRA via phorvex.ai/lora-adapter on a LoRA-enabled
	// pod; surfacing it as SuspectAdapter lets recon mint the adapter-integrity fact that ONLY
	// adapter-rotate covers (the same annotation/label the adapter-rotate handler consumes).
	if p.Labels["phorvex.ai/lora-enabled"] == "true" {
		out.SuspectAdapter = p.Annotations["phorvex.ai/lora-adapter"]
	}
	return out
}

func distinctGuardrailVariants(current, alternatives string) int {
	seen := map[string]struct{}{}
	for _, value := range append([]string{current}, strings.Split(alternatives, ",")...) {
		if value = strings.TrimSpace(value); value != "" {
			seen[value] = struct{}{}
		}
	}
	return len(seen)
}

// primaryImageID returns the running image digest of the first container (image-rarity
// + CVE/EPSS keying). Falls back to the spec image ref when the digest is not yet
// reported. "" when nothing is known.
func primaryImageID(p *corev1.Pod) string {
	for i := range p.Status.ContainerStatuses {
		if id := p.Status.ContainerStatuses[i].ImageID; id != "" {
			return id
		}
	}
	if len(p.Spec.Containers) > 0 {
		return p.Spec.Containers[0].Image
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
	hasGPU := false
	mig := ""
	scan := func(rl corev1.ResourceList) {
		for name := range rl {
			n := string(name)
			if strings.HasPrefix(n, gpuPrefix) {
				hasGPU = true
				if strings.Contains(n, "mig") && mig == "" {
					mig = n
				}
			}
		}
	}
	for _, ct := range p.Spec.Containers {
		scan(ct.Resources.Limits)
		scan(ct.Resources.Requests)
	}
	return hasGPU, mig
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
	ph, _ := classifyPhase(p, t)
	return ph
}

// Phase reason strings recorded alongside the phase (T1-C: phaseReason). The Warm enum
// value covers both busy-measured and warm-no-app-signal; the reason disambiguates them.
const (
	PhaseReasonColdStart    = "coldstart"
	PhaseReasonUnknown      = "unknown"
	PhaseReasonDraining     = "draining"
	PhaseReasonIdleMeasured = "idle-measured"
	PhaseReasonWarmNoApp    = "warm-no-app-signal"
	PhaseReasonBusyMeasured = "busy-measured"
)

// PhaseReasonOf returns the auditable reason for PhaseOf's verdict on the same inputs, so
// the record distinguishes idle-measured from warm-no-app-signal from busy-measured (A-10).
func PhaseReasonOf(p model.Pod, t model.Telemetry) string {
	_, reason := classifyPhase(p, t)
	return reason
}

// classifyPhase is the SINGLE decision tree behind PhaseOf and PhaseReasonOf, so the phase and
// its recorded reason can never drift (K3 P3 F3). The Warm enum value covers both busy-measured
// and warm-no-app-signal; the reason disambiguates them.
func classifyPhase(p model.Pod, t model.Telemetry) (model.WorkloadPhase, string) {
	if p.Phase == string(corev1.PodSucceeded) || p.Phase == string(corev1.PodFailed) {
		return model.PhaseDraining, PhaseReasonDraining
	}
	if !p.Ready {
		// Young + not ready => still warming; older + not ready => unknown/unhealthy.
		if p.Age < 2*time.Minute {
			return model.PhaseColdStarting, PhaseReasonColdStart
		}
		return model.PhaseUnknown, PhaseReasonUnknown
	}
	if !t.AppLevelPresent() {
		// Ready, no APP-LEVEL signal: assume warm (rotating costs the warm-load). Keyed on
		// AppLevelPresent (not any-signal), so a pod exporting only universal cAdvisor metrics
		// stays Warm for its whole life instead of collapsing to Idle — the M-142 fix.
		return model.PhaseWarm, PhaseReasonWarmNoApp
	}
	if t.ReqRate.Usable() && t.ReqRate.Value <= 0.001 && (!t.GPUUtil.Usable() || t.GPUUtil.Value <= 0.01) {
		return model.PhaseIdle, PhaseReasonIdleMeasured
	}
	return model.PhaseWarm, PhaseReasonBusyMeasured
}

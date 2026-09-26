package console

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// podBoundCPUCleanupLiveAbsence checks the current old-nonce footprint. It is
// needed at both launch admission and the new event boundary. The historical
// run may still have emitted an event or caused an effect; this checks only
// present owned resources, and does not relabel its PARTIAL result.
func podBoundCPUCleanupLiveAbsence(ctx context.Context, kc kubernetes.Interface, dc dynamic.Interface,
	proof cpuCleanupProof, ledgerNamespace, ledgerName string) error {
	ledgerSum := sha256.Sum256([]byte(proof.namespaceUID))
	if kc == nil || dc == nil || !mongoKubeUID.MatchString(proof.namespaceUID) ||
		!podBoundTokenNonce.MatchString(proof.nonce) || proof.name != "pod-token-"+proof.nonce ||
		len(proof.created) != len(cpuPreEventResources) || proof.sourcePodUID == "" ||
		proof.peerPodUID == "" || proof.replicaSetUID == "" || proof.amtdUID == "" ||
		ledgerNamespace == "" || ledgerName == "" ||
		ledgerName != fmt.Sprintf("phorvex-quarantine-capacity-%x", ledgerSum[:20]) {
		return errors.New("CPU token predecessor cleanup scope unavailable")
	}
	if proof.postRequest && (!mongoKubeUID.MatchString(proof.clusterUID) ||
		proof.sourcePodName == "" || proof.peerPodName == "" ||
		!mongoSHA.MatchString(proof.requestSHA256) || !mongoSHA.MatchString(proof.auditStartSHA256)) {
		return errors.New("CPU token post-request cleanup source unavailable")
	}
	ns := podBoundTokenCPUNamespace
	cluster, err := kc.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil || cluster.UID == "" || proof.postRequest && string(cluster.UID) != proof.clusterUID {
		return errors.New("CPU token predecessor cluster identity changed")
	}
	ownedNS, err := kc.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
	if err != nil || string(ownedNS.UID) != proof.namespaceUID || ownedNS.DeletionTimestamp != nil ||
		ownedNS.Labels["phorvex.ai/cpu-token-fixture"] != "true" {
		return errors.New("CPU token predecessor namespace identity changed")
	}
	getAbsent := func(resource, name string, get func() error) error {
		if name == "" || !apierrors.IsNotFound(get()) {
			return fmt.Errorf("CPU token predecessor %s/%s absence unconfirmed", resource, name)
		}
		return nil
	}
	for resource, uid := range proof.created {
		if !cpuPreEventResources[resource] || !mongoKubeUID.MatchString(uid) {
			return errors.New("CPU token predecessor created UID scope differs")
		}
		name := proof.name
		var get func() error
		switch resource {
		case "serviceaccounts":
			get = func() error { _, e := kc.CoreV1().ServiceAccounts(ns).Get(ctx, name, metav1.GetOptions{}); return e }
		case "deployments":
			get = func() error { _, e := kc.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{}); return e }
		case "services":
			get = func() error { _, e := kc.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{}); return e }
		case "poddisruptionbudgets":
			get = func() error {
				_, e := kc.PolicyV1().PodDisruptionBudgets(ns).Get(ctx, name, metav1.GetOptions{})
				return e
			}
		case "roles":
			get = func() error { _, e := kc.RbacV1().Roles(ns).Get(ctx, name, metav1.GetOptions{}); return e }
		case "rolebindings":
			get = func() error { _, e := kc.RbacV1().RoleBindings(ns).Get(ctx, name, metav1.GetOptions{}); return e }
		case "phorvexpolicies":
			gvr := schema.GroupVersionResource{Group: "phorvex.ai", Version: "v1alpha1", Resource: resource}
			get = func() error { _, e := dc.Resource(gvr).Namespace(ns).Get(ctx, name, metav1.GetOptions{}); return e }
		case "podmonitors":
			gvr := schema.GroupVersionResource{Group: "monitoring.coreos.com", Version: "v1", Resource: resource}
			get = func() error { _, e := dc.Resource(gvr).Namespace(ns).Get(ctx, name, metav1.GetOptions{}); return e }
		default:
			return errors.New("CPU token predecessor resource outside fixed scope")
		}
		if err := getAbsent(resource, name, get); err != nil {
			return err
		}
	}
	for _, name := range []string{proof.sourcePodName, proof.peerPodName} {
		if name == "" {
			continue
		}
		if err := getAbsent("pods", name, func() error {
			_, e := kc.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
			return e
		}); err != nil {
			return err
		}
	}
	amtdName := "phorvex-" + ns + "-" + proof.nonce
	amtdGVR := schema.GroupVersionResource{Group: "amtd.r6security.com", Version: "v1beta1", Resource: "adaptivemovingtargetdefenses"}
	if err := getAbsent("adaptivemovingtargetdefenses", amtdName, func() error {
		_, e := dc.Resource(amtdGVR).Namespace(ns).Get(ctx, amtdName, metav1.GetOptions{})
		return e
	}); err != nil {
		return err
	}
	eventName := "phorvex-e2e-" + proof.nonce
	eventGVR := schema.GroupVersionResource{Group: "amtd.r6security.com", Version: "v1beta1", Resource: "securityevents"}
	if err := getAbsent("securityevents", eventName, func() error {
		_, e := dc.Resource(eventGVR).Get(ctx, eventName, metav1.GetOptions{})
		return e
	}); err != nil {
		return err
	}
	if err := cpuCleanupOwnedInventoryAbsent(ctx, kc, dc, proof); err != nil {
		return err
	}
	return cpuCleanupLedgerAbsent(ctx, kc, proof, ledgerNamespace, ledgerName)
}

func cpuCleanupOwnedInventoryAbsent(ctx context.Context, kc kubernetes.Interface, dc dynamic.Interface, p cpuCleanupProof) error {
	ns := podBoundTokenCPUNamespace
	const limit = 200
	pods, err := kc.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{Limit: limit})
	if err != nil || pods.Continue != "" {
		return errors.New("CPU token predecessor Pod inventory incomplete")
	}
	for _, pod := range pods.Items {
		if string(pod.UID) == p.sourcePodUID || string(pod.UID) == p.peerPodUID ||
			pod.Name == p.sourcePodName || p.peerPodName != "" && pod.Name == p.peerPodName ||
			pod.Labels[podBoundOwnerLabel] == p.nonce || pod.Name == p.name || strings.HasPrefix(pod.Name, p.name+"-") {
			return errors.New("CPU token predecessor owned Pod or replacement remains")
		}
	}
	replicas, err := kc.AppsV1().ReplicaSets(ns).List(ctx, metav1.ListOptions{Limit: limit})
	if err != nil || replicas.Continue != "" {
		return errors.New("CPU token predecessor ReplicaSet inventory incomplete")
	}
	for _, rs := range replicas.Items {
		if string(rs.UID) == p.replicaSetUID || rs.Labels[podBoundOwnerLabel] == p.nonce ||
			strings.HasPrefix(rs.Name, p.name+"-") {
			return errors.New("CPU token predecessor owned ReplicaSet remains")
		}
		for _, ref := range rs.OwnerReferences {
			if string(ref.UID) == p.deploymentUID {
				return errors.New("CPU token predecessor owned ReplicaSet remains")
			}
		}
	}
	slices, err := kc.DiscoveryV1().EndpointSlices(ns).List(ctx, metav1.ListOptions{Limit: limit})
	if err != nil || slices.Continue != "" {
		return errors.New("CPU token predecessor EndpointSlice inventory incomplete")
	}
	for _, slice := range slices.Items {
		if slice.Labels["kubernetes.io/service-name"] == p.name || slice.Labels[podBoundOwnerLabel] == p.nonce {
			return errors.New("CPU token predecessor Service EndpointSlice remains")
		}
		for _, ref := range slice.OwnerReferences {
			if string(ref.UID) == p.created["services"] {
				return errors.New("CPU token predecessor Service EndpointSlice remains")
			}
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.TargetRef != nil && (string(endpoint.TargetRef.UID) == p.sourcePodUID ||
				string(endpoint.TargetRef.UID) == p.peerPodUID) {
				return errors.New("CPU token predecessor Service EndpointSlice still routes old Pod")
			}
		}
	}
	network, err := kc.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{Limit: limit})
	if err != nil || network.Continue != "" {
		return errors.New("CPU token predecessor NetworkPolicy inventory incomplete")
	}
	req := podBoundTokenRequest{Namespace: ns, Nonce: p.nonce, SourcePodName: p.sourcePodName,
		SourcePodUID: p.sourcePodUID, PeerPodName: p.peerPodName, PeerPodUID: p.peerPodUID}
	for _, policy := range network.Items {
		if strings.Contains(policy.Name, p.nonce) || policy.Labels[podBoundOwnerLabel] == p.nonce ||
			podBoundGeneratedCleanupName("networkpolicies", policy.Name, req) ||
			policy.Spec.PodSelector.MatchLabels[podBoundOwnerLabel] == p.nonce {
			return errors.New("CPU token predecessor NetworkPolicy remains")
		}
	}
	for _, gvr := range []schema.GroupVersionResource{
		{Group: "amtd.r6security.com", Version: "v1beta1", Resource: "adaptivemovingtargetdefenses"},
		{Group: "amtd.r6security.com", Version: "v1beta1", Resource: "securityevents"},
	} {
		var listErr error
		var count int
		var continuation string
		if gvr.Resource == "securityevents" {
			items, err := dc.Resource(gvr).List(ctx, metav1.ListOptions{FieldSelector: "metadata.name=" + "phorvex-e2e-" + p.nonce, Limit: 2})
			listErr = err
			if err == nil {
				count, continuation = len(items.Items), items.GetContinue()
			}
		} else {
			items, err := dc.Resource(gvr).Namespace(ns).List(ctx, metav1.ListOptions{FieldSelector: "metadata.name=" + "phorvex-" + ns + "-" + p.nonce, Limit: 2})
			listErr = err
			if err == nil {
				count, continuation = len(items.Items), items.GetContinue()
			}
		}
		if listErr != nil || count != 0 || continuation != "" {
			return errors.New("CPU token predecessor generated object inventory incomplete")
		}
	}
	return nil
}

func cpuCleanupLedgerAbsent(ctx context.Context, kc kubernetes.Interface, p cpuCleanupProof, namespace, name string) error {
	cm, err := kc.CoreV1().ConfigMaps(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil || cm.UID == "" || cm.DeletionTimestamp != nil || cm.Labels["phorvex.ai/quarantine-capacity"] != "v1" {
		return errors.New("CPU token predecessor protected ledger unavailable")
	}
	raw := cm.Data["ledger"]
	if len(raw) == 0 || len(raw) > 768<<10 || rejectNATSNestedDuplicates([]byte(raw)) != nil {
		return errors.New("CPU token predecessor protected ledger ambiguous")
	}
	var ledger struct {
		Version      int    `json:"version"`
		Namespace    string `json:"namespace"`
		NamespaceUID string `json:"namespaceUID"`
		Records      map[string]struct {
			PodUID       string `json:"podUID"`
			PolicyUID    string `json:"policyUID"`
			EventName    string `json:"eventName"`
			NamespaceUID string `json:"namespaceUID"`
		} `json:"records"`
	}
	if json.Unmarshal([]byte(raw), &ledger) != nil || ledger.Version != 1 ||
		ledger.Namespace != podBoundTokenCPUNamespace || ledger.NamespaceUID != p.namespaceUID || ledger.Records == nil ||
		len(ledger.Records) > 128 {
		return errors.New("CPU token predecessor protected ledger scope differs")
	}
	for key, record := range ledger.Records {
		if key == "" || record.PodUID != key || record.NamespaceUID != p.namespaceUID ||
			key == p.sourcePodUID || key == p.peerPodUID || record.PolicyUID == p.created["phorvexpolicies"] ||
			record.EventName == "phorvex-e2e-"+p.nonce {
			return errors.New("CPU token predecessor protected reservation remains or ledger is ambiguous")
		}
	}
	return nil
}

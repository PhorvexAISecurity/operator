package scenarios

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/r6security/phoenix-test-harness/internal/core"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type podTokenInventory struct {
	checked         []string
	problems        []string
	protectedAbsent bool
}

func (i *podTokenInventory) note(name string, err error) {
	if err != nil {
		i.problems = append(i.problems, name+": "+err.Error())
	} else {
		i.checked = append(i.checked, name)
	}
}
func (i podTokenInventory) digest() string {
	rows := append([]string{}, i.checked...)
	rows = append(rows, i.problems...)
	sort.Strings(rows)
	return podTokenHash([]byte(strings.Join(rows, "\n")))
}
func podTokenLedgerName(namespaceUID types.UID) string {
	sum := sha256.Sum256([]byte(namespaceUID))
	return "phorvex-quarantine-capacity-" + hex.EncodeToString(sum[:20])
}
func podTokenAMTDName(f podTokenFixture) string {
	return "phorvex-" + f.namespace + "-" + strings.TrimPrefix(f.name, "pod-token-")
}
func podTokenPhoenixNPName(namespace, pod string) string {
	legacy := namespace + "-" + pod + "-policy"
	if len(legacy) <= 63 && len(validation.IsValidLabelValue(legacy)) == 0 {
		return legacy
	}
	sum := sha256.Sum256([]byte("phoenix-quarantine-policy-v1\x00" + namespace + "\x00" + pod))
	return "amtd-q-" + hex.EncodeToString(sum[:24])
}
func podTokenNativeNPName(uid types.UID) string {
	return "phorvex-quarantine-" + podTokenHash([]byte(uid))
}
func podTokenOwnedAMTD(obj unstructured.Unstructured, f podTokenFixture) bool {
	a := obj.GetAnnotations()
	return obj.GetName() == podTokenAMTDName(f) && obj.GetUID() != "" &&
		obj.GetLabels()["app.kubernetes.io/managed-by"] == "phorvex" &&
		a["phorvex.ai/policy-name"] == f.name && a["phorvex.ai/policy-uid"] == string(f.policyUID) &&
		a["phorvex.ai/policy-generation"] == fmt.Sprint(f.policyGeneration) &&
		a["phorvex.ai/identity-version"] == "v1" && a["phorvex.ai/namespace-raw"] == f.namespace &&
		a["phorvex.ai/tenant-raw"] == strings.TrimPrefix(f.name, "pod-token-")
}
func podTokenGeneratedNP(np networkingv1.NetworkPolicy, f podTokenFixture, amtdUID types.UID) (bool, error) {
	for _, p := range []corev1.Pod{f.source, f.peer} {
		if p.UID == "" || p.Name == "" {
			continue
		}
		if np.Name == podTokenNativeNPName(p.UID) {
			if np.UID == "" || np.Labels["app.kubernetes.io/managed-by"] != "phorvex" ||
				len(np.OwnerReferences) != 1 || np.OwnerReferences[0].Kind != "Pod" || np.OwnerReferences[0].UID != p.UID ||
				np.Spec.PodSelector.MatchLabels["phorvex.ai/quarantined"] != string(p.UID) {
				return true, errors.New("native generated NetworkPolicy identity ambiguous")
			}
			return true, nil
		}
		if np.Name == podTokenPhoenixNPName(f.namespace, p.Name) {
			if np.UID == "" || amtdUID == "" || len(np.OwnerReferences) != 1 ||
				np.OwnerReferences[0].Kind != "AdaptiveMovingTargetDefense" || np.OwnerReferences[0].UID != amtdUID {
				return true, errors.New("Phoenix generated NetworkPolicy owner ambiguous")
			}
			return true, nil
		}
	}
	return false, nil
}
func podTokenProtectedInventory(ctx context.Context, env *core.Env, f podTokenFixture) (bool, int, error) {
	name := podTokenLedgerName(f.namespaceUID)
	if env.Config.PodBoundTokenFixture.ProtectedLedgerName != name {
		return false, 0, errors.New("protected capacity ledger name differs from actual namespace UID")
	}
	cm, err := env.Kube.CoreV1().ConfigMaps(env.Config.PodBoundTokenFixture.ManagerNamespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return true, 0, nil
	}
	if err != nil {
		return false, 0, errors.New("protected capacity ledger read unavailable")
	}
	if cm.UID == "" || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || cm.Labels["phorvex.ai/quarantine-capacity"] != "v1" || len(cm.Data["ledger"]) == 0 || len(cm.Data["ledger"]) > 768<<10 {
		return false, 0, errors.New("protected capacity ledger identity or bound invalid")
	}
	var ledger struct {
		Version      int                        `json:"version"`
		Namespace    string                     `json:"namespace"`
		NamespaceUID string                     `json:"namespaceUID"`
		Records      map[string]json.RawMessage `json:"records"`
	}
	if json.Unmarshal([]byte(cm.Data["ledger"]), &ledger) != nil || ledger.Version != 1 || ledger.Namespace != env.Config.Namespace || ledger.NamespaceUID != string(f.namespaceUID) || ledger.Records == nil || len(ledger.Records) > 128 {
		return false, 0, errors.New("protected capacity ledger scope invalid")
	}
	for uid, raw := range ledger.Records {
		if uid == "" || len(raw) > 8192 {
			return false, 0, errors.New("protected capacity ledger record invalid")
		}
		var row struct {
			OperationID  string   `json:"operationID"`
			Namespace    string   `json:"namespace"`
			PodUID       string   `json:"podUID"`
			NamespaceUID string   `json:"namespaceUID"`
			Pod          string   `json:"pod"`
			PolicyName   string   `json:"policyName"`
			PolicyUID    string   `json:"policyUID"`
			Backend      string   `json:"backend"`
			Phase        string   `json:"phase"`
			EventName    string   `json:"eventName"`
			EventUID     string   `json:"eventUID"`
			Objects      []string `json:"objects"`
			Detail       string   `json:"detail"`
		}
		if json.Unmarshal(raw, &row) != nil {
			return false, 0, errors.New("protected capacity ledger record JSON invalid")
		}
		operation, hexErr := hex.DecodeString(row.OperationID)
		if row.PodUID != uid || row.NamespaceUID != string(f.namespaceUID) ||
			row.Namespace != env.Config.Namespace || row.Pod == "" || row.PolicyName == "" || row.PolicyUID == "" || row.Backend == "" ||
			len(row.OperationID) != 40 || hexErr != nil || len(operation) != 20 || len(row.Objects) > 8 || len(row.Detail) > 512 {
			return false, 0, errors.New("protected capacity ledger record identity invalid")
		}
		switch row.Phase {
		case "dispatching", "ambiguous":
			if row.EventName != "" || row.EventUID != "" || len(row.Objects) != 0 {
				return false, 0, errors.New("protected capacity ledger pending record malformed")
			}
		case "native-effect":
			if row.EventName != "" || row.EventUID != "" {
				return false, 0, errors.New("protected capacity ledger native record malformed")
			}
		case "phoenix-event":
			if row.EventName == "" || row.EventUID == "" || len(row.Objects) != 0 {
				return false, 0, errors.New("protected capacity ledger event record malformed")
			}
		default:
			return false, 0, errors.New("protected capacity ledger phase unknown")
		}
		if uid == string(f.source.UID) {
			return false, len(ledger.Records), errors.New("protected reservation for original source UID remains")
		}
	}
	return true, len(ledger.Records), nil
}
func podTokenProtectedAbsence(ctx context.Context, env *core.Env, f podTokenFixture) (bool, error) {
	absent, _, err := podTokenProtectedInventory(ctx, env, f)
	return absent, err
}
func podTokenDeleteTyped(ctx context.Context, env *core.Env, f podTokenFixture, resource string, uid types.UID) error {
	if uid == "" {
		return errors.New("create ACK UID absent")
	}
	if got, ok := env.CreatedUID(resource, f.name); !ok || got != uid {
		return errors.New("create ACK authority missing")
	}
	if err := podTokenCreatePhase(env, "DELETE_INTENT", resource, f.name, uid); err != nil {
		return err
	}
	options := podTokenUIDDelete(uid)
	ns := env.Config.Namespace
	var err error
	switch resource {
	case "serviceaccounts":
		err = env.Kube.CoreV1().ServiceAccounts(ns).Delete(ctx, f.name, options)
	case "deployments":
		err = env.Kube.AppsV1().Deployments(ns).Delete(ctx, f.name, options)
	case "services":
		err = env.Kube.CoreV1().Services(ns).Delete(ctx, f.name, options)
	case "poddisruptionbudgets":
		err = env.Kube.PolicyV1().PodDisruptionBudgets(ns).Delete(ctx, f.name, options)
	case "roles":
		err = env.Kube.RbacV1().Roles(ns).Delete(ctx, f.name, options)
	case "rolebindings":
		err = env.Kube.RbacV1().RoleBindings(ns).Delete(ctx, f.name, options)
	case "phorvexpolicies", "podmonitors":
		obj := &unstructured.Unstructured{}
		if resource == "phorvexpolicies" {
			obj.SetGroupVersionKind(natsResponsePolicyGVK)
		} else {
			obj.SetGroupVersionKind(schema.GroupVersionKind{Group: "monitoring.coreos.com", Version: "v1", Kind: "PodMonitor"})
		}
		obj.SetNamespace(ns)
		obj.SetName(f.name)
		obj.SetUID(uid)
		err = env.Ctrl.Delete(ctx, obj, ctrlclient.Preconditions{UID: &uid})
	default:
		return errors.New("Pod token resource not in cleanup allowlist")
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if err := podTokenCreatePhase(env, "DELETE_ACK", resource, f.name, uid); err != nil {
		return err
	}
	return nil
}
func podTokenVerifyGone(ctx context.Context, env *core.Env, f podTokenFixture, resource string, uid types.UID) error {
	ns := env.Config.Namespace
	var gotUID types.UID
	var err error
	switch resource {
	case "serviceaccounts":
		var p *corev1.ServiceAccount
		p, err = env.Kube.CoreV1().ServiceAccounts(ns).Get(ctx, f.name, metav1.GetOptions{})
		if err == nil {
			gotUID = p.UID
		}
	case "services":
		var p *corev1.Service
		p, err = env.Kube.CoreV1().Services(ns).Get(ctx, f.name, metav1.GetOptions{})
		if err == nil {
			gotUID = p.UID
		}
	case "deployments":
		p, e := env.Kube.AppsV1().Deployments(ns).Get(ctx, f.name, metav1.GetOptions{})
		err = e
		if e == nil {
			gotUID = p.UID
		}
	case "poddisruptionbudgets":
		p, e := env.Kube.PolicyV1().PodDisruptionBudgets(ns).Get(ctx, f.name, metav1.GetOptions{})
		err = e
		if e == nil {
			gotUID = p.UID
		}
	case "roles":
		p, e := env.Kube.RbacV1().Roles(ns).Get(ctx, f.name, metav1.GetOptions{})
		err = e
		if e == nil {
			gotUID = p.UID
		}
	case "rolebindings":
		p, e := env.Kube.RbacV1().RoleBindings(ns).Get(ctx, f.name, metav1.GetOptions{})
		err = e
		if e == nil {
			gotUID = p.UID
		}
	case "phorvexpolicies", "podmonitors":
		obj := &unstructured.Unstructured{}
		if resource == "phorvexpolicies" {
			obj.SetGroupVersionKind(natsResponsePolicyGVK)
		} else {
			obj.SetGroupVersionKind(schema.GroupVersionKind{Group: "monitoring.coreos.com", Version: "v1", Kind: "PodMonitor"})
		}
		err = env.Ctrl.Get(ctx, ctrlclient.ObjectKey{Namespace: ns, Name: f.name}, obj)
		if err == nil {
			gotUID = obj.GetUID()
		}
	default:
		return errors.New("Pod token cleanup inventory resource unknown")
	}
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if gotUID != uid {
		return errors.New("same-name replacement exists during cleanup")
	}
	return errors.New("original resource still present")
}
func podTokenWaitAbsent(ctx context.Context, env *core.Env, f podTokenFixture, resource string, uid types.UID) error {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		err := podTokenVerifyGone(ctx, env, f, resource, uid)
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return err
		case <-tick.C:
		}
	}
}
func podTokenWaitDescendantsAbsent(ctx context.Context, env *core.Env, f podTokenFixture) error {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	selector := podTokenOwnerLabel + "=" + env.Config.PodBoundTokenFixture.Nonce
	for {
		pods, podErr := env.Kube.CoreV1().Pods(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector, Limit: 20})
		sets, setErr := env.Kube.AppsV1().ReplicaSets(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector, Limit: 20})
		if podErr == nil && setErr == nil && pods.Continue == "" && sets.Continue == "" && len(pods.Items) == 0 && len(sets.Items) == 0 {
			return nil
		}
		if podErr != nil && !apierrors.IsNotFound(podErr) {
			return podErr
		}
		if setErr != nil && !apierrors.IsNotFound(setErr) {
			return setErr
		}
		select {
		case <-ctx.Done():
			return errors.New("owned Pod or ReplicaSet descendant still present after bounded cleanup")
		case <-tick.C:
		}
	}
}
func podTokenWaitEndpointSlicesAbsent(ctx context.Context, env *core.Env, f podTokenFixture) error {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		slices, err := env.Kube.DiscoveryV1().EndpointSlices(env.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=" + f.name, Limit: 20})
		if err != nil || slices.Continue != "" {
			return errors.New("owned Service EndpointSlice inventory unavailable")
		}
		if len(slices.Items) == 0 {
			return nil
		}
		for _, slice := range slices.Items {
			if slice.UID == "" || len(slice.OwnerReferences) != 1 || slice.OwnerReferences[0].Kind != "Service" || slice.OwnerReferences[0].UID != f.serviceUID {
				return errors.New("same-name EndpointSlice owner ambiguous")
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("owned EndpointSlice remains after bounded Service cleanup")
		case <-tick.C:
		}
	}
}
func podTokenGeneratedChildrenAbsent(ctx context.Context, env *core.Env, f podTokenFixture) error {
	amtd := &unstructured.UnstructuredList{}
	amtd.SetGroupVersionKind(schema.GroupVersionKind{Group: "amtd.r6security.com", Version: "v1beta1", Kind: "AdaptiveMovingTargetDefenseList"})
	if err := env.Ctrl.List(ctx, amtd, ctrlclient.InNamespace(env.Config.Namespace)); err != nil || amtd.GetContinue() != "" {
		return errors.New("generated AMTD inventory unavailable")
	}
	for _, obj := range amtd.Items {
		if obj.GetName() == podTokenAMTDName(f) || obj.GetAnnotations()["phorvex.ai/policy-uid"] == string(f.policyUID) && f.policyUID != "" {
			return errors.New("generated AMTD still present")
		}
	}
	nps, err := env.Kube.NetworkingV1().NetworkPolicies(env.Config.Namespace).List(ctx, metav1.ListOptions{Limit: 200})
	if err != nil || nps.Continue != "" {
		return errors.New("generated NetworkPolicy inventory incomplete")
	}
	for _, np := range nps.Items {
		candidate, _ := podTokenGeneratedNP(np, f, "")
		if candidate {
			return errors.New("generated NetworkPolicy still present")
		}
	}
	return nil
}

// Delete only source/peer native policies or Phoenix policies whose standing
// AMTD carries the exact policy identity. A matching name with unknown owner
// is debt, never an object to adopt or sweep.
func podTokenDeleteGenerated(ctx context.Context, env *core.Env, f podTokenFixture) error {
	amtd := &unstructured.UnstructuredList{}
	amtd.SetGroupVersionKind(schema.GroupVersionKind{Group: "amtd.r6security.com", Version: "v1beta1", Kind: "AdaptiveMovingTargetDefenseList"})
	if err := env.Ctrl.List(ctx, amtd, ctrlclient.InNamespace(env.Config.Namespace)); err != nil || amtd.GetContinue() != "" {
		return errors.New("generated AMTD inventory unavailable before cleanup")
	}
	var owned *unstructured.Unstructured
	for _, obj := range amtd.Items {
		if obj.GetName() == podTokenAMTDName(f) || obj.GetAnnotations()["phorvex.ai/policy-uid"] == string(f.policyUID) && f.policyUID != "" {
			if !podTokenOwnedAMTD(obj, f) || owned != nil {
				return errors.New("generated standing AMTD identity ambiguous")
			}
			copy := obj.DeepCopy()
			owned = copy
		}
	}
	nps, err := env.Kube.NetworkingV1().NetworkPolicies(env.Config.Namespace).List(ctx, metav1.ListOptions{Limit: 200})
	if err != nil || nps.Continue != "" {
		return errors.New("generated NetworkPolicy inventory unavailable before cleanup")
	}
	for _, np := range nps.Items {
		var amtdUID types.UID
		if owned != nil {
			amtdUID = owned.GetUID()
		}
		candidate, identifyErr := podTokenGeneratedNP(np, f, amtdUID)
		if identifyErr != nil {
			return identifyErr
		}
		if !candidate {
			continue
		}
		if err := podTokenCreatePhase(env, "DELETE_INTENT", "networkpolicies", np.Name, np.UID); err != nil {
			return err
		}
		if err := env.Kube.NetworkingV1().NetworkPolicies(env.Config.Namespace).Delete(ctx, np.Name, podTokenUIDDelete(np.UID)); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if err := podTokenCreatePhase(env, "DELETE_ACK", "networkpolicies", np.Name, np.UID); err != nil {
			return err
		}
	}
	if owned != nil {
		uid := owned.GetUID()
		if err := podTokenCreatePhase(env, "DELETE_INTENT", "adaptivemovingtargetdefenses", owned.GetName(), uid); err != nil {
			return err
		}
		if err := env.Ctrl.Delete(ctx, owned, ctrlclient.Preconditions{UID: &uid}); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if err := podTokenCreatePhase(env, "DELETE_ACK", "adaptivemovingtargetdefenses", owned.GetName(), uid); err != nil {
			return err
		}
	}
	return nil
}
func podTokenCleanupFixture(ctx context.Context, env *core.Env, f podTokenFixture) (podTokenCleanup, bool, error) {
	inventory := podTokenInventory{}
	if f.name == "" || f.namespaceUID == "" {
		return podTokenCleanup{Status: "UNCONFIRMED"}, false, errors.New("fixture cleanup identity absent")
	}
	if err := env.Guard.AssertMutationAllowed(env.Config.Namespace); err != nil {
		return podTokenCleanup{Status: "UNCONFIRMED"}, false, err
	}
	ns, err := env.Kube.CoreV1().Namespaces().Get(ctx, env.Config.Namespace, metav1.GetOptions{})
	if err != nil || ns.UID != f.namespaceUID {
		return podTokenCleanup{Status: "UNCONFIRMED"}, false, errors.New("fixture namespace changed before cleanup")
	}
	order := []string{"phorvexpolicies", "podmonitors", "poddisruptionbudgets", "deployments", "rolebindings", "roles", "services", "serviceaccounts"}
	for _, resource := range order {
		uid := f.created[resource+"/"+f.name]
		if uid == "" {
			continue
		}
		err := podTokenDeleteTyped(ctx, env, f, resource, uid)
		if err == nil {
			waitCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			err = podTokenWaitAbsent(waitCtx, env, f, resource, uid)
			cancel()
		}
		inventory.note(resource, err)
		if resource == "services" {
			if err == nil {
				waitCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
				inventory.note("service-endpointslices", podTokenWaitEndpointSlicesAbsent(waitCtx, env, f))
				cancel()
			} else {
				inventory.note("service-endpointslices", errors.New("Service absence unconfirmed before EndpointSlice inventory"))
			}
		}
		if resource == "phorvexpolicies" {
			if err == nil {
				inventory.note("generated-delete", podTokenDeleteGenerated(ctx, env, f))
			} else {
				inventory.note("generated-delete", errors.New("policy absence unconfirmed before generated-child cleanup"))
			}
		}
	}
	// Deployment deletion should retire controller Pods and its exact ReplicaSet.
	if f.deploymentUID != "" {
		waitCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		inventory.note("pod-and-replicaset-descendants", podTokenWaitDescendantsAbsent(waitCtx, env, f))
		cancel()
	}
	generatedCtx, generatedDone := context.WithTimeout(ctx, 60*time.Second)
	var generatedErr error
	for {
		generatedErr = podTokenGeneratedChildrenAbsent(generatedCtx, env, f)
		if generatedErr == nil || generatedCtx.Err() != nil {
			break
		}
		select {
		case <-generatedCtx.Done():
		case <-time.After(2 * time.Second):
		}
	}
	generatedDone()
	inventory.note("generated", generatedErr)
	absent, err := podTokenProtectedAbsence(ctx, env, f)
	inventory.protectedAbsent = absent
	inventory.note("protected-reservation", err)
	status := "CONFIRMED_ABSENT"
	if len(inventory.problems) > 0 || !absent {
		status = "UNCONFIRMED"
	}
	result := podTokenCleanup{Status: status, InventorySHA256: inventory.digest(), Absent: status == "CONFIRMED_ABSENT"}
	if status != "CONFIRMED_ABSENT" {
		return result, absent, fmt.Errorf("Pod token cleanup unconfirmed: %s", strings.Join(inventory.problems, "; "))
	}
	return result, absent, nil
}

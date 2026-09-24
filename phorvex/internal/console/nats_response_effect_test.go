package console

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/audit"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

// This exercises the selected branch's actual Kubernetes reads, using the
// generated SecurityEvent, AMTD, adopted Pod, and single Phoenix NP contract
// observed in round 20. The fake API only supplies objects; it does not set a
// final readiness boolean or bypass the producer checks.
func TestNATSResponsePhoenixAPIObjectEffect(t *testing.T) {
	for _, tc := range []struct {
		name       string
		longPod    bool
		wrongOp    bool
		podControl bool
		npControl  bool
		wantReady  bool
	}{
		{name: "producer-shaped effect", wantReady: true},
		{name: "long producer-shaped effect", longPod: true, wantReady: true},
		{name: "wrong operation", wrongOp: true},
		{name: "Pod owner not controller", podControl: true},
		{name: "policy owner not controller", npControl: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nonce := strings.Repeat("a", 24)
			r := natsResponseRequest{Nonce: nonce, Namespace: natsFixtureNamespace, NamespaceUID: "namespace-uid",
				ClientPod: "source", ClientPodUID: "source-uid", PeerPodUID: "peer-uid",
				PolicyName: "nats-response-" + nonce, PolicyUID: "policy-uid", PolicyGeneration: 3}
			if tc.longPod {
				r.ClientPod = "nats-response-" + nonce + "-1234567890-abcde"
			}
			amtdName := "phorvex-" + r.Namespace + "-" + nonce
			npName := amtdv1beta1.QuarantineNetworkPolicyName(r.Namespace, r.ClientPod)
			amtdUID := types.UID("amtd-uid")
			owner := metav1.OwnerReference{APIVersion: "amtd.r6security.com/v1beta1", Kind: "AdaptiveMovingTargetDefense", Name: amtdName, UID: amtdUID, Controller: ptrNATSBool(true)}
			rsOwner := metav1.OwnerReference{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "consumer-rs", UID: "rs-uid", Controller: ptrNATSBool(true)}
			image := "observer@sha256:" + strings.Repeat("d", 64)
			prior := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: r.ClientPod, Namespace: r.Namespace, UID: types.UID(r.ClientPodUID),
				Labels: map[string]string{"fixture.phorvex.ai/role": "source"}, OwnerReferences: []metav1.OwnerReference{rsOwner}},
				Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{ContainerID: "containerd://source", ImageID: image}}}}
			current := prior.DeepCopy()
			current.OwnerReferences = []metav1.OwnerReference{owner}
			current.Labels["amtd.r6security.com/network-policy"] = npName
			if tc.podControl {
				current.OwnerReferences[0].Controller = ptrNATSBool(false)
			}
			peer := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "peer", Namespace: r.Namespace, UID: types.UID(r.PeerPodUID),
				Labels: map[string]string{"fixture.phorvex.ai/role": ""}, OwnerReferences: []metav1.OwnerReference{rsOwner}},
				Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
					ContainerStatuses: []corev1.ContainerStatus{{ContainerID: "containerd://peer", ImageID: image}}}}
			np := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: npName, Namespace: r.Namespace, UID: "np-uid", OwnerReferences: []metav1.OwnerReference{owner}},
				Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"amtd.r6security.com/network-policy": npName}},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}}}
			if tc.npControl {
				np.OwnerReferences[0].Controller = ptrNATSBool(false)
			}
			kc := fake.NewClientset(current, peer, np)
			operation := natsQuarantineOperationID(r.PolicyUID, r.Namespace, r.ClientPodUID)
			if tc.wrongOp {
				operation = strings.Repeat("0", 40)
			}
			event := map[string]any{"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent",
				"metadata": map[string]any{"name": "phorvex-quarantine-abcde", "uid": "generated-uid",
					"labels": map[string]string{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/tenant": nonce, "phorvex.ai/action": "quarantine"},
					"annotations": map[string]string{"phorvex.ai/identity-version": "v1", "phorvex.ai/namespace-raw": r.Namespace,
						"phorvex.ai/tenant-raw": nonce, "phorvex.ai/quarantine-target-uid": r.ClientPodUID,
						"phorvex.ai/quarantine-namespace-uid": r.NamespaceUID, "phorvex.ai/quarantine-operation": operation}},
				"spec": map[string]any{"targets": []string{r.Namespace + "/" + r.ClientPod},
					"rule": map[string]string{"type": "phorvex.quarantine", "source": "PhorvexController", "threatLevel": "high"}}}
			amtd := amtdv1beta1.AdaptiveMovingTargetDefense{TypeMeta: metav1.TypeMeta{APIVersion: "amtd.r6security.com/v1beta1", Kind: "AdaptiveMovingTargetDefense"},
				ObjectMeta: metav1.ObjectMeta{Name: amtdName, Namespace: r.Namespace, UID: amtdUID,
					Labels: map[string]string{"app.kubernetes.io/managed-by": "phorvex", "phorvex.ai/tenant": nonce},
					Annotations: map[string]string{"phorvex.ai/identity-version": "v1", "phorvex.ai/namespace-raw": r.Namespace,
						"phorvex.ai/tenant-raw": nonce, "phorvex.ai/policy-name": r.PolicyName,
						"phorvex.ai/policy-uid": r.PolicyUID, "phorvex.ai/policy-generation": "3"}},
				Spec: amtdv1beta1.AdaptiveMovingTargetDefenseSpec{PodSelector: map[string]string{"fixture.phorvex.ai/owner-nonce": nonce, "fixture.phorvex.ai/role": "source"},
					MatcherMode: amtdv1beta1.MatcherModeExact,
					Strategy: []amtdv1beta1.ResponseStrategy{
						{Rule: amtdv1beta1.Rule{Type: "phorvex.rotate", ThreatLevel: "high", Source: "PhorvexController"}, Action: amtdv1beta1.AMTDAction{Delete: &amtdv1beta1.DeleteAction{}}},
						{Rule: amtdv1beta1.Rule{Type: "phorvex.quarantine", ThreatLevel: "high", Source: "PhorvexController"}, Action: amtdv1beta1.AMTDAction{Quarantine: &amtdv1beta1.QuarantineAction{}}}}}}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case strings.Contains(req.URL.Path, "/securityevents/"):
					_ = json.NewEncoder(w).Encode(event)
				case strings.Contains(req.URL.Path, "/adaptivemovingtargetdefenses/"):
					_ = json.NewEncoder(w).Encode(amtd)
				default:
					http.Error(w, "unexpected fixed API path", http.StatusNotFound)
				}
			}))
			defer server.Close()
			policy := v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: r.PolicyName, Namespace: r.Namespace, UID: types.UID(r.PolicyUID), Generation: r.PolicyGeneration, ResourceVersion: "1"},
				Spec: v1alpha1.PhorvexPolicySpec{Tenant: nonce, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"fixture.phorvex.ai/owner-nonce": nonce, "fixture.phorvex.ai/role": "source"}},
					Mode: v1alpha1.ModeActive, Triggers: v1alpha1.TriggersSpec{EventDriven: true, ReactiveOnly: true},
					Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionRotate, v1alpha1.ActionQuarantine}}}}
			policyJSON, err := json.Marshal(policy)
			if err != nil {
				t.Fatal(err)
			}
			s := &Server{cfg: Config{ExperimentRESTConfig: &rest.Config{Host: server.URL}, Exec: func(_ time.Duration, bin string, _ ...string) (string, error) {
				if bin != "kubectl" {
					t.Fatal("unexpected executable")
				}
				return string(policyJSON), nil
			}}}
			rec := &audit.Record{Action: "quarantine", Selected: true, Actuated: true, DispatchOutcome: model.DispatchEmitted,
				Phoenix: &model.PhoenixForensics{EventName: "phorvex-quarantine-abcde", EventUID: "generated-uid", AMTDName: amtdName,
					AMTDNamespace: r.Namespace, RuleType: "phorvex.quarantine", RuleSource: "PhorvexController", RuleThreatLevel: "high"}}
			got, ready, err := s.natsQuarantineEffectOnce(context.Background(), kc, r, natsM0Proof{client: prior, peer: *peer}, rec)
			if tc.wantReady {
				if err != nil || !ready || got.PhoenixNetworkPolicyUID != "np-uid" {
					t.Fatalf("actual object-effect branch refused: %+v ready=%v err=%v", got, ready, err)
				}
			} else if ready {
				t.Fatalf("invalid producer shape admitted: %+v err=%v", got, err)
			}
		})
	}
}

func ptrNATSBool(v bool) *bool { return &v }

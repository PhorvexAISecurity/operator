package ingest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/endpointlease"
	"github.com/phorvex/phorvex/internal/model"
)

func TestEndpointLeaseIngestRequiresCurrentSourcePolicyAndFreshTrustedEvent(t *testing.T) {
	const source = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	const image = "example.test/proxy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const podUID = "44444444-4444-4444-8444-444444444444"
	const policyUID = "55555555-5555-4555-8555-555555555555"
	if err := ConfigureEndpointLeaseApprovedAuthority(source, image); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ConfigureEndpointLeaseApprovedAuthority("", "") })
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "vllm", Name: "vllm-a", UID: types.UID(podUID), Labels: map[string]string{"app": "vllm"}}}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "vllm", Name: "vllm-defense", UID: types.UID(policyUID), Generation: 1},
		Spec: v1alpha1.PhorvexPolicySpec{Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "vllm"}}}}
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod, policy).Build()
	now := time.Now().UTC().Truncate(time.Second)
	observation := endpointlease.Observation{Version: 1, ScenarioID: "ai2-endpoint-security", EvidenceSource: "TEST_INJECTED",
		PolicyName: "vllm-defense", PolicyUID: policyUID, PolicyGeneration: 1, TargetPodUID: podUID,
		ServiceUID: "11111111-1111-4111-8111-111111111111", PolicyConfigMapUID: "33333333-3333-4333-8333-333333333333",
		ProxySourceSHA256: source, SecretUID: "22222222-2222-4222-8222-222222222222",
		SeedSHA256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", PriorRevision: 0,
		RevokedClientHMAC:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RetainedClientHMAC: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		AcceptedStatus:     200, AcceptedResponseSHA256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		RetainedBaselineStatus: 200, RetainedBaselineResponseSHA256: "0000000000000000000000000000000000000000000000000000000000000000",
		ObservedAt: now.Add(-time.Second)}
	encode := func(o endpointlease.Observation) string {
		t.Helper()
		raw, err := json.Marshal(o)
		if err != nil {
			t.Fatal(err)
		}
		var values map[string]any
		if err := json.Unmarshal(raw, &values); err != nil {
			t.Fatal(err)
		}
		raw, err = json.Marshal(values)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	event := model.SecurityEventInfo{CreatedAt: now, Age: 0, Trust: TrustTrusted, TargetsPod: true,
		Type: endpointlease.RuleType, Source: "redteam", CreatorIdentity: endpointLeaseConsoleCreator,
		Name: "lease-event", UID: "66666666-6666-4666-8666-666666666666", ConsoleTargetPodUID: podUID,
		EndpointLeaseRaw: encode(observation)}
	live := endpointlease.Live{ServiceUID: observation.ServiceUID, PolicyUID: observation.PolicyConfigMapUID,
		SecretUID: observation.SecretUID, SeedSHA256: observation.SeedSHA256, SourceSHA256: source,
		State: endpointlease.State{Version: 1, Revision: 0, AllowedClientHMACs: []string{observation.RevokedClientHMAC, observation.RetainedClientHMAC}}}
	validations := 0
	validate := func(_ context.Context, _ client.Reader, gotPod, gotSource, gotImage string) (endpointlease.Live, error) {
		validations++
		if gotPod != podUID || gotSource != source || gotImage != image {
			t.Fatalf("unreviewed authority: %s %s %s", gotPod, gotSource, gotImage)
		}
		return live, nil
	}
	check := func(name string, e model.SecurityEventInfo, l endpointlease.Live, want bool) {
		t.Run(name, func(t *testing.T) {
			live = l
			p := model.Pod{Namespace: "vllm", Name: "vllm-a", UID: podUID}
			bindEndpointLeaseObservationWithValidator(context.Background(), reader, &p, []model.SecurityEventInfo{e}, validate)
			if p.HasBoundEndpointLeaseObservation() != want {
				t.Fatalf("bound=%v want=%v", p.HasBoundEndpointLeaseObservation(), want)
			}
		})
	}
	check("positive", event, live, true)
	duplicate := model.Pod{Namespace: "vllm", Name: "vllm-a", UID: podUID}
	bindEndpointLeaseObservationWithValidator(context.Background(), reader, &duplicate,
		[]model.SecurityEventInfo{event, event}, validate)
	if duplicate.HasBoundEndpointLeaseObservation() {
		t.Fatal("competing trusted assertions bound one credential fact")
	}
	wrongSource := event
	changed := observation
	changed.ProxySourceSHA256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	wrongSource.EndpointLeaseRaw = encode(changed)
	check("source", wrongSource, live, false)
	wrongUID := event
	wrongUID.ConsoleTargetPodUID = "old-pod"
	check("pod UID", wrongUID, live, false)
	wrongPolicy := event
	changed = observation
	changed.PolicyUID = "77777777-7777-4777-8777-777777777777"
	wrongPolicy.EndpointLeaseRaw = encode(changed)
	check("policy UID", wrongPolicy, live, false)
	old := event
	old.Age = 61 * time.Second
	check("stale", old, live, false)
	untrusted := event
	untrusted.Trust = TrustUntrusted
	check("untrusted", untrusted, live, false)
	changedState := live
	changedState.State.Revision = 1
	check("current revision", event, changedState, false)
	if validations != 3 {
		t.Fatalf("live validator called %d times, want positive, policy UID and revision cases", validations)
	}
}

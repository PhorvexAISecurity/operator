package actuator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/litellmclient"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type liteNativeFixture struct {
	c         client.Client
	seedSHA   string
	created   time.Time
	clientA   string
	clientB   string
	sourceSHA string
}

type litePolicyWriteError struct {
	client.Client
	err error
}

func (c litePolicyWriteError) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if obj.GetNamespace() == litellmclient.Namespace && obj.GetName() == litellmclient.PolicyConfigMapName {
		return c.err
	}
	return c.Client.Update(ctx, obj, opts...)
}

func newLiteNativeFixture(t *testing.T, variants ...string) liteNativeFixture {
	t.Helper()
	sourceFile := "gateway.py"
	gatewayImage := litellmclient.ApprovedGatewayImage
	if len(variants) > 0 {
		sourceFile = variants[0]
		gatewayImage = litellmclient.ApprovedRuntimeImage
	}
	sourcePath := "../../../build/test-harness/fixtures/litellm-live/" + sourceFile
	if sourceFile == "frozen-m1b" {
		sourcePath = "../../../deploy/helm/phorvex-stack/files/litellm-m1b/gateway-metrics-source-configmap.json"
	}
	code, e := os.ReadFile(sourcePath)
	if e != nil {
		t.Fatal(e)
	}
	if sourceFile == "frozen-m1b" {
		var cm corev1.ConfigMap
		if json.Unmarshal(code, &cm) != nil || cm.Immutable == nil || !*cm.Immutable || len(cm.Data) != 1 {
			t.Fatal("frozen M1b source ConfigMap differs")
		}
		code = []byte(cm.Data[litellmclient.SourceKey])
		if litellmclient.SHA256(code) != litellmclient.MetricsSourceSHA256 {
			t.Fatal("frozen M1b source bytes drifted")
		}
	}
	sourceSHA := litellmclient.SHA256(code)
	if !litellmclient.ApprovedSource(sourceSHA) {
		t.Fatalf("gateway source not pinned: %s", sourceSHA)
	}
	immutable := true
	seedSHA := strings.Repeat("c", 64)
	clientA := strings.Repeat("a", 64)
	clientB := strings.Repeat("b", 64)
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: litellmclient.ServiceName, Namespace: litellmclient.Namespace, UID: "service-uid"},
		Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "litellm"}, Ports: []corev1.ServicePort{{Port: 4000, TargetPort: intstr.FromInt32(4001)}}}}
	source := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: litellmclient.ApprovedSourceConfigMap(sourceSHA), Namespace: litellmclient.Namespace, UID: "source-uid"},
		Immutable: &immutable, Data: map[string]string{litellmclient.SourceKey: string(code)}}
	clients := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: litellmclient.ClientsConfigMapName, Namespace: litellmclient.Namespace, UID: "clients-uid"},
		Immutable: &immutable, Data: map[string]string{litellmclient.ClientsKey: `{"modelAlias":"gpt-4o-mini","seedSHA256":"` + seedSHA + `","version":2}`}}
	policyCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: litellmclient.PolicyConfigMapName, Namespace: litellmclient.Namespace, UID: "policy-cm-uid", ResourceVersion: "1"},
		Data: map[string]string{litellmclient.PolicyKey: `{"entries":[],"revision":0,"version":2}`}}
	journal := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: litellmclient.JournalName, Namespace: "phorvex-system", UID: "journal-uid",
		Labels: map[string]string{litellmclient.JournalLabel: "v2"}},
		Data: map[string]string{litellmclient.JournalKey: `{"receipts":[],"version":2}`}}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: "litellm-defense", Namespace: litellmclient.Namespace, UID: "select-uid", Generation: 1},
		Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive,
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{"r6th.io/rotation-target": "true"}},
			Actions:  v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionLiteLLMClientRevoke)}}}}
	objects := []client.Object{svc, source, clients, policyCM, journal, policy}
	for i, name := range []string{"litellm-a", "litellm-b"} {
		uid := types.UID("pod-" + string(rune('a'+i)))
		ip := "10.1.0." + string(rune('1'+i))
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: litellmclient.Namespace, UID: uid,
			Labels: map[string]string{"app": "litellm", "r6th.io/rotation-target": "true"},
			Annotations: map[string]string{litellmclient.SourceSHAAnnotation: sourceSHA,
				litellmclient.GatewayImageAnnotation: gatewayImage,
				litellmclient.PolicyUIDAnnotation:    "policy-cm-uid", litellmclient.ServiceUIDAnnotation: "service-uid",
				litellmclient.SeedSHAAnnotation: seedSHA}},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "litellm", Image: "backend@sha256:" + strings.Repeat(string(rune('d'+i)), 64)},
				{Name: litellmclient.GatewayContainerName, Image: gatewayImage, Command: []string{"python3", "-B", "/opt/phorvex/gateway.py"},
					Env: []corev1.EnvVar{{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}},
						{Name: "PHORVEX_LITELLM_CLIENTS_FILE", Value: "/etc/phorvex-litellm/clients.json"},
						{Name: "PHORVEX_LITELLM_TRIAL_SEED_FILE", Value: "/etc/phorvex-litellm-seed/seed"},
						{Name: "PHORVEX_LITELLM_POLICY_FILE", Value: "/etc/phorvex-litellm-policy/state.json"},
						{Name: "PHORVEX_LITELLM_STATUS_TOKEN_FILE", Value: "/etc/phorvex-litellm-status/token"},
						{Name: "PHORVEX_LITELLM_POLICY_CONFIGMAP_UID", Value: "policy-cm-uid"},
						{Name: "PHORVEX_LITELLM_GATEWAY_SOURCE_SHA256", Value: sourceSHA}},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "litellm-live-gateway-source", MountPath: "/opt/phorvex", ReadOnly: true},
						{Name: "litellm-live-clients", MountPath: "/etc/phorvex-litellm", ReadOnly: true},
						{Name: "litellm-live-policy", MountPath: "/etc/phorvex-litellm-policy", ReadOnly: true},
						{Name: "litellm-live-status", MountPath: "/etc/phorvex-litellm-status", ReadOnly: true},
						{Name: "litellm-live-trial-seed", MountPath: "/etc/phorvex-litellm-seed", ReadOnly: true}}}},
				Volumes: []corev1.Volume{
					{Name: "litellm-live-gateway-source", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: litellmclient.ApprovedSourceConfigMap(sourceSHA)}}}},
					{Name: "litellm-live-clients", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: litellmclient.ClientsConfigMapName}}}},
					{Name: "litellm-live-policy", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: litellmclient.PolicyConfigMapName}}}},
					{Name: "litellm-live-status", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "status-secret"}}},
					{Name: "litellm-live-trial-seed", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: litellmclient.TrialSeedSecretName}}}}},
			Status: corev1.PodStatus{PodIP: ip, ContainerStatuses: []corev1.ContainerStatus{
				{Name: "litellm", ImageID: "backend@sha256:" + strings.Repeat(string(rune('d'+i)), 64), Ready: true},
				{Name: litellmclient.GatewayContainerName, ImageID: gatewayImage, Ready: true}}}}
		if sourceSHA == litellmclient.AuthMetricsSourceSHA256 {
			addActuatorAuthMetricsBinding(pod)
		}
		objects = append(objects, pod)
	}
	ready := true
	port := int32(4001)
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "litellm-slice", Namespace: litellmclient.Namespace,
		Labels: map[string]string{discoveryv1.LabelServiceName: litellmclient.ServiceName}},
		Ports: []discoveryv1.EndpointPort{{Port: &port}}, Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.1.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: "litellm-a", UID: "pod-a"}},
			{Addresses: []string{"10.1.0.2"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: "litellm-b", UID: "pod-b"}}}}
	objects = append(objects, slice)
	return liteNativeFixture{c: fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(objects...).Build(),
		seedSHA: seedSHA, clientA: clientA, clientB: clientB, sourceSHA: sourceSHA,
		created: time.Now().UTC().Truncate(time.Second).Add(-time.Second)}
}

func (f liteNativeFixture) request(t *testing.T, hash, opID string) Request {
	t.Helper()
	eventName := "event-" + opID
	eventUID := "uid-" + opID
	observed := f.created.Add(950 * time.Millisecond)
	payload := litellmclient.Observation{Version: 2, ClientSHA256: hash, ConfigMapUID: "policy-cm-uid",
		ClientsConfigMapUID: "clients-uid", SeedSHA256: f.seedSHA, ServiceUID: "service-uid",
		TargetPodUID: "pod-a", PeerPodUID: "pod-b", RequestPath: "/v1/chat/completions",
		Objective: "ai2-query-extraction", ObservedAt: observed,
		PolicyName: "litellm-defense", PolicyUID: "select-uid", PolicyGeneration: 1}
	raw, _ := json.Marshal(payload)
	event := &amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: eventName, UID: types.UID(eventUID),
		CreationTimestamp: metav1.NewTime(f.created), Annotations: map[string]string{
			"phorvex.ai/creator-identity":       "system:serviceaccount:phorvex-system:phorvex-phorvex-console",
			model.ConsoleTargetPodUIDAnnotation: "pod-a", litellmclient.ObservationAnnotation: string(raw)}},
		Spec: amtdv1beta1.SecurityEventSpec{Targets: []string{"litellm/litellm-a"},
			Rule: amtdv1beta1.Rule{Type: litellmclient.RuleType, Source: "redteam"}}}
	if e := f.c.Create(context.Background(), event); e != nil {
		t.Fatal(e)
	}
	return Request{Namespace: litellmclient.Namespace, Pod: "litellm-a", TargetUID: "pod-a", Action: model.ActionLiteLLMClientRevoke,
		PolicyName: "litellm-defense", PolicyUID: "select-uid", PolicyGeneration: 1,
		OperationID: opID, TickID: "tick-" + opID,
		LiteLLMClientObservation: &model.LiteLLMClientObservation{EventName: eventName, EventUID: eventUID,
			CreatorIdentity: "system:serviceaccount:phorvex-system:phorvex-phorvex-console",
			TargetPodUID:    "pod-a", PeerPodUID: "pod-b", ClientSHA256: hash, ConfigMapUID: "policy-cm-uid",
			ClientsConfigMapUID: "clients-uid", SeedSHA256: f.seedSHA, ServiceUID: "service-uid",
			GatewaySourceSHA256: f.sourceSHA, PolicyName: "litellm-defense", PolicyUID: "select-uid",
			PolicyGeneration: 1, ObservedAt: observed}}
}

func (f liteNativeFixture) enactContext(t *testing.T) EnactCtx {
	t.Helper()
	return EnactCtx{Reader: f.c, Client: f.c, JournalNamespace: "phorvex-system",
		LiteLLMStatusToken: "private-test-token-1234567890123456",
		LiteLLMStatusTransport: litellmRoundTrip(func(req *http.Request) (*http.Response, error) {
			if req.URL.Path != "/v1/admission/state" || req.URL.Port() != "4002" ||
				req.Header.Get("Authorization") != "Bearer private-test-token-1234567890123456" {
				t.Fatal("actor status query differs")
			}
			sha := req.URL.Query().Get("clientSHA256")
			cm := &corev1.ConfigMap{}
			if e := f.c.Get(context.Background(), client.ObjectKey{Namespace: litellmclient.Namespace, Name: litellmclient.PolicyConfigMapName}, cm); e != nil {
				t.Fatal(e)
			}
			state, e := litellmclient.ParseState(cm.Data[litellmclient.PolicyKey])
			if e != nil {
				t.Fatal(e)
			}
			entry, active := state.Entry(sha)
			uid := "pod-a"
			if req.URL.Hostname() == "10.1.0.2" {
				uid = "pod-b"
			}
			body := map[string]any{"version": 2, "podUID": uid, "sourceSHA256": f.sourceSHA,
				"seedSHA256": f.seedSHA, "configMapUID": "policy-cm-uid", "clientSHA256": sha,
				"active": active, "revision": state.Revision, "operationId": entry.OperationID,
				"role": "attacker", "ready": true,
				"counters": map[string]int{"forwardedRequests": 1, "upstreamCompletions": 1,
					"deniedRequests": 0, "usageTokens": 2}}
			raw, _ := json.Marshal(body)
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
		})}
}

func TestLiteLLMNativeTwoDistinctFiresPreservePriorDenial(t *testing.T) {
	for _, sourceFile := range []string{"gateway.py", "frozen-m1b", "gateway_metrics.py"} {
		t.Run(sourceFile, func(t *testing.T) { liteLLMNativeTwoDistinctFiresPreservePriorDenial(t, sourceFile) })
	}
}

func liteLLMNativeTwoDistinctFiresPreservePriorDenial(t *testing.T, sourceFile string) {
	f := newLiteNativeFixture(t, sourceFile)
	ec := f.enactContext(t)
	for i, pair := range []struct{ hash, op string }{{f.clientA, "decision-1"}, {f.clientB, "decision-2"}} {
		req := f.request(t, pair.hash, pair.op)
		result, e := (litellmClientRevokeHandler{}).Enact(context.Background(), ec, req)
		if e != nil || !result.Emitted {
			t.Fatalf("Fire %d did not confirm exact native effect: %+v %v", i+1, result, e)
		}
		cm := &corev1.ConfigMap{}
		if e = f.c.Get(context.Background(), client.ObjectKey{Namespace: litellmclient.Namespace, Name: litellmclient.PolicyConfigMapName}, cm); e != nil {
			t.Fatal(e)
		}
		state, e := litellmclient.ParseState(cm.Data[litellmclient.PolicyKey])
		if e != nil || len(state.Entries) != i+1 {
			t.Fatalf("prior policy denial dropped: %+v %v", state, e)
		}
	}
	journal := &corev1.ConfigMap{}
	if e := f.c.Get(context.Background(), client.ObjectKey{Namespace: "phorvex-system", Name: litellmclient.JournalName}, journal); e != nil {
		t.Fatal(e)
	}
	doc, e := litellmReadJournal(journal)
	if e != nil || len(doc.Receipts) != 2 || doc.Receipts[0].Phase != "terminal-full" || doc.Receipts[1].Phase != "terminal-full" {
		t.Fatalf("protected prior receipts lost: %+v %v", doc, e)
	}
}

func TestLiteLLMPreparedOperationRecoversOnlyMatchingCASWithoutSecondWrite(t *testing.T) {
	for _, sourceFile := range []string{"gateway.py", "frozen-m1b", "gateway_metrics.py"} {
		t.Run(sourceFile, func(t *testing.T) { liteLLMPreparedOperationRecoversOnlyMatchingCASWithoutSecondWrite(t, sourceFile) })
	}
}

func liteLLMPreparedOperationRecoversOnlyMatchingCASWithoutSecondWrite(t *testing.T, sourceFile string) {
	ctx := context.Background()
	f := newLiteNativeFixture(t, sourceFile)
	req := f.request(t, f.clientA, "decision-recover")
	policyCM := &corev1.ConfigMap{}
	policyKey := client.ObjectKey{Namespace: litellmclient.Namespace, Name: litellmclient.PolicyConfigMapName}
	if e := f.c.Get(ctx, policyKey, policyCM); e != nil {
		t.Fatal(e)
	}
	initial, e := litellmclient.ParseState(policyCM.Data[litellmclient.PolicyKey])
	if e != nil {
		t.Fatal(e)
	}
	committed, e := initial.Append(f.clientA, req.OperationID)
	if e != nil {
		t.Fatal(e)
	}
	policyCM.Data[litellmclient.PolicyKey], e = litellmclient.EncodeState(committed)
	if e != nil || f.c.Update(ctx, policyCM) != nil {
		t.Fatal("setup committed one exact policy CAS")
	}
	if e := f.c.Get(ctx, policyKey, policyCM); e != nil {
		t.Fatal(e)
	}
	committedRV := policyCM.ResourceVersion
	o := req.LiteLLMClientObservation
	r := litellmRevokeReceipt{Version: 2, Phase: "prepared", PolicyName: req.PolicyName, PolicyUID: req.PolicyUID,
		PolicyGeneration: req.PolicyGeneration, TargetUID: req.TargetUID, PeerUID: o.PeerPodUID,
		EventName: o.EventName, EventUID: o.EventUID, ClientSHA256: o.ClientSHA256,
		ConfigMapUID: o.ConfigMapUID, ClientsConfigMapUID: o.ClientsConfigMapUID, SeedSHA256: o.SeedSHA256,
		ServiceUID: o.ServiceUID, SourceSHA256: o.GatewaySourceSHA256,
		OperationID: req.OperationID, SelectionDecisionID: req.OperationID, TickID: req.TickID}
	journal := &corev1.ConfigMap{}
	journalKey := client.ObjectKey{Namespace: "phorvex-system", Name: litellmclient.JournalName}
	if e := f.c.Get(ctx, journalKey, journal); e != nil {
		t.Fatal(e)
	}
	doc, e := litellmReadJournal(journal)
	if e != nil {
		t.Fatal(e)
	}
	doc, e = doc.append(r)
	if e != nil {
		t.Fatal(e)
	}
	journal.Data[litellmclient.JournalKey] = litellmJournalRaw(doc)
	if e := f.c.Update(ctx, journal); e != nil {
		t.Fatal(e)
	}
	ec := f.enactContext(t)
	blocked := ec
	blocked.LiteLLMStatusTransport = litellmRoundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	})
	first, e := recoverLiteLLMClientOperations(ctx, blocked, nil)
	if e != nil || len(first) != 1 || first[0].Err == nil || first[0].Outcome == "confirmed" {
		t.Fatalf("unconfirmed gateway status earned recovery: %+v %v", first, e)
	}
	second, e := recoverLiteLLMClientOperations(ctx, ec, nil)
	if e != nil || len(second) != 1 || second[0].Err != nil || second[0].Outcome != "confirmed" {
		t.Fatalf("same committed operation did not recover: %+v %v", second, e)
	}
	if e := f.c.Get(ctx, policyKey, policyCM); e != nil || policyCM.ResourceVersion != committedRV {
		t.Fatalf("recovery repeated policy CAS: RV=%s want=%s err=%v", policyCM.ResourceVersion, committedRV, e)
	}
	if e := f.c.Get(ctx, journalKey, journal); e != nil {
		t.Fatal(e)
	}
	doc, e = litellmReadJournal(journal)
	if e != nil || len(doc.Receipts) != 1 || doc.Receipts[0].Phase != "terminal-full" {
		t.Fatalf("protected recovery journal not terminal: %+v %v", doc, e)
	}
	third, e := recoverLiteLLMClientOperations(ctx, ec, nil)
	if e != nil || len(third) != 0 {
		t.Fatalf("terminal operation replayed: %+v %v", third, e)
	}
}

func TestLiteLLMDefinitiveConflictRetiresIntentButTimeoutDoesNot(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		wantPhase string
	}{
		{"conflict", apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, litellmclient.PolicyConfigMapName, errors.New("resource version changed")), "aborted"},
		{"ambiguous timeout", context.DeadlineExceeded, "prepared"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLiteNativeFixture(t)
			ec := f.enactContext(t)
			ec.Client = litePolicyWriteError{Client: f.c, err: tc.err}
			req := f.request(t, f.clientA, "decision-failed")
			result, e := (litellmClientRevokeHandler{}).Enact(context.Background(), ec, req)
			if e == nil || result.Emitted {
				t.Fatalf("failed policy CAS earned native effect: %+v %v", result, e)
			}
			policy := &corev1.ConfigMap{}
			if e := f.c.Get(context.Background(), client.ObjectKey{Namespace: litellmclient.Namespace, Name: litellmclient.PolicyConfigMapName}, policy); e != nil {
				t.Fatal(e)
			}
			state, e := litellmclient.ParseState(policy.Data[litellmclient.PolicyKey])
			if e != nil || state.Revision != 0 || len(state.Entries) != 0 {
				t.Fatalf("failed policy CAS had effect: %+v %v", state, e)
			}
			journal := &corev1.ConfigMap{}
			if e := f.c.Get(context.Background(), client.ObjectKey{Namespace: "phorvex-system", Name: litellmclient.JournalName}, journal); e != nil {
				t.Fatal(e)
			}
			doc, e := litellmReadJournal(journal)
			if e != nil || len(doc.Receipts) != 1 || doc.Receipts[0].Phase != tc.wantPhase {
				t.Fatalf("protected receipt phase: %+v %v", doc, e)
			}
			if tc.wantPhase == "aborted" {
				if doc.Receipts[0].AbortReason != "definitive-policy-conflict" || !doc.matchesPolicy(state) {
					t.Fatalf("abort did not join proof of no policy write: %+v", doc)
				}
				fresh := f.request(t, f.clientB, "decision-after-abort")
				good := f.enactContext(t)
				if got, err := (litellmClientRevokeHandler{}).Enact(context.Background(), good, fresh); err != nil || !got.Emitted {
					t.Fatalf("fresh owned credential remained wedged after definitive conflict: %+v %v", got, err)
				}
			} else if doc.matchesPolicy(state) {
				t.Fatal("ambiguous policy timeout was silently retired")
			}
		})
	}
}

func TestLiteLLMPendingJournalFencesBothBoundPodsOnly(t *testing.T) {
	ctx := context.Background()
	f := newLiteNativeFixture(t)
	req := f.request(t, f.clientA, "decision-pending")
	o := req.LiteLLMClientObservation
	r := litellmRevokeReceipt{Version: 2, Phase: "prepared", PolicyName: req.PolicyName, PolicyUID: req.PolicyUID,
		PolicyGeneration: req.PolicyGeneration, TargetUID: req.TargetUID, PeerUID: o.PeerPodUID,
		EventName: o.EventName, EventUID: o.EventUID, ClientSHA256: o.ClientSHA256,
		ConfigMapUID: o.ConfigMapUID, ClientsConfigMapUID: o.ClientsConfigMapUID, SeedSHA256: o.SeedSHA256,
		ServiceUID: o.ServiceUID, SourceSHA256: o.GatewaySourceSHA256,
		OperationID: req.OperationID, SelectionDecisionID: req.OperationID, TickID: req.TickID}
	journal := &corev1.ConfigMap{}
	key := client.ObjectKey{Namespace: "phorvex-system", Name: litellmclient.JournalName}
	if e := f.c.Get(ctx, key, journal); e != nil {
		t.Fatal(e)
	}
	doc, e := litellmReadJournal(journal)
	if e != nil {
		t.Fatal(e)
	}
	doc, e = doc.append(r)
	if e != nil {
		t.Fatal(e)
	}
	journal.Data[litellmclient.JournalKey] = litellmJournalRaw(doc)
	if e := f.c.Update(ctx, journal); e != nil {
		t.Fatal(e)
	}
	for _, uid := range []string{"pod-a", "pod-b"} {
		pending, e := PendingLiteLLMClientOperation(ctx, f.c, "phorvex-system", "litellm", uid)
		if e != nil || !pending {
			t.Fatalf("bound Pod %s not fenced: %v %v", uid, pending, e)
		}
	}
	for _, scope := range [][2]string{{"litellm", "pod-c"}, {"other", "pod-a"}} {
		pending, e := PendingLiteLLMClientOperation(ctx, f.c, "phorvex-system", scope[0], scope[1])
		if e != nil || pending {
			t.Fatalf("unrelated Pod fenced: %v %v", pending, e)
		}
	}
	if e := f.c.Get(ctx, key, journal); e != nil {
		t.Fatal(e)
	}
	doc, e = litellmReadJournal(journal)
	if e != nil {
		t.Fatal(e)
	}
	doc.Receipts[0].Phase = "aborted"
	doc.Receipts[0].AbortReason = "definitive-policy-conflict"
	journal.Data[litellmclient.JournalKey] = litellmJournalRaw(doc)
	if e := f.c.Update(ctx, journal); e != nil {
		t.Fatal(e)
	}
	pending, e := PendingLiteLLMClientOperation(ctx, f.c, "phorvex-system", "litellm", "pod-a")
	if e != nil || pending {
		t.Fatalf("retired intent still fenced: %v %v", pending, e)
	}
	if e := f.c.Get(ctx, key, journal); e != nil {
		t.Fatal(e)
	}
	journal.Data[litellmclient.JournalKey] = `{"receipts":"malformed","version":2}`
	if e := f.c.Update(ctx, journal); e != nil {
		t.Fatal(e)
	}
	pending, e = PendingLiteLLMClientOperation(ctx, f.c, "phorvex-system", "litellm", "pod-a")
	if e == nil || !pending {
		t.Fatalf("malformed protected journal not refused: %v %v", pending, e)
	}
	if e := f.c.Delete(ctx, journal); e != nil {
		t.Fatal(e)
	}
	pending, e = PendingLiteLLMClientOperation(ctx, f.c, "phorvex-system", "litellm", "pod-a")
	if e == nil || !pending {
		t.Fatalf("missing journal with installed source not refused: %v %v", pending, e)
	}
	source := &corev1.ConfigMap{}
	if e := f.c.Get(ctx, client.ObjectKey{Namespace: litellmclient.Namespace, Name: litellmclient.SourceConfigMapName}, source); e != nil {
		t.Fatal(e)
	}
	if e := f.c.Delete(ctx, source); e != nil {
		t.Fatal(e)
	}
	pending, e = PendingLiteLLMClientOperation(ctx, f.c, "phorvex-system", "litellm", "pod-a")
	if e != nil || pending {
		t.Fatalf("uninstalled profile fenced unrelated LiteLLM target: %v %v", pending, e)
	}
}

func TestLiteLLMNewSourceJournalAndInvalidObservationControls(t *testing.T) {
	for _, sourceFile := range []string{"frozen-m1b", "gateway_metrics.py"} {
		t.Run(sourceFile, func(t *testing.T) { liteLLMNewSourceJournalAndInvalidObservationControls(t, sourceFile) })
	}
}

func liteLLMNewSourceJournalAndInvalidObservationControls(t *testing.T, sourceFile string) {
	ctx := context.Background()
	f := newLiteNativeFixture(t, sourceFile)
	req := f.request(t, f.clientA, "invalid-source")
	req.LiteLLMClientObservation.GatewaySourceSHA256 = strings.Repeat("d", 64)
	if _, err := (litellmClientRevokeHandler{}).Enact(ctx, f.enactContext(t), req); err == nil {
		t.Fatal("unapproved observation accepted")
	}
	req.LiteLLMClientObservation.GatewaySourceSHA256 = litellmclient.ApprovedSourceSHA256
	if _, err := (litellmClientRevokeHandler{}).Enact(ctx, f.enactContext(t), req); err == nil {
		t.Fatal("old observation against new live source accepted")
	}
	journal := &corev1.ConfigMap{}
	if err := f.c.Get(ctx, client.ObjectKey{Namespace: "phorvex-system", Name: litellmclient.JournalName}, journal); err != nil {
		t.Fatal(err)
	}
	if err := f.c.Delete(ctx, journal); err != nil {
		t.Fatal(err)
	}
	if pending, err := PendingLiteLLMClientOperation(ctx, f.c, "phorvex-system", "litellm", "pod-a"); !pending || err == nil {
		t.Fatal("missing journal with only new source did not fence")
	}
}

func addActuatorAuthMetricsBinding(p *corev1.Pod) {
	group, mode, optional := int64(10001), int32(0440), false
	p.Spec.SecurityContext = &corev1.PodSecurityContext{FSGroup: &group}
	p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: litellmclient.MetricsTokenVolumeName, VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
		SecretName: "phorvex-litellm-gateway-metrics-token-v1", Optional: &optional, DefaultMode: &mode, Items: []corev1.KeyToPath{{Key: "token", Path: "token"}},
	}}})
	gateway := &p.Spec.Containers[1]
	gateway.Env = append(gateway.Env, corev1.EnvVar{Name: "PHORVEX_LITELLM_METRICS_ENABLED", Value: "1"},
		corev1.EnvVar{Name: "PHORVEX_LITELLM_METRICS_TOKEN_FILE", Value: litellmclient.MetricsTokenFilePath},
		corev1.EnvVar{Name: "POD_NAME", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.name"}}},
		corev1.EnvVar{Name: "POD_NAMESPACE", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"}}})
	gateway.VolumeMounts = append(gateway.VolumeMounts, corev1.VolumeMount{Name: litellmclient.MetricsTokenVolumeName, MountPath: litellmclient.MetricsTokenMountPath, ReadOnly: true})
}

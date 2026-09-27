package actuator

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/endpointlease"
	"github.com/phorvex/phorvex/internal/model"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

type leaseHTTP func(*http.Request) (*http.Response, error)

func (f leaseHTTP) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type leaseCountingClient struct {
	client.Client
	policyWrites, journalWrites int
	failPolicy                  string
}

func (c *leaseCountingClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if cm, ok := obj.(*corev1.ConfigMap); ok {
		if cm.Namespace == endpointlease.Namespace && cm.Name == endpointlease.PolicyConfigMapName {
			c.policyWrites++
			switch c.failPolicy {
			case "conflict":
				return apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, cm.Name, errors.New("test conflict"))
			case "lost-ack":
				if err := c.Client.Update(ctx, obj, opts...); err != nil {
					return err
				}
				return errors.New("lost policy update reply")
			}
		}
		if cm.Name == endpointlease.JournalName {
			c.journalWrites++
		}
	}
	return c.Client.Update(ctx, obj, opts...)
}

type leaseFixture struct {
	c                               *leaseCountingClient
	source, proxyImage, engineImage string
	request                         Request
	old, retained                   string
	oldInFlight                     uint64
}

func newLeaseFixture(t *testing.T) *leaseFixture {
	t.Helper()
	r := leaseTestReceipt(t)
	sourceFiles := []string{"guardrail_proxy.py", "dual_server.py", "endpoint_lease.py", "drain_v11.py", "drain_v11_init.py"}
	data := map[string]string{}
	for _, name := range sourceFiles {
		data[name] = "# " + name + "\n"
	}
	source := endpointlease.SourceSHA256([]byte(data[sourceFiles[0]]), []byte(data[sourceFiles[1]]), []byte(data[sourceFiles[2]]), []byte(data[sourceFiles[3]]), []byte(data[sourceFiles[4]]))
	proxyImage := "registry.example/proxy@sha256:" + strings.Repeat("d", 64)
	engineImage := "registry.example/engine@sha256:" + strings.Repeat("e", 64)
	state := endpointlease.State{Version: 1, ServiceUID: r.ServiceUID, ProxySourceSHA256: source, SecretUID: r.SecretUID, SeedSHA256: r.SeedSHA256,
		AllowedClientHMACs: []string{r.RevokedClientHMAC, r.RetainedClientHMAC}, RevokedClientHMACs: []string{}}
	stateRaw, err := endpointlease.EncodeState(state)
	if err != nil {
		t.Fatal(err)
	}
	immutable := true
	creator := endpointLeaseConsoleCreator
	ann := map[string]string{endpointlease.SourceConfigMapAnnotation: endpointlease.SourceConfigMapName, endpointlease.SourceSHAAnnotation: source,
		endpointlease.PolicyUIDAnnotation: r.PolicyConfigMapUID, endpointlease.EventCreatorAnnotation: creator}
	env := []corev1.EnvVar{}
	for k, v := range map[string]string{"PHORVEX_ENDPOINT_LEASE_REQUIRED": "true", "PHORVEX_ENDPOINT_LEASE_SECRET_DIR": "/etc/phorvex/endpoint-lease-keys",
		"PHORVEX_ENDPOINT_LEASE_POLICY_CONFIGMAP_UID": r.PolicyConfigMapUID, "PHORVEX_ENDPOINT_LEASE_SECRET_UID": r.SecretUID,
		"PHORVEX_ENDPOINT_LEASE_SERVICE_UID": r.ServiceUID, "PHORVEX_ENDPOINT_LEASE_SOURCE_SHA256": source} {
		env = append(env, corev1.EnvVar{Name: k, Value: v})
	}
	env = append(env, corev1.EnvVar{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}})
	mounts := []corev1.VolumeMount{{Name: "lease-keys", MountPath: "/etc/phorvex/endpoint-lease-keys", ReadOnly: true}}
	for _, name := range sourceFiles {
		mounts = append(mounts, corev1.VolumeMount{Name: "lease-source", MountPath: "/src/" + name, SubPath: name, ReadOnly: true})
	}
	spec := corev1.PodSpec{Volumes: []corev1.Volume{{Name: "lease-source", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: endpointlease.SourceConfigMapName}}}},
		{Name: "lease-keys", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: endpointlease.SecretName}}}},
		Containers: []corev1.Container{{Name: "vllm", Image: engineImage, Args: []string{"--model", "fixture", "--host", "127.0.0.1", "--port", "8001"},
			Env: []corev1.EnvVar{{Name: "VLLM_API_KEY", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "vllm-control"}, Key: "api-key"}}}}},
			{Name: endpointlease.ProxyContainerName, Image: proxyImage, Command: []string{"python3", "-B", "/src/dual_server.py"}, Env: env, VolumeMounts: mounts}}}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: endpointlease.ServiceName, Namespace: endpointlease.Namespace, UID: types.UID(r.ServiceUID)},
		Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "vllm"}, Ports: []corev1.ServicePort{{Port: 8000, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(8000)}}}}
	policyCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: endpointlease.PolicyConfigMapName, Namespace: endpointlease.Namespace, UID: types.UID(r.PolicyConfigMapUID), ResourceVersion: "1"}, Data: map[string]string{endpointlease.PolicyKey: stateRaw}}
	sourceCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: endpointlease.SourceConfigMapName, Namespace: endpointlease.Namespace, UID: types.UID("77777777-7777-4777-8777-777777777777")}, Immutable: &immutable, Data: data}
	journal := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: endpointlease.JournalName, Namespace: "phorvex-system", UID: types.UID("88888888-8888-4888-8888-888888888888"), ResourceVersion: "1", Labels: map[string]string{endpointlease.JournalLabel: "v1"}},
		Data: map[string]string{endpointlease.JournalKey: endpointLeaseJournalRaw(endpointLeaseJournal{Version: 1, Receipts: []endpointLeaseReceipt{}})}}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: endpointlease.ServiceName, Namespace: endpointlease.Namespace, UID: types.UID("99999999-9999-4999-8999-999999999999")},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Annotations: ann}, Spec: spec}}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "vllm-rs", Namespace: endpointlease.Namespace, UID: types.UID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: endpointlease.ServiceName, UID: dep.UID, Controller: leaseBool(true)}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: r.TargetPodName, Namespace: endpointlease.Namespace, UID: types.UID(r.TargetPodUID), Labels: map[string]string{"app": "vllm"}, Annotations: ann,
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: leaseBool(true)}}}, Spec: spec,
		Status: corev1.PodStatus{PodIP: "10.0.0.7", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			ContainerStatuses: []corev1.ContainerStatus{{Name: "vllm", Ready: true, ContainerID: "containerd://engine", ImageID: "containerd://sha256:" + strings.Repeat("e", 64)},
				{Name: endpointlease.ProxyContainerName, Ready: true, ContainerID: "containerd://old-proxy", ImageID: "containerd://sha256:" + strings.Repeat("d", 64)}}}}
	port := int32(8000)
	proto := corev1.ProtocolTCP
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "vllm-slice", Namespace: endpointlease.Namespace, Labels: map[string]string{discoveryv1.LabelServiceName: endpointlease.ServiceName},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: endpointlease.ServiceName, UID: svc.UID, Controller: leaseBool(true)}}},
		Ports: []discoveryv1.EndpointPort{{Port: &port, Protocol: &proto}}, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.7"}, Conditions: discoveryv1.EndpointConditions{Ready: leaseBool(true)},
			TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: endpointlease.Namespace, Name: pod.Name, UID: pod.UID}}}}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: r.PolicyName, Namespace: endpointlease.Namespace, UID: types.UID(r.PolicyUID), Generation: 1},
		Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "vllm"}},
			Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionType(model.ActionEndpointLeaseRevoke)}}}}
	observed := time.Now().UTC().Truncate(time.Second)
	obs := endpointlease.Observation{Version: 1, ScenarioID: "ai2-endpoint-security", EvidenceSource: "TEST_INJECTED", PolicyName: r.PolicyName, PolicyUID: r.PolicyUID, PolicyGeneration: 1,
		TargetPodUID: r.TargetPodUID, ServiceUID: r.ServiceUID, PolicyConfigMapUID: r.PolicyConfigMapUID, ProxySourceSHA256: source, SecretUID: r.SecretUID, SeedSHA256: r.SeedSHA256,
		PriorRevision: 0, RevokedClientHMAC: r.RevokedClientHMAC, RetainedClientHMAC: r.RetainedClientHMAC, AcceptedStatus: 200, AcceptedResponseSHA256: strings.Repeat("f", 64),
		RetainedBaselineStatus: 200, RetainedBaselineResponseSHA256: strings.Repeat("f", 64), ObservedAt: observed}
	obsRaw := endpointLeaseCanonical(obs)
	event := &amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: r.EventName, UID: types.UID(r.EventUID), CreationTimestamp: metav1.NewTime(observed),
		Annotations: map[string]string{"phorvex.ai/creator-identity": creator, model.ConsoleTargetPodUIDAnnotation: r.TargetPodUID, endpointlease.ObservationAnnotation: obsRaw}},
		Spec: amtdv1beta1.SecurityEventSpec{Targets: []string{endpointlease.Namespace + "/" + r.TargetPodName}, Rule: amtdv1beta1.Rule{Type: endpointlease.RuleType, Source: "redteam"}}}
	objects := []client.Object{svc, policyCM, sourceCM, journal, dep, rs, pod, slice, policy, event}
	base := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(objects...).Build()
	f := &leaseFixture{c: &leaseCountingClient{Client: base}, source: source, proxyImage: proxyImage, engineImage: engineImage, old: r.RevokedClientHMAC, retained: r.RetainedClientHMAC}
	f.request = Request{Action: model.ActionEndpointLeaseRevoke, Namespace: endpointlease.Namespace, Pod: r.TargetPodName, TargetUID: r.TargetPodUID, PolicyName: r.PolicyName, PolicyUID: r.PolicyUID, PolicyGeneration: 1,
		OperationID: r.OperationID, TickID: r.TickID, EndpointLeaseObservation: &model.EndpointLeaseObservation{EventName: r.EventName, EventUID: r.EventUID, CreatorIdentity: creator,
			ScenarioID: obs.ScenarioID, EvidenceSource: obs.EvidenceSource, PolicyName: r.PolicyName, PolicyUID: r.PolicyUID, PolicyGeneration: 1, TargetPodUID: r.TargetPodUID,
			ServiceUID: r.ServiceUID, PolicyConfigMapUID: r.PolicyConfigMapUID, ProxySourceSHA256: source, SecretUID: r.SecretUID, SeedSHA256: r.SeedSHA256,
			PriorRevision: 0, RevokedClientHMAC: r.RevokedClientHMAC, RetainedClientHMAC: r.RetainedClientHMAC, AcceptedStatus: 200, AcceptedResponseSHA256: obs.AcceptedResponseSHA256,
			RetainedBaselineStatus: 200, RetainedBaselineResponseSHA256: obs.RetainedBaselineResponseSHA256, ObservedAt: observed}}
	return f
}

func leaseBool(v bool) *bool { return &v }

func (f *leaseFixture) enactCtx(t *testing.T) EnactCtx {
	t.Helper()
	return EnactCtx{Client: f.c, Reader: f.c, JournalNamespace: "phorvex-system", EndpointLeaseApprovedSourceSHA256: f.source,
		EndpointLeaseApprovedProxyImage: f.proxyImage, EndpointLeaseApprovedEngineImage: f.engineImage, EndpointLeaseStatusToken: strings.Repeat("t", 32),
		EndpointLeaseStatusTransport: leaseHTTP(func(req *http.Request) (*http.Response, error) {
			if req.URL.Scheme != "https" || req.URL.Host != "10.0.0.7:8443" || req.URL.Path != endpointlease.StatusPath || req.Header.Get("Authorization") != "Bearer "+strings.Repeat("t", 32) {
				t.Fatalf("untrusted status route: %s", req.URL.String())
			}
			cm := &corev1.ConfigMap{}
			if err := f.c.Get(context.Background(), client.ObjectKey{Namespace: endpointlease.Namespace, Name: endpointlease.PolicyConfigMapName}, cm); err != nil {
				t.Fatal(err)
			}
			state, err := endpointlease.ParseState(cm.Data[endpointlease.PolicyKey])
			if err != nil {
				t.Fatal(err)
			}
			status := endpointlease.Status{Version: 1, PodUID: f.request.TargetUID, ServiceUID: state.ServiceUID, ProxySourceSHA256: state.ProxySourceSHA256,
				PolicyConfigMapUID: string(cm.UID), SecretUID: state.SecretUID, SeedSHA256: state.SeedSHA256, Revision: state.Revision, LastOperationID: state.LastOperationID,
				StateSHA256: endpointlease.SHA256([]byte(cm.Data[endpointlease.PolicyKey])), RevokedClientHMAC: f.old, RetainedClientHMAC: f.retained,
				RevokedClientAllowed: state.Revision == 0, RetainedClientAllowed: true, OldRevisionInFlight: f.oldInFlight, Ready: true}
			raw := endpointLeaseCanonical(status)
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(raw))}, nil
		})}
}

func TestEndpointLeaseOneCASAndProtectedTerminal(t *testing.T) {
	f := newLeaseFixture(t)
	result, err := (endpointLeaseRevokeHandler{}).Enact(context.Background(), f.enactCtx(t), f.request)
	if err != nil || !result.Emitted || f.c.policyWrites != 1 || f.c.journalWrites != 2 {
		t.Fatalf("one CAS/terminal: %+v err=%v writes=%d/%d", result, err, f.c.policyWrites, f.c.journalWrites)
	}
	cm := &corev1.ConfigMap{}
	_ = f.c.Get(context.Background(), client.ObjectKey{Namespace: "phorvex-system", Name: endpointlease.JournalName}, cm)
	doc, err := endpointLeaseReadJournal(cm)
	if err != nil || len(doc.Receipts) != 1 || doc.Receipts[0].Phase != "terminal-full" || doc.Receipts[0].DecisionID != f.request.OperationID {
		t.Fatalf("terminal receipt: %+v %v", doc, err)
	}
}

func TestEndpointLeaseConflictAbortsOnlyWithOldPolicyProof(t *testing.T) {
	f := newLeaseFixture(t)
	f.c.failPolicy = "conflict"
	result, err := (endpointLeaseRevokeHandler{}).Enact(context.Background(), f.enactCtx(t), f.request)
	if err == nil || result.Emitted || f.c.policyWrites != 1 {
		t.Fatalf("conflict must not claim effect: %+v %v", result, err)
	}
	cm := &corev1.ConfigMap{}
	_ = f.c.Get(context.Background(), client.ObjectKey{Namespace: "phorvex-system", Name: endpointlease.JournalName}, cm)
	doc, err := endpointLeaseReadJournal(cm)
	if err != nil || doc.Receipts[0].Phase != "aborted" {
		t.Fatalf("proved no-write abort: %+v %v", doc, err)
	}
}

func TestEndpointLeaseLostCASReplyRecoversWithoutReplay(t *testing.T) {
	f := newLeaseFixture(t)
	f.c.failPolicy = "lost-ack"
	result, err := (endpointLeaseRevokeHandler{}).Enact(context.Background(), f.enactCtx(t), f.request)
	if err == nil || result.Emitted || f.c.policyWrites != 1 {
		t.Fatalf("lost reply claimed effect: %+v %v", result, err)
	}
	cm := &corev1.ConfigMap{}
	_ = f.c.Get(context.Background(), client.ObjectKey{Namespace: "phorvex-system", Name: endpointlease.JournalName}, cm)
	doc, err := endpointLeaseReadJournal(cm)
	if err != nil || doc.Receipts[0].Phase != "prepared" {
		t.Fatalf("lost reply must retain intent: %+v %v", doc, err)
	}
	ec := f.enactCtx(t)
	recovery := RecoveryEvent{}
	if err := recoverPreparedEndpointLease(context.Background(), ec, doc.Receipts[0], &recovery); err != nil || f.c.policyWrites != 1 {
		t.Fatalf("restart replayed policy CAS or refused exact readback: %v writes=%d", err, f.c.policyWrites)
	}
	_ = f.c.Get(context.Background(), client.ObjectKey{Namespace: "phorvex-system", Name: endpointlease.JournalName}, cm)
	doc, err = endpointLeaseReadJournal(cm)
	if err != nil || doc.Receipts[0].Phase != "terminal-full" {
		t.Fatalf("recovered journal: %+v %v", doc, err)
	}
}

func TestEndpointLeaseOldStreamAndIncarnationCannotInheritTerminal(t *testing.T) {
	for _, mutation := range []string{"old-stream", "new-container"} {
		t.Run(mutation, func(t *testing.T) {
			f := newLeaseFixture(t)
			f.c.failPolicy = "lost-ack"
			_, _ = (endpointLeaseRevokeHandler{}).Enact(context.Background(), f.enactCtx(t), f.request)
			journal := &corev1.ConfigMap{}
			_ = f.c.Get(context.Background(), client.ObjectKey{Namespace: "phorvex-system", Name: endpointlease.JournalName}, journal)
			doc, err := endpointLeaseReadJournal(journal)
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "old-stream" {
				f.oldInFlight = 1
			} else {
				pod := &corev1.Pod{}
				_ = f.c.Get(context.Background(), client.ObjectKey{Namespace: endpointlease.Namespace, Name: f.request.Pod}, pod)
				pod.Status.ContainerStatuses[1].ContainerID = "containerd://replacement"
				if err := f.c.Status().Update(context.Background(), pod); err != nil {
					t.Fatal(err)
				}
			}
			if err := endpointLeaseReadback(context.Background(), f.enactCtx(t), doc.Receipts[0]); err == nil {
				t.Fatal("old stream or replacement proxy inherited terminal proof")
			}
			if f.c.policyWrites != 1 {
				t.Fatalf("replayed CAS on uncertainty: %d", f.c.policyWrites)
			}
		})
	}
}

func TestEndpointLeasePrivateStatusRejectsRedirectAndMalformedBody(t *testing.T) {
	for _, mode := range []string{"redirect", "html", "stale"} {
		t.Run(mode, func(t *testing.T) {
			f := newLeaseFixture(t)
			live, err := endpointlease.ValidateLive(context.Background(), f.c, f.request.TargetUID, f.source, f.proxyImage, f.engineImage)
			if err != nil {
				t.Fatal(err)
			}
			ec := f.enactCtx(t)
			ec.EndpointLeaseStatusTransport = leaseHTTP(func(*http.Request) (*http.Response, error) {
				switch mode {
				case "redirect":
					return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://elsewhere.example/"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
				case "html":
					return &http.Response{StatusCode: 404, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: io.NopCloser(strings.NewReader("not found"))}, nil
				default:
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"ready":true}`))}, nil
				}
			})
			if err := endpointLeaseStatus(context.Background(), ec, live.Pods[0], live, f.old, f.retained, true, false); err == nil {
				t.Fatal("untrusted status response accepted")
			}
		})
	}
}

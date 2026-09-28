package actuator

import (
	"context"
	"errors"
	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voiceadmissionpolicy"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	"io"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"net/http"
	"os"
	"path/filepath"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"strings"
	"testing"
	"time"
)

type admissionSourceFixture struct {
	pod                  *corev1.Pod
	dep                  *appsv1.Deployment
	source, legacy, rule *corev1.ConfigMap
	ingress              *networkingv1.Ingress
	code, image          string
}

func admissionServingSourceFixture(t *testing.T) admissionSourceFixture {
	t.Helper()
	if voiceadmissionpolicy.ReviewedAdmissionImage == "" || voiceadmissionpolicy.ReviewedAdmissionSourceSHA256 == "" {
		t.Skip("reviewed runtime/image publication pending")
	}
	const Namespace = voiceadmissionpolicy.Namespace
	const WrapperPath = voiceadmissionpolicy.WrapperPath
	const ConfigMapName = voiceadmissionpolicy.ConfigMapName
	const RuleKey = voiceadmissionpolicy.RuleKey
	const WrapperConfigMapAnnotation = voiceadmissionpolicy.WrapperConfigMapAnnotation
	const SourceSHAAnnotation = voiceadmissionpolicy.SourceSHAAnnotation
	const AuthProfileSHAAnnotation = voiceadmissionpolicy.AuthProfileSHAAnnotation
	const LegacyBundleSHAAnnotation = voiceadmissionpolicy.LegacyBundleSHAAnnotation
	const PolicyConfigMapAnnotation = voiceadmissionpolicy.PolicyConfigMapAnnotation
	const testUID = "11111111-1111-4111-8111-111111111111"
	type AuthProfile = voiceadmissionpolicy.AuthProfile
	Digest := voiceadmissionpolicy.Digest
	SourceHashes := voiceadmissionpolicy.SourceHashes
	testRule := func() voiceadmissionpolicy.Rule { s, _, _, _ := admissionReadbackFixture(); return s.rule }

	yes := true
	uid := types.UID(testUID)
	sha := strings.Repeat("a", 64)
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: Namespace, Name: "voice-bot", UID: uid}}
	owner := metav1.OwnerReference{APIVersion: "apps/v1", Kind: "Deployment", Name: dep.Name, UID: uid, Controller: &yes}
	cm := func(name string) *corev1.ConfigMap {
		return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: Namespace, Name: name, UID: uid, ResourceVersion: "1", OwnerReferences: []metav1.OwnerReference{owner}}, Immutable: &yes, Data: map[string]string{}}
	}
	legacy := cm("")
	files := []string{"bot.py", "voice_memory_policy.py", "voice_output_policy.py", "voice_mcp_policy.py"}
	parts := []string{}
	for _, name := range files {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", "build", "integrations", "voice-memory", name))
		if err != nil {
			t.Fatal(err)
		}
		legacy.Data[name] = string(b)
		parts = append(parts, string(b))
	}
	legacySHA := Digest([]byte(strings.Join(parts, "\x00")))
	legacy.Name = "voice-memory-source-" + legacySHA[:12]
	profile := AuthProfile{Version: 1, DeploymentUID: testUID, PublicHost: "voicebot.phorvex.ai", WebsocketSigningURLs: []string{"wss://voicebot.phorvex.ai/ws"}, WebhookSigningURL: "https://voicebot.phorvex.ai/", TwilioSecretName: "voice-secrets", AuthTokenSHA256: sha}
	source := cm("")
	source.Data = map[string]string{"auth-profile.json": string(profile.Bytes())}
	for _, name := range []string{"entry.py", "policy.py"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", "build", "integrations", "voice-admission", name))
		if err != nil {
			t.Fatal(err)
		}
		source.Data[name] = string(b)
	}
	code, bundle, profileSHA, err := SourceHashes(source)
	if err != nil {
		t.Fatal(err)
	}
	source.Name = "voice-admission-source-" + bundle[:12]
	r := testRule()
	r.AdmissionSourceSHA256 = code
	r.LegacyBundleSHA256 = legacySHA
	r.AuthProfileSHA256 = profileSHA
	rule := cm(ConfigMapName)
	rule.Immutable = nil
	rule.Data = map[string]string{RuleKey: string(r.Bytes())}
	image := voiceadmissionpolicy.ReviewedAdmissionImage
	c := corev1.Container{Name: "bot", Image: image, Command: []string{"python3", "-B", WrapperPath + "/entry.py"}, WorkingDir: "/app", EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "voice-secrets"}}}}}
	for name, value := range map[string]string{"PUBLIC_HOST": profile.PublicHost, "VOICE_ADMISSION_SOURCE_SHA256": code, "VOICE_ADMISSION_DEPLOYMENT_UID": testUID, "VOICE_ADMISSION_POLICY_CM_UID": testUID, "VOICE_ADMISSION_SECURITY_POLICY_UID": testUID, "VOICE_ADMISSION_WRAPPER_CM_UID": testUID, "VOICE_ADMISSION_AUTH_PROFILE_SHA256": profileSHA, "VOICE_ADMISSION_LEGACY_BUNDLE_SHA256": legacySHA, "VOICE_MEMORY_POLICY_REQUIRED": "true", "VOICE_REFUND_POLICY_REQUIRED": "true", "VOICE_MCP_POLICY_REQUIRED": "true", "VOICE_OUTPUT_POLICY_REQUIRED": "true"} {
		c.Env = append(c.Env, corev1.EnvVar{Name: name, Value: value})
	}
	for name, value := range map[string]string{"VOICE_MEMORY_POLICY_DIR": "/etc/phorvex/voice-memory-policy", "VOICE_REFUND_POLICY_DIR": "/etc/phorvex/voice-refund-policy", "VOICE_MCP_POLICY_DIR": "/etc/phorvex/voice-mcp-tool-policy", "VOICE_OUTPUT_POLICY_DIR": "/etc/phorvex/voice-output-policy", "VOICE_MEMORY_STATE_DIR": "/var/lib/phorvex-voice-memory", "VOICE_MEMORY_STATE_TOKEN_FILE": "/etc/phorvex/voice-memory-state-token/token"} {
		c.Env = append(c.Env, corev1.EnvVar{Name: name, Value: value})
	}
	c.Env = append(c.Env, corev1.EnvVar{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}})
	spec := corev1.PodSpec{Containers: []corev1.Container{c}, ServiceAccountName: "voice-bot-admission-reader", AutomountServiceAccountToken: &yes}
	for _, v := range []struct{ name, cm, path string }{{"source", source.Name, WrapperPath}, {"legacy", legacy.Name, ""}, {"memory", "voice-memory-policy", "/etc/phorvex/voice-memory-policy"}, {"refund", "voice-refund-policy", "/etc/phorvex/voice-refund-policy"}, {"mcp", "voice-mcp-tool-policy", "/etc/phorvex/voice-mcp-tool-policy"}, {"output", "voice-output-policy", "/etc/phorvex/voice-output-policy"}} {
		spec.Volumes = append(spec.Volumes, corev1.Volume{Name: v.name, VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: v.cm}}}})
		if v.path != "" {
			spec.Containers[0].VolumeMounts = append(spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: v.name, MountPath: v.path, ReadOnly: true})
		}
	}
	for _, name := range files {
		spec.Containers[0].VolumeMounts = append(spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "legacy", MountPath: "/app/" + name, SubPath: name, ReadOnly: true})
	}
	spec.Volumes = append(spec.Volumes, corev1.Volume{Name: "token", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "voice-memory-state-token"}}}, corev1.Volume{Name: "state", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}})
	spec.Containers[0].VolumeMounts = append(spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "token", MountPath: "/etc/phorvex/voice-memory-state-token", ReadOnly: true}, corev1.VolumeMount{Name: "state", MountPath: "/var/lib/phorvex-voice-memory"})
	annotations := map[string]string{"phorvex.ai/voice-output-source-configmap": legacy.Name, voiceadmissionpolicy.EventCreatorAnnotation: voiceadmissionpolicy.Creator, WrapperConfigMapAnnotation: source.Name, SourceSHAAnnotation: code, AuthProfileSHAAnnotation: profileSHA, LegacyBundleSHAAnnotation: legacySHA, PolicyConfigMapAnnotation: ConfigMapName}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: Namespace, Name: "voice-bot", UID: uid, Annotations: annotations}, Spec: spec}
	dep.Spec.Template = corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Annotations: annotations}, Spec: *spec.DeepCopy()}
	class := "alb"
	pathType := networkingv1.PathTypePrefix
	ingress := &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: Namespace, Name: "voice-bot-public", Annotations: map[string]string{"alb.ingress.kubernetes.io/scheme": "internet-facing", "alb.ingress.kubernetes.io/ssl-redirect": "443"}}, Spec: networkingv1.IngressSpec{IngressClassName: &class, Rules: []networkingv1.IngressRule{{Host: profile.PublicHost, IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{Path: "/", PathType: &pathType, Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "voice-bot", Port: networkingv1.ServiceBackendPort{Number: 8080}}}}}}}}}}}
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "bot", Ready: true, ImageID: "docker-pullable://" + image, ContainerID: "containerd://fixture", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.Now()}}}}
	return admissionSourceFixture{pod, dep, source, legacy, rule, ingress, code, image}
}

func admissionNativeFixture(t *testing.T) (admissionSourceFixture, client.Client, EnactCtx, Request, *bool) {
	t.Helper()
	ctx := context.Background()
	f := admissionServingSourceFixture(t)
	uid := f.dep.UID
	labels := map[string]string{"app": "voice-bot"}
	yes := true
	port := int32(8080)
	protocol := corev1.ProtocolTCP
	f.dep.Spec.Selector = &metav1.LabelSelector{MatchLabels: labels}
	f.dep.Spec.Template.Labels = labels
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot-rs", Namespace: "voice", UID: types.UID("22222222-2222-4222-8222-222222222222"), OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(f.dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}}
	f.pod.Labels = labels
	f.pod.ResourceVersion = "1"
	f.pod.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(rs, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))}
	f.pod.Status = corev1.PodStatus{PodIP: "192.0.2.1", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: f.pod.Status.ContainerStatuses}
	peer := f.pod.DeepCopy()
	peer.Name = "voice-bot-peer"
	peer.UID = types.UID("77777777-7777-4777-8777-777777777777")
	peer.Status.PodIP = "192.0.2.2"
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot", Namespace: "voice", UID: uid}, Spec: corev1.ServiceSpec{Selector: labels, Ports: []corev1.ServicePort{{Port: 8080, TargetPort: intstr.FromInt32(8080), Protocol: corev1.ProtocolTCP}}}}
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "voice-bot-endpoints", Namespace: "voice", Labels: map[string]string{discoveryv1.LabelServiceName: svc.Name}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(svc, corev1.SchemeGroupVersion.WithKind("Service"))}}, AddressType: discoveryv1.AddressTypeIPv4, Ports: []discoveryv1.EndpointPort{{Port: &port, Protocol: &protocol}}}
	for _, p := range []*corev1.Pod{f.pod, peer} {
		slice.Endpoints = append(slice.Endpoints, discoveryv1.Endpoint{Addresses: []string{p.Status.PodIP}, Conditions: discoveryv1.EndpointConditions{Ready: &yes}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "voice", Name: p.Name, UID: p.UID}})
	}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Name: "voice-defense", Namespace: "voice", UID: uid, Generation: 1}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: labels}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionVoiceSessionAdmissionEnforce}}}}
	token := strings.Repeat("x", 32)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "voice-memory-state-token", Namespace: "voice"}, Data: map[string][]byte{"token": []byte(token)}}
	journal := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: voiceadmissionpolicy.JournalName, Namespace: "operator", UID: uid, ResourceVersion: "1", Labels: map[string]string{voiceadmissionpolicy.JournalLabel: "v1"}}, Data: map[string]string{"receipts.json": string((voiceadmissionpolicy.Journal{Version: 1, Receipts: []voiceadmissionpolicy.Receipt{}}).Bytes())}}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "voice"}}
	c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(namespace, f.dep, rs, f.pod, peer, f.source, f.legacy, f.rule, f.ingress, svc, slice, policy, secret, journal).Build()
	prior, err := voiceadmissionpolicy.Parse(f.rule.Data[voiceadmissionpolicy.RuleKey])
	if err != nil {
		t.Fatal(err)
	}
	_, _, session, _ := admissionReadbackFixture()
	session.AdmissionSourceSHA256 = prior.AdmissionSourceSHA256
	session.LegacyBundleSHA256 = prior.LegacyBundleSHA256
	session.AuthProfileSHA256 = prior.AuthProfileSHA256
	session.AdmissionRuleSHA256 = prior.SHA256()
	session.ConnectedAtUnixMs = time.Now().UnixMilli() - 2000
	session.ObservedAtUnixMs = time.Now().UnixMilli() - 1000
	provider := voiceadmissionpolicy.ProviderEvidence{Version: 1, SessionID: session.SessionID, RunSHA256: session.RunSHA256, CallSIDHash: session.CallSIDHash, PodUID: session.PodUID, DeploymentUID: session.DeploymentUID, AdmissionSourceSHA256: session.AdmissionSourceSHA256, LegacyBundleSHA256: session.LegacyBundleSHA256, AuthProfileSHA256: session.AuthProfileSHA256, ObservedAtUnixMs: session.ObservedAtUnixMs, STTFrames: 1, ModelTextFrames: 1, ModelCompletions: 1, TTSAudioFrames: 1, TTSAudioBytes: 960, STTTextSHA256: strings.Repeat("a", 64), ModelTextSHA256: strings.Repeat("b", 64)}
	a := voiceadmissionpolicy.EventAssertion{Version: 1, ScenarioID: voiceadmissionpolicy.ScenarioID, CaseID: "unsigned-live", RunSHA256: session.RunSHA256, SessionID: session.SessionID, DeploymentUID: session.DeploymentUID, PodUID: session.PodUID, AdmissionSourceSHA256: session.AdmissionSourceSHA256, LegacyBundleSHA256: session.LegacyBundleSHA256, AuthProfileSHA256: session.AuthProfileSHA256, PolicyCMUID: string(f.rule.UID), PolicyResourceVersion: f.rule.ResourceVersion, RuleSHA256: prior.SHA256(), SecurityPolicyUID: string(uid), SecurityPolicyGeneration: 1, ObservedAtUnixMs: session.ObservedAtUnixMs, EvidenceSource: "TEST_INJECTED", Observed: true, SentAudioFrames: session.SentAudioFrames, SentAudioBytes: session.SentAudioBytes, ReceiptSHA256: voiceadmissionpolicy.Digest(voiceadmissionpolicy.CanonicalBytes(session)), ProviderEvidenceSHA256: voiceadmissionpolicy.Digest(voiceadmissionpolicy.CanonicalBytes(provider))}
	eventUID := "66666666-6666-4666-8666-666666666666"
	event := &amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: "admission-loss", UID: types.UID(eventUID), CreationTimestamp: metav1.NewTime(time.Now().Add(-500 * time.Millisecond)), Annotations: map[string]string{"phorvex.ai/creator-identity": voiceadmissionpolicy.Creator, model.ConsoleTargetPodUIDAnnotation: string(f.pod.UID), voiceadmissionpolicy.EventAnnotation: string(voiceadmissionpolicy.CanonicalBytes(a))}}, Spec: amtdv1beta1.SecurityEventSpec{Targets: []string{"voice/" + f.pod.Name}, Rule: amtdv1beta1.Rule{Type: voiceadmissionpolicy.EventType, Source: "redteam"}}}
	if err := c.Create(ctx, event); err != nil {
		t.Fatal(err)
	}
	req := Request{Namespace: "voice", Pod: f.pod.Name, TargetUID: string(f.pod.UID), PolicyName: policy.Name, PolicyUID: string(uid), PolicyGeneration: 1, TickID: "tick", OperationID: "selection", Action: model.ActionVoiceSessionAdmissionEnforce, VoiceAdmissionObservation: &model.VoiceAdmissionObservation{EventName: event.Name, EventUID: eventUID, CreatorIdentity: voiceadmissionpolicy.Creator, TargetPodUID: string(f.pod.UID), DeploymentUID: string(uid), ConfigMapUID: string(f.rule.UID), ConfigMapResourceVersion: f.rule.ResourceVersion, SourceSHA256: prior.AdmissionSourceSHA256, RuleSHA256: prior.SHA256(), SessionID: session.SessionID, PolicyName: policy.Name, PolicyUID: string(uid), PolicyGeneration: 1, Assertion: a}}
	cleaned := false
	transport := admissionRoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer "+token {
			return nil, errors.New("unexpected token")
		}
		current := &corev1.ConfigMap{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voiceadmissionpolicy.ConfigMapName}, current); err != nil {
			return nil, err
		}
		rule, err := voiceadmissionpolicy.Parse(current.Data[voiceadmissionpolicy.RuleKey])
		if err != nil {
			return nil, err
		}
		var body []byte
		switch request.URL.Path {
		case voiceadmissionpolicy.StatePath:
			podUID := string(f.pod.UID)
			if request.URL.Hostname() == peer.Status.PodIP {
				podUID = string(peer.UID)
			}
			state := voiceadmissionpolicy.State{Version: 1, PodUID: podUID, DeploymentUID: rule.DeploymentUID, PolicyCMUID: string(current.UID), PolicyResourceVersion: current.ResourceVersion, RuleSHA256: rule.SHA256(), Revision: rule.Revision, Mode: rule.Mode, OperationID: rule.OperationID, AdmissionSourceSHA256: rule.AdmissionSourceSHA256, LegacyBundleSHA256: rule.LegacyBundleSHA256, AuthProfileSHA256: rule.AuthProfileSHA256, ObservedAtUnixMs: time.Now().UnixMilli(), ActiveSigned: 1, Settled: rule.Revision == 1, DelegatesCompleted: 8, DisconnectsDelivered: 1}
			if rule.Revision == 0 {
				state.ActiveUnsigned = 1
			}
			body = voiceadmissionpolicy.CanonicalBytes(state)
		case "/v1/voice-session-admission/evidence":
			if cleaned {
				return nil, errors.New("owned evidence cleaned")
			}
			body = voiceadmissionpolicy.CanonicalBytes(voiceadmissionpolicy.Evidence{Session: session, Provider: provider})
		case "/v1/voice-session-admission/session":
			if cleaned {
				return nil, errors.New("owned lifecycle cleaned")
			}
			live := session
			live.ObservedAtUnixMs = time.Now().UnixMilli()
			if rule.Revision == 1 {
				live.Stage = "closed"
				live.DisconnectDelivered = true
				live.DelegateCompleted = true
				live.DisconnectedAtUnixMs = live.ObservedAtUnixMs
			}
			body = voiceadmissionpolicy.CanonicalBytes(live)
		default:
			return nil, errors.New("unexpected private route")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})
	return f, c, EnactCtx{Reader: c, Client: c, JournalNamespace: "operator", VoiceAdmissionTransport: transport, VoiceAdmissionEnabled: true}, req, &cleaned
}

func TestAdmissionNativeOneWayAllPodBarrierAndCleanupRetry(t *testing.T) {
	_, c, ec, req, cleaned := admissionNativeFixture(t)
	ctx := context.Background()
	result, err := (voiceAdmissionHandler{}).Enact(ctx, ec, req)
	if err != nil || !result.Emitted {
		t.Fatalf("enforce: %+v %v", result, err)
	}
	_, journal, err := voiceAdmissionJournalGet(ctx, c, "operator")
	if err != nil || journal.Receipts[0].Phase != "terminal-full" || len(journal.Receipts[0].PodReceipts) != 2 {
		t.Fatalf("missing all-serving-Pod terminal receipt: %+v %v", journal, err)
	}
	*cleaned = true
	result, err = (voiceAdmissionHandler{}).Enact(ctx, ec, req)
	if err != nil || !result.Emitted || !strings.Contains(result.Note, "histor") {
		t.Fatalf("protected same-op retry after cleanup: %+v %v", result, err)
	}
	other := req
	other.OperationID = "new-selection"
	if _, err = (voiceAdmissionHandler{}).Enact(ctx, ec, other); err == nil {
		t.Fatal("new decision appended/reset one-way operation")
	}
	cm := &corev1.ConfigMap{}
	if err = c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voiceadmissionpolicy.ConfigMapName}, cm); err != nil {
		t.Fatal(err)
	}
	rule, _ := voiceadmissionpolicy.Parse(cm.Data[voiceadmissionpolicy.RuleKey])
	if rule.Revision != 1 || rule.OperationID != journal.Receipts[0].OperationID {
		t.Fatal("enforced history changed on retry")
	}
}

type admissionLostAckClient struct {
	client.Client
	lost bool
}

func (c *admissionLostAckClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if err := c.Client.Update(ctx, obj, opts...); err != nil {
		return err
	}
	if obj.GetNamespace() == "voice" && obj.GetName() == voiceadmissionpolicy.ConfigMapName && !c.lost {
		c.lost = true
		return errors.New("policy acknowledgment lost after durable CAS")
	}
	return nil
}

func TestAdmissionNativeLostCASAckRecoversOriginalSelection(t *testing.T) {
	_, c, ec, req, _ := admissionNativeFixture(t)
	ctx := context.Background()
	ec.Client = &admissionLostAckClient{Client: c}
	result, err := (voiceAdmissionHandler{}).Enact(ctx, ec, req)
	if err == nil || result.MutationKind != "partial" {
		t.Fatalf("lost acknowledgment incorrectly settled: %+v %v", result, err)
	}
	_, before, err := voiceAdmissionJournalGet(ctx, c, "operator")
	if err != nil || before.Receipts[0].Phase != "prepared" {
		t.Fatalf("original prepared receipt lost: %+v %v", before, err)
	}
	ec.Client = c
	events, err := recoverVoiceAdmissionOperations(ctx, ec, func(a model.Action) bool { return a == model.ActionVoiceSessionAdmissionEnforce })
	if err != nil || len(events) != 1 || events[0].Outcome != "confirmed" {
		t.Fatalf("stored selection recovery: %+v %v", events, err)
	}
	_, after, err := voiceAdmissionJournalGet(ctx, c, "operator")
	if err != nil || after.Receipts[0].Phase != "terminal-full" || after.Receipts[0].OperationID != before.Receipts[0].OperationID || after.Receipts[0].SelectionDecisionID != req.OperationID {
		t.Fatalf("recovery replaced historical selection: %+v %v", after, err)
	}
}

func TestAdmissionPendingFencePreservesUninstalledLegacyVoice(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: "legacy", UID: types.UID("11111111-1111-4111-8111-111111111111")}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "bot", Command: []string{"python3", "-B", "/app/bot.py"}}}}}
	c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(pod).Build()
	blocked, err := PendingVoiceAdmissionOperation(context.Background(), c, "operator", "voice", pod.Name, string(pod.UID))
	if err != nil || blocked {
		t.Fatalf("new uninstalled fence changed legacy behavior: %v %v", blocked, err)
	}
	pod.Annotations = map[string]string{voiceadmissionpolicy.PolicyConfigMapAnnotation: voiceadmissionpolicy.ConfigMapName}
	if err := c.Update(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	// An installed target whose authoritative journal/policy disappeared is unknown.
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: voiceadmissionpolicy.ConfigMapName}}
	if err := c.Create(context.Background(), cm); err != nil {
		t.Fatal(err)
	}
	blocked, err = PendingVoiceAdmissionOperation(context.Background(), c, "operator", "voice", pod.Name, string(pod.UID))
	if err == nil || !blocked {
		t.Fatalf("installed missing history escaped fence: %v %v", blocked, err)
	}
}

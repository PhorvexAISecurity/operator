package actuator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/voicemcppolicy"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
)

type voiceMCPFixture struct {
	client        client.Client
	req           Request
	ec            EnactCtx
	rule          voicemcppolicy.Rule
	voicePod      *corev1.Pod
	mcpPod        *corev1.Pod
	stateRevision uint64
}

type voiceMCPFakeJournalClient struct{ client.Client }

func (c voiceMCPFakeJournalClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if cm, ok := obj.(*corev1.ConfigMap); ok && cm.Namespace == "operator" && cm.Labels[voiceMCPJournalLabel] == "v1" {
		cm.UID = types.UID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
	}
	return c.Client.Create(ctx, obj, opts...)
}

type voiceMCPCreateRaceClient struct {
	client.Client
	inserted bool
}

func (c *voiceMCPCreateRaceClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok || cm.Labels[voiceMCPJournalLabel] != "v1" || c.inserted {
		return c.Client.Create(ctx, obj, opts...)
	}
	c.inserted = true
	var receipt voiceMCPReceipt
	if err := json.Unmarshal([]byte(cm.Data["receipt.json"]), &receipt); err != nil {
		return err
	}
	receipt.TickID = "competing-tick"
	receipt.OperationID = voiceMCPOperationID(Request{PolicyUID: receipt.PolicyUID, TickID: receipt.TickID, OperationID: receipt.SelectionDecisionID},
		&model.VoiceMCPObservation{DeploymentUID: receipt.DeploymentUID, TargetPodUID: receipt.TargetPodUID, EventUID: receipt.EventUID, RunSHA256: receipt.RunSHA256,
			ToolName: receipt.ToolName, MCPServiceUID: receipt.MCPServiceUID, MCPPodUID: receipt.MCPPodUID, MCPDeploymentUID: receipt.MCPDeploymentUID,
			MCPConfigMapUID: receipt.MCPConfigMapUID, MCPSourceSHA256: receipt.MCPSourceSHA256})
	var err error
	receipt.Desired, err = voicemcppolicy.Append(receipt.Prior, receipt.ToolName, receipt.OperationID)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(receipt)
	competing := cm.DeepCopy()
	competing.UID = types.UID("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
	competing.Data["receipt.json"] = string(data)
	if err := c.Client.Create(ctx, competing); err != nil {
		return err
	}
	return c.Client.Create(ctx, obj, opts...)
}

func makeVoiceMCPFixture(t *testing.T) *voiceMCPFixture {
	t.Helper()
	ctx := context.Background()
	approvedImage := "registry.example.test/mcp@sha256:" + strings.Repeat("a", 64)
	ids := []types.UID{
		"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222",
		"33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444",
		"55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666",
		"77777777-7777-4777-8777-777777777777", "88888888-8888-4888-8888-888888888888",
		"99999999-9999-4999-8999-999999999999", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
	}
	ready := []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	voiceDep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: "bot", UID: ids[0]}, Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "bot"}}}}
	voiceRS := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: "bot-rs", UID: ids[1], OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(voiceDep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}}
	voiceSourceBytes := map[string]string{"bot.py": "bot source", "voice_memory_policy.py": "memory source", "voice_output_policy.py": "output source", "voice_mcp_policy.py": "mcp source"}
	h := sha256.Sum256([]byte(voiceSourceBytes["bot.py"] + "\x00" + voiceSourceBytes["voice_memory_policy.py"] + "\x00" + voiceSourceBytes["voice_mcp_policy.py"]))
	voiceSHA := hex.EncodeToString(h[:])
	bh := sha256.Sum256([]byte(voiceSourceBytes["bot.py"] + "\x00" + voiceSourceBytes["voice_memory_policy.py"] + "\x00" + voiceSourceBytes["voice_output_policy.py"] + "\x00" + voiceSourceBytes["voice_mcp_policy.py"]))
	voiceSourceName := "voice-memory-source-" + hex.EncodeToString(bh[:])[:12]
	immutable := true
	voiceSource := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: voiceSourceName, UID: ids[2], ResourceVersion: "1",
		OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(voiceDep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}, Immutable: &immutable, Data: voiceSourceBytes}
	volumes := []corev1.Volume{
		{Name: "rule", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: voicemcppolicy.ConfigMapName}}}},
		{Name: "token", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: voiceMCPSecretName}}},
		{Name: "ledger", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		{Name: "source", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: voiceSourceName}}}},
		{Name: "mcp-test-token", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "voice-mcp-test-token"}}},
	}
	mounts := []corev1.VolumeMount{{Name: "rule", MountPath: "/etc/phorvex/voice-mcp-tool-policy", ReadOnly: true}, {Name: "token", MountPath: "/etc/phorvex/voice-memory-state-token", ReadOnly: true}, {Name: "ledger", MountPath: "/var/lib/phorvex-voice-memory"},
		{Name: "mcp-test-token", MountPath: "/etc/phorvex/voice-mcp-test-token", ReadOnly: true},
		{Name: "source", MountPath: "/app/bot.py", ReadOnly: true, SubPath: "bot.py"}, {Name: "source", MountPath: "/app/voice_memory_policy.py", ReadOnly: true, SubPath: "voice_memory_policy.py"}, {Name: "source", MountPath: "/app/voice_output_policy.py", ReadOnly: true, SubPath: "voice_output_policy.py"}, {Name: "source", MountPath: "/app/voice_mcp_policy.py", ReadOnly: true, SubPath: "voice_mcp_policy.py"}}
	creator := "system:serviceaccount:phorvex-system:console"
	voiceDep.Spec.Template.Annotations = map[string]string{"phorvex.ai/voice-mcp-policy-configmap": voicemcppolicy.ConfigMapName, "phorvex.ai/voice-mcp-source-configmap": voiceSourceName, "phorvex.ai/voice-mcp-source-sha256": voiceSHA, "phorvex.ai/voice-mcp-event-creator": creator}
	bot := corev1.Container{Name: "bot", Image: "registry.example.test/bot@sha256:" + strings.Repeat("b", 64), Command: []string{"python3", "-B", "/app/bot.py"},
		Env: []corev1.EnvVar{{Name: "VOICE_MCP_POLICY_REQUIRED", Value: "true"}, {Name: "MCP_URL", Value: voiceMCPInstalledURL},
			{Name: "VOICE_MCP_TEST_ENABLED", Value: "true"}, {Name: "VOICE_MCP_SERVER_SOURCE_SHA256", Value: voicemcppolicy.ReviewedMCPSourceSHA256}}, VolumeMounts: mounts}
	voiceDep.Spec.Template.Spec = corev1.PodSpec{Containers: []corev1.Container{bot}, Volumes: volumes}
	voicePod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: "bot-1", UID: ids[3], Labels: map[string]string{"app": "bot"}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(voiceRS, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))}, Annotations: map[string]string{
		"phorvex.ai/voice-mcp-policy-configmap": voicemcppolicy.ConfigMapName, "phorvex.ai/voice-mcp-source-configmap": voiceSourceName, "phorvex.ai/voice-mcp-source-sha256": voiceSHA, "phorvex.ai/voice-mcp-event-creator": creator}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{bot}, Volumes: volumes}, Status: corev1.PodStatus{PodIP: "127.0.0.1", Conditions: ready}}
	policy := &v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: "voice-defense", UID: ids[4], Generation: 1}, Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "bot"}}, Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionVoiceMCPToolPin}}}}
	rule := voicemcppolicy.Rule{Version: 1, DeploymentUID: string(ids[0]), PolicyUID: string(ids[4]), SourceSHA256: voiceSHA, Entries: []voicemcppolicy.Entry{}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: voicemcppolicy.ConfigMapName, UID: ids[5], ResourceVersion: "1", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(voiceDep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}, Data: map[string]string{voicemcppolicy.RuleKey: string(rule.Bytes())}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "voice", Name: voiceMCPSecretName}, Data: map[string][]byte{"token": []byte(strings.Repeat("s", 32))}}
	mcpDep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "mcp", Name: "mcp-server", UID: ids[6]}, Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "mcp-server"}}}}
	mcpRS := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "mcp", Name: "mcp-rs", UID: ids[7], OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(mcpDep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}}
	mcpServerBytes, readErr := os.ReadFile("testdata/voice-mcp/server.py")
	if readErr != nil {
		t.Fatal(readErr)
	}
	mcpServer := string(mcpServerBytes)
	mh := sha256.Sum256([]byte(mcpServer))
	mcpSHA := hex.EncodeToString(mh[:])
	if mcpSHA != voicemcppolicy.ReviewedMCPSourceSHA256 {
		t.Fatalf("reviewed MCP source test fixture drifted: %s", mcpSHA)
	}
	mcpSourceName := "voice-mcp-source-" + mcpSHA[:12]
	mcpVolume := corev1.Volume{Name: "source", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: mcpSourceName}}}}
	mcpContainer := corev1.Container{Name: "mcp-server", Image: approvedImage, WorkingDir: "/app", Command: []string{"python3", "-B", "/app/server.py"}, VolumeMounts: []corev1.VolumeMount{{Name: "source", MountPath: "/app/server.py", SubPath: "server.py", ReadOnly: true}, {Name: "test-token", MountPath: "/etc/phorvex/voice-mcp-test-token", ReadOnly: true}}}
	mcpTestTokenVolume := corev1.Volume{Name: "test-token", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "voice-mcp-test-token"}}}
	mcpPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "mcp", Name: "mcp-1", UID: ids[8], Labels: map[string]string{"app": "mcp-server"}, Annotations: map[string]string{voicemcppolicy.MCPSourceAnnotation: mcpSourceName}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(mcpRS, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{mcpContainer}, Volumes: []corev1.Volume{mcpVolume, mcpTestTokenVolume}}, Status: corev1.PodStatus{PodIP: "127.0.0.2", Conditions: ready,
			ContainerStatuses: []corev1.ContainerStatus{{Name: "mcp-server", Ready: true, ContainerID: "containerd://mcp", ImageID: approvedImage}}}}
	mcpDep.Spec.Template.Annotations = map[string]string{voicemcppolicy.MCPSourceAnnotation: mcpSourceName}
	mcpDep.Spec.Template.Spec = corev1.PodSpec{Containers: []corev1.Container{mcpContainer}, Volumes: []corev1.Volume{mcpVolume, mcpTestTokenVolume}}
	mcpCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "mcp", Name: mcpSourceName, UID: ids[9]}, Immutable: &immutable, Data: map[string]string{"server.py": mcpServer}}
	service := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "mcp", Name: voicemcppolicy.MCPServiceName, UID: ids[10]}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "mcp-server"}, Ports: []corev1.ServicePort{{Protocol: corev1.ProtocolTCP, Port: 8000, TargetPort: intstr.FromInt32(8000)}}}}
	port := int32(8000)
	protocol := corev1.ProtocolTCP
	yes := true
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: "mcp", Name: "mcp-server-slice", Labels: map[string]string{discoveryv1.LabelServiceName: voicemcppolicy.MCPServiceName}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(service, corev1.SchemeGroupVersion.WithKind("Service"))}}, Ports: []discoveryv1.EndpointPort{{Port: &port, Protocol: &protocol}}, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"127.0.0.2"}, Conditions: discoveryv1.EndpointConditions{Ready: &yes}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: mcpPod.Name, UID: mcpPod.UID}}}}
	c := fake.NewClientBuilder().WithScheme(p4bScheme()).WithObjects(voiceDep, voiceRS, voicePod, voiceSource, policy, cm, secret, mcpDep, mcpRS, mcpPod, mcpCM, service, slice,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "voice"}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "mcp"}}, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "operator"}}).Build()
	observed := time.Now().UTC().Add(-time.Second)
	eventRaw := map[string]any{"version": 1, "scenarioId": "ai2-mcp-tool-poisoning", "runSHA256": strings.Repeat("1", 64), "toolName": voicemcppolicy.StoreDirectory, "observedDescriptorSHA256": strings.Repeat("2", 64), "goodDescriptorSHA256": voicemcppolicy.StoreDirectoryGoodSHA256,
		"deploymentUID": string(voiceDep.UID), "podUID": string(voicePod.UID), "sourceSHA256": voiceSHA, "mcpDeploymentUID": string(mcpDep.UID), "mcpPodUID": string(mcpPod.UID), "mcpServiceUID": string(service.UID), "mcpConfigMapUID": string(mcpCM.UID), "mcpSourceSHA256": mcpSHA,
		"policyName": policy.Name, "policyUID": string(policy.UID), "policyGeneration": int64(1), "observedAt": observed.Format(time.RFC3339Nano), "evidenceSource": "TEST_INJECTED", "mcpFetchObserved": true, "voiceBehaviorObserved": true}
	raw, _ := json.Marshal(eventRaw)
	event := &amtdv1beta1.SecurityEvent{ObjectMeta: metav1.ObjectMeta{Name: "mcp-event", UID: ids[11], CreationTimestamp: metav1.NewTime(time.Now().UTC()), Annotations: map[string]string{"phorvex.ai/creator-identity": creator, model.ConsoleTargetPodUIDAnnotation: string(voicePod.UID), voiceMCPEventAnnotation: string(raw)}}, Spec: amtdv1beta1.SecurityEventSpec{Targets: []string{"voice/" + voicePod.Name}, Rule: amtdv1beta1.Rule{Type: model.AttackVectorVoiceMCP, Source: "redteam"}}}
	if err := c.Create(ctx, event); err != nil {
		t.Fatal(err)
	}
	o := &model.VoiceMCPObservation{EventName: event.Name, EventUID: string(event.UID), CreatorIdentity: creator, ScenarioID: "ai2-mcp-tool-poisoning", RunSHA256: strings.Repeat("1", 64), TargetPodUID: string(voicePod.UID), DeploymentUID: string(voiceDep.UID), ConfigMapUID: string(cm.UID), ConfigMapResourceVersion: cm.ResourceVersion, SourceConfigMapUID: string(voiceSource.UID), RuleSHA256: rule.SHA256(), SourceSHA256: voiceSHA, ToolName: voicemcppolicy.StoreDirectory, GoodDescriptorSHA256: voicemcppolicy.StoreDirectoryGoodSHA256, ObservedDescriptorSHA256: strings.Repeat("2", 64), MCPServiceName: service.Name, MCPServiceUID: string(service.UID), MCPPodName: mcpPod.Name, MCPPodUID: string(mcpPod.UID), MCPDeploymentUID: string(mcpDep.UID), MCPConfigMapUID: string(mcpCM.UID), MCPSourceSHA256: mcpSHA, PolicyName: policy.Name, PolicyUID: string(policy.UID), PolicyGeneration: 1, SelectedRevision: 0, ObservedAt: observed}
	req := Request{Namespace: "voice", Pod: voicePod.Name, TargetUID: string(voicePod.UID), PolicyName: policy.Name, PolicyUID: string(policy.UID), PolicyGeneration: 1, TickID: "tick-1", OperationID: "decision-1", Action: model.ActionVoiceMCPToolPin, VoiceMCPObservation: o}
	f := &voiceMCPFixture{client: c, req: req, rule: rule, voicePod: voicePod, mcpPod: mcpPod}
	f.ec = EnactCtx{Reader: c, Client: voiceMCPFakeJournalClient{c}, JournalNamespace: "operator", VoiceMCPApprovedImage: approvedImage, VoiceMCPTransport: voiceRefundRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != voicemcppolicy.StatePath || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("s", 32) {
			t.Fatalf("incorrect private readback %s", r.URL)
		}
		current := &corev1.ConfigMap{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: "voice", Name: voicemcppolicy.ConfigMapName}, current); err != nil {
			return nil, err
		}
		rule, err := voicemcppolicy.Parse(current.Data[voicemcppolicy.RuleKey])
		if err != nil {
			return nil, err
		}
		revision := rule.Revision
		if f.stateRevision != 0 {
			revision = f.stateRevision
		}
		state := voiceMCPState{Version: 1, PodUID: string(voicePod.UID), DeploymentUID: rule.DeploymentUID, PolicyUID: rule.PolicyUID, SourceSHA256: rule.SourceSHA256, RuleSHA256: rule.SHA256(), Revision: revision, OperationID: rule.OperationID, EntryCount: len(rule.Entries), Ready: true, GoodDescriptorSHA256: voicemcppolicy.StoreDirectoryGoodSHA256}
		body, _ := json.Marshal(state)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})}
	return f
}

func TestVoiceMCPNativeSelectionAndRecovery(t *testing.T) {
	ctx := context.Background()
	f := makeVoiceMCPFixture(t)
	result, err := (voiceMCPHandler{}).Enact(ctx, f.ec, f.req)
	if err != nil || !result.Emitted || result.MutationKind != "forward-only" {
		t.Fatalf("actual append unconfirmed: %+v %v", result, err)
	}
	journalName := voiceMCPJournalName(f.req.VoiceMCPObservation.DeploymentUID, 1)
	journal, receipt, err := voiceMCPJournalGet(ctx, f.ec, journalName)
	if err != nil || receipt.Phase != "terminal-full" {
		t.Fatalf("terminal receipt missing: %+v %v", receipt, err)
	}
	if receipt.TickID != f.req.TickID || receipt.SelectionDecisionID != f.req.OperationID || len(receipt.Desired.Entries) != 1 || receipt.Desired.Entries[0].GoodDescriptorSHA256 != voicemcppolicy.StoreDirectoryGoodSHA256 {
		t.Fatalf("selection/rule proof lost: %+v", receipt)
	}
	competing := f.req
	competing.TickID = "other-tick"
	if result, err := (voiceMCPHandler{}).Enact(ctx, f.ec, competing); err == nil || result.Emitted {
		t.Fatalf("competing tick claimed receipt: %+v %v", result, err)
	}
	if result, err := (voiceMCPHandler{}).Enact(ctx, f.ec, f.req); err != nil || result.Emitted || result.NoEffect != NoEffectReconciled {
		t.Fatalf("repeat selection credited a new effect: %+v %v", result, err)
	}
	receipt.Phase = "prepared"
	data, _ := json.Marshal(receipt)
	journal.Data["receipt.json"] = string(data)
	if err := f.client.Update(ctx, journal); err != nil {
		t.Fatal(err)
	}
	events, err := recoverVoiceMCPOperations(ctx, f.ec, func(action model.Action) bool { return action == model.ActionVoiceMCPToolPin })
	if err != nil || len(events) != 1 || events[0].Outcome != "confirmed" {
		t.Fatalf("restart recovery failed: %+v %v", events, err)
	}
	_, after, err := voiceMCPJournalGet(ctx, f.ec, journalName)
	if err != nil || after.Phase != "terminal-full" {
		t.Fatalf("recovery did not close original intent: %+v %v", after, err)
	}
}

func TestVoiceMCPNativeRefusesSourceAndReadbackDrift(t *testing.T) {
	ctx := context.Background()
	f := makeVoiceMCPFixture(t)
	target := Target{Namespace: "voice", Pod: f.voicePod.Name, UID: string(f.voicePod.UID), PolicyName: f.req.PolicyName, PolicyUID: f.req.PolicyUID}
	scope, err := voiceMCPScopeAt(ctx, f.client, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := voicemcppolicy.CurrentSource(ctx, f.client, voicemcppolicy.SourcePins{DeploymentUID: f.req.VoiceMCPObservation.MCPDeploymentUID, PodUID: f.req.VoiceMCPObservation.MCPPodUID, ServiceUID: f.req.VoiceMCPObservation.MCPServiceUID, ConfigMapUID: f.req.VoiceMCPObservation.MCPConfigMapUID, SourceSHA256: f.req.VoiceMCPObservation.MCPSourceSHA256, ApprovedImage: f.ec.VoiceMCPApprovedImage}); err != nil {
		t.Fatalf("current MCP source rejected: %v", err)
	}
	imagePin := f.ec.VoiceMCPApprovedImage
	f.ec.VoiceMCPApprovedImage = ""
	if result, err := (voiceMCPHandler{}).Enact(ctx, f.ec, f.req); err == nil || result.Emitted {
		t.Fatalf("missing reviewed image admitted: %+v %v", result, err)
	}
	f.ec.VoiceMCPApprovedImage = imagePin
	mcpCurrent := &corev1.Pod{}
	if err := f.client.Get(ctx, client.ObjectKeyFromObject(f.mcpPod), mcpCurrent); err != nil {
		t.Fatal(err)
	}
	mcpCurrent.Status.ContainerStatuses[0].ImageID = "registry.example.test/unreviewed@sha256:" + strings.Repeat("b", 64)
	if err := f.client.Status().Update(ctx, mcpCurrent); err != nil {
		t.Fatal(err)
	}
	if result, err := (voiceMCPHandler{}).Enact(ctx, f.ec, f.req); err == nil || result.Emitted {
		t.Fatalf("unreviewed runtime image admitted: %+v %v", result, err)
	}
	mcpCurrent.Status.ContainerStatuses[0].ImageID = imagePin
	if err := f.client.Status().Update(ctx, mcpCurrent); err != nil {
		t.Fatal(err)
	}
	f.stateRevision = 1
	if err := voiceMCPReadback(ctx, scope, f.rule, f.ec.VoiceMCPTransport); err == nil {
		t.Fatal("stale app revision accepted")
	}
	f.stateRevision = 0
	voiceCurrent := &corev1.Pod{}
	if err := f.client.Get(ctx, client.ObjectKeyFromObject(f.voicePod), voiceCurrent); err != nil {
		t.Fatal(err)
	}
	voiceCurrent.Spec.Containers[0].Env[1].Value = "http://unreviewed.mcp.svc.cluster.local:8000/mcp/"
	if err := f.client.Update(ctx, voiceCurrent); err != nil {
		t.Fatal(err)
	}
	if result, err := (voiceMCPHandler{}).Enact(ctx, f.ec, f.req); err == nil || result.Emitted {
		t.Fatalf("other MCP URL admitted: %+v %v", result, err)
	}
	voiceCurrent.Spec.Containers[0].Env[1].Value = voiceMCPInstalledURL
	if err := f.client.Update(ctx, voiceCurrent); err != nil {
		t.Fatal(err)
	}
	voiceCurrent.Spec.Containers[0].Command = []string{"python3", "/app/bot.py"}
	if err := f.client.Update(ctx, voiceCurrent); err != nil {
		t.Fatal(err)
	}
	if result, err := (voiceMCPHandler{}).Enact(ctx, f.ec, f.req); err == nil || result.Emitted {
		t.Fatalf("unreviewed bot command admitted: %+v %v", result, err)
	}
	voiceCurrent.Spec.Containers[0].Command = []string{"python3", "-B", "/app/bot.py"}
	voiceCurrent.Spec.Containers[0].VolumeMounts[3].ReadOnly = false
	if err := f.client.Update(ctx, voiceCurrent); err != nil {
		t.Fatal(err)
	}
	if result, err := (voiceMCPHandler{}).Enact(ctx, f.ec, f.req); err == nil || result.Emitted {
		t.Fatalf("writable test-token mount admitted: %+v %v", result, err)
	}
	voiceCurrent.Spec.Containers[0].VolumeMounts[3].ReadOnly = true
	if err := f.client.Update(ctx, voiceCurrent); err != nil {
		t.Fatal(err)
	}
	current := &corev1.Pod{}
	if err := f.client.Get(ctx, client.ObjectKeyFromObject(f.mcpPod), current); err != nil {
		t.Fatal(err)
	}
	current.Spec.Containers[0].Command = []string{"python", "/app/server.py"}
	if err := f.client.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	if result, err := (voiceMCPHandler{}).Enact(ctx, f.ec, f.req); err == nil || result.Emitted {
		t.Fatalf("source command drift admitted: %+v %v", result, err)
	}
	if _, _, err := voiceMCPJournalGet(ctx, f.ec, voiceMCPJournalName(f.req.VoiceMCPObservation.DeploymentUID, 1)); err == nil {
		t.Fatal("drift reserved journal")
	}
}

func TestVoiceMCPReadbackRequiresEveryServingPod(t *testing.T) {
	f := makeVoiceMCPFixture(t)
	scope := voiceMCPScope{secret: []byte(strings.Repeat("s", 32)), pods: []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{UID: types.UID("11111111-1111-4111-8111-111111111111")}, Status: corev1.PodStatus{PodIP: "127.0.0.1"}},
		{ObjectMeta: metav1.ObjectMeta{UID: types.UID("22222222-2222-4222-8222-222222222222")}, Status: corev1.PodStatus{PodIP: "127.0.0.2"}},
	}}
	transport := voiceRefundRoundTrip(func(r *http.Request) (*http.Response, error) {
		uid := string(scope.pods[0].UID)
		revision := f.rule.Revision
		if r.URL.Hostname() == "127.0.0.2" {
			uid = string(scope.pods[1].UID)
			revision++
		}
		state := voiceMCPState{Version: 1, PodUID: uid, DeploymentUID: f.rule.DeploymentUID, PolicyUID: f.rule.PolicyUID, SourceSHA256: f.rule.SourceSHA256,
			RuleSHA256: f.rule.SHA256(), Revision: revision, OperationID: f.rule.OperationID, EntryCount: len(f.rule.Entries), Ready: true,
			GoodDescriptorSHA256: voicemcppolicy.StoreDirectoryGoodSHA256}
		body, _ := json.Marshal(state)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})
	if err := voiceMCPReadback(context.Background(), scope, f.rule, transport); err == nil {
		t.Fatal("stale second serving Pod credited")
	}
}

func TestVoiceMCPJournalCreateRaceRejectsCompetingSelection(t *testing.T) {
	f := makeVoiceMCPFixture(t)
	race := &voiceMCPCreateRaceClient{Client: f.client}
	f.ec.Client = race
	result, err := (voiceMCPHandler{}).Enact(context.Background(), f.ec, f.req)
	if err == nil || result.Emitted || !race.inserted {
		t.Fatalf("competing prepared journal claimed: %+v %v inserted=%t", result, err, race.inserted)
	}
	_, receipt, err := voiceMCPJournalGet(context.Background(), f.ec, voiceMCPJournalName(f.req.VoiceMCPObservation.DeploymentUID, 1))
	if err != nil || receipt.Phase != "prepared" || receipt.TickID != "competing-tick" {
		t.Fatalf("competing intent lost: %+v %v", receipt, err)
	}
	current := &corev1.ConfigMap{}
	if err := f.client.Get(context.Background(), client.ObjectKey{Namespace: "voice", Name: voicemcppolicy.ConfigMapName}, current); err != nil {
		t.Fatal(err)
	}
	rule, err := voicemcppolicy.Parse(current.Data[voicemcppolicy.RuleKey])
	if err != nil || rule.Revision != 0 {
		t.Fatalf("competing intent caused mutation: %+v %v", rule, err)
	}
}

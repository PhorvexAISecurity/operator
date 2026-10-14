package console

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/decision"
	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/litellmclient"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
	amtdv1beta1 "github.com/r6security/phoenix/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// The console's real event producer writes to a fake Kubernetes API which only
// supplies admission UID/creator metadata. Ingestion, recon and selection are
// production code. This proves source wiring, not live LiteLLM enforcement.
func TestLiteLiveProducedEventFeedsNormalDecision(t *testing.T) {
	for _, sourceFile := range []string{"gateway.py", "frozen-m1b", "gateway_metrics.py"} {
		t.Run(sourceFile, func(t *testing.T) { liteLiveProducedEventFeedsNormalDecision(t, sourceFile) })
	}
}

func liteLiveProducedEventFeedsNormalDecision(t *testing.T, sourceFile string) {
	ctx := context.Background()
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	const creator = "system:serviceaccount:phorvex-system:phorvex-phorvex-console"
	const policyUID = "policy-uid"
	const clientSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	seedSHA := strings.Repeat("b", 64)
	sourcePath := "../../../build/test-harness/fixtures/litellm-live/" + sourceFile
	if sourceFile == "frozen-m1b" {
		sourcePath = "../../../deploy/helm/phorvex-stack/files/litellm-m1b/gateway-metrics-source-configmap.json"
	}
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if sourceFile == "frozen-m1b" {
		var cm corev1.ConfigMap
		if json.Unmarshal(source, &cm) != nil || cm.Immutable == nil || !*cm.Immutable || len(cm.Data) != 1 {
			t.Fatal("frozen M1b source ConfigMap differs")
		}
		source = []byte(cm.Data[litellmclient.SourceKey])
		if litellmclient.SHA256(source) != litellmclient.MetricsSourceSHA256 {
			t.Fatal("frozen M1b source bytes drifted")
		}
	}
	sourceSHA := litellmclient.SHA256(source)
	if !litellmclient.ApprovedSource(sourceSHA) {
		t.Fatalf("reviewed gateway source drift: %s", sourceSHA)
	}
	immutable := true
	objects := []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "litellm"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "litellm", Name: "litellm", UID: "service-uid"},
			Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "litellm"}, Ports: []corev1.ServicePort{{Port: 4000, TargetPort: intstr.FromInt32(4001)}}}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "litellm", Name: litellmclient.ApprovedSourceConfigMap(sourceSHA), UID: "source-uid"},
			Immutable: &immutable, Data: map[string]string{litellmclient.SourceKey: string(source)}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "litellm", Name: litellmclient.ClientsConfigMapName, UID: "clients-uid"},
			Immutable: &immutable, Data: map[string]string{litellmclient.ClientsKey: `{"modelAlias":"gpt-4o-mini","seedSHA256":"` + seedSHA + `","version":2}`}},
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "litellm", Name: litellmclient.PolicyConfigMapName, UID: "policy-cm-uid", ResourceVersion: "1"},
			Data: map[string]string{litellmclient.PolicyKey: `{"entries":[],"revision":0,"version":2}`}},
		&v1alpha1.PhorvexPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: "litellm", Name: "litellm-defense", UID: types.UID(policyUID), Generation: 1},
			Spec: v1alpha1.PhorvexPolicySpec{Mode: v1alpha1.ModeActive, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"r6th.io/rotation-target": "true"}},
				Actions: v1alpha1.ActionsSpec{Enabled: []v1alpha1.ActionType{v1alpha1.ActionRotate, v1alpha1.ActionQuarantine, v1alpha1.ActionType(model.ActionLiteLLMClientRevoke)}}}},
	}
	ready := true
	port := int32(4001)
	endpoints := []discoveryv1.Endpoint{}
	for i, name := range []string{"litellm-a", "litellm-b"} {
		uid := types.UID("pod-" + string(rune('a'+i)))
		ip := "10.1.0." + string(rune('1'+i))
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "litellm", Name: name, UID: uid,
			CreationTimestamp: metav1.NewTime(now.Add(-20 * time.Minute)), Labels: map[string]string{"app": "litellm", "r6th.io/rotation-target": "true"},
			Annotations: map[string]string{litellmclient.SourceSHAAnnotation: sourceSHA,
				litellmclient.GatewayImageAnnotation: litellmclient.ApprovedRuntimeImage,
				litellmclient.PolicyUIDAnnotation:    "policy-cm-uid", litellmclient.ServiceUIDAnnotation: "service-uid",
				litellmclient.SeedSHAAnnotation: seedSHA}},
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "litellm", Image: "backend@sha256:" + strings.Repeat("d", 64)},
				{Name: litellmclient.GatewayContainerName, Image: litellmclient.ApprovedRuntimeImage,
					Command: []string{"python3", "-B", "/opt/phorvex/gateway.py"},
					Env: []corev1.EnvVar{{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}},
						{Name: "PHORVEX_LITELLM_CLIENTS_FILE", Value: "/etc/phorvex-litellm/clients.json"},
						{Name: "PHORVEX_LITELLM_TRIAL_SEED_FILE", Value: "/etc/phorvex-litellm-seed/seed"},
						{Name: "PHORVEX_LITELLM_POLICY_FILE", Value: "/etc/phorvex-litellm-policy/state.json"},
						{Name: "PHORVEX_LITELLM_STATUS_TOKEN_FILE", Value: "/etc/phorvex-litellm-status/token"},
						{Name: "PHORVEX_LITELLM_POLICY_CONFIGMAP_UID", Value: "policy-cm-uid"},
						{Name: "PHORVEX_LITELLM_GATEWAY_SOURCE_SHA256", Value: sourceSHA}},
					VolumeMounts: []corev1.VolumeMount{{Name: "litellm-live-gateway-source", MountPath: "/opt/phorvex", ReadOnly: true},
						{Name: "litellm-live-clients", MountPath: "/etc/phorvex-litellm", ReadOnly: true},
						{Name: "litellm-live-policy", MountPath: "/etc/phorvex-litellm-policy", ReadOnly: true},
						{Name: "litellm-live-status", MountPath: "/etc/phorvex-litellm-status", ReadOnly: true},
						{Name: "litellm-live-trial-seed", MountPath: "/etc/phorvex-litellm-seed", ReadOnly: true}}}},
				Volumes: []corev1.Volume{{Name: "litellm-live-gateway-source", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: litellmclient.ApprovedSourceConfigMap(sourceSHA)}}}},
					{Name: "litellm-live-clients", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: litellmclient.ClientsConfigMapName}}}},
					{Name: "litellm-live-policy", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: litellmclient.PolicyConfigMapName}}}},
					{Name: "litellm-live-status", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "status-token"}}},
					{Name: "litellm-live-trial-seed", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: litellmclient.TrialSeedSecretName}}}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: ip,
				Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
				ContainerStatuses: []corev1.ContainerStatus{{Name: "litellm", ImageID: "backend@sha256:" + strings.Repeat("d", 64), Ready: true},
					{Name: litellmclient.GatewayContainerName, ImageID: litellmclient.ApprovedRuntimeImage, Ready: true}}}}
		if sourceSHA == litellmclient.AuthMetricsSourceSHA256 {
			addConsoleAuthMetricsBinding(pod)
		}
		objects = append(objects, pod)
		endpoints = append(endpoints, discoveryv1.Endpoint{Addresses: []string{ip}, Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: name, UID: uid}})
	}
	objects = append(objects, &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: "litellm", Name: "litellm-slice",
		Labels: map[string]string{discoveryv1.LabelServiceName: litellmclient.ServiceName}},
		Ports: []discoveryv1.EndpointPort{{Port: &port}}, Endpoints: endpoints})
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, v1alpha1.AddToScheme, amtdv1beta1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	priorTrust := ingest.EventTrust()
	ingest.ConfigureEventTrust(ingest.NewTrustedDetectors([]string{"phorvex-system/phorvex-phorvex-console"}))
	t.Cleanup(func() { ingest.ConfigureEventTrust(priorTrust) })
	server := NewServer(Config{StateDir: t.TempDir(), Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
		if bin != "kubectl" || len(args) != 5 || args[0] != "create" || args[1] != "-f" || args[3] != "-o" || args[4] != "json" {
			t.Fatalf("unexpected event transport %s %q", bin, args)
		}
		raw, err := os.ReadFile(args[2])
		if err != nil {
			return "", err
		}
		var event amtdv1beta1.SecurityEvent
		if err = json.Unmarshal(raw, &event); err != nil {
			return "", err
		}
		if event.Spec.Rule.Type != litellmclient.RuleType || len(event.Spec.Targets) != 1 || event.Spec.Targets[0] != "litellm/litellm-a" {
			t.Fatalf("producer event scope differs: %+v", event)
		}
		event.UID = "event-uid"
		event.CreationTimestamp = metav1.NewTime(now.Add(-time.Second))
		event.Annotations[ingest.CreatorIdentityAnnotation] = creator
		if err = c.Create(ctx, &event); err != nil {
			return "", err
		}
		answer, err := json.Marshal(event)
		return string(answer), err
	}})
	w := &liteLiveWorker{s: server, ctx: ctx, out: t.TempDir(), p: liteLLMLiveProfile{EventCreator: creator, PolicyName: "litellm-defense", SeedSHA256: seedSHA},
		attackerSHA: clientSHA, bound: liteLiveSnapshot{PolicyConfigMapUID: "policy-cm-uid", ClientsConfigMapUID: "clients-uid",
			ServiceUID: "service-uid", PolicyUID: policyUID, PolicyGeneration: 1,
			Pods: []liteLivePod{{Name: "litellm-a", UID: "pod-a"}, {Name: "litellm-b", UID: "pod-b"}}}}
	created, err := w.createEvent("ai2-query-extraction", now.Add(-2*time.Second))
	if err != nil || created.UID != "event-uid" {
		t.Fatalf("production producer failed: %+v %v", created, err)
	}

	check := func(at time.Time, want bool) *model.Pod {
		t.Helper()
		snap, err := ingest.CollectSnapshot(ctx, c, at, nil, c)
		if err != nil {
			t.Fatal(err)
		}
		p := snap.PodByKey["litellm/litellm-a"]
		if p == nil || p.HasBoundLiteLLMClientObservation() != want {
			t.Fatalf("trusted event bound=%v want=%v pod=%+v", p != nil && p.HasBoundLiteLLMClientObservation(), want, p)
		}
		if !want {
			return p
		}
		if p.LiteLLMClientObservation.EventUID != created.UID || p.LiteLLMClientObservation.TargetPodUID != "pod-a" {
			t.Fatalf("producer event identity lost: %+v", p.LiteLLMClientObservation)
		}
		view := &model.WorkloadView{Pod: *p, Events: snap.EventByPod["litellm/litellm-a"], Physics: model.NeutralPhysics(), Phase: model.PhaseWarm,
			ExposureByVariable: map[string]time.Duration{model.VarPodIdentity: 20 * time.Minute}}
		pol := model.Policy{Tenant: "litellm", Namespace: "litellm", PolicyName: "litellm-defense", PolicyUID: policyUID,
			PolicyGeneration: 1, Mode: "active", TraceEnabled: true, TickID: "litellm-chain-tick", MaxMovesPerTick: 1,
			NormSparsity: .4, FlowDisruption: .6, WeightSecrets: .8, Lambda: .4, CostCeiling: model.DefaultCostCeiling,
			MinAvailableReplicas: 1, ProactiveFloor: 15 * time.Minute, ExposurePressureScale: 15 * time.Minute,
			AntiOverRotationWindow: 90 * time.Second, TickInterval: 10 * time.Second, EventAgeHorizon: time.Hour,
			EventDriven: true, ReactiveOnly: true, AssetWeightFromLabels: func(map[string]string) float64 { return .4 },
			EnabledActions: map[model.Action]bool{model.ActionLiteLLMClientRevoke: true, model.ActionRotate: true, model.ActionQuarantine: true}}
		engine := decision.NewCoverageEngine()
		engine.Now = func() time.Time { return at }
		profile, ok := recon.Registry.Get("ucw-recon")
		if !ok {
			t.Fatal("UCW recon absent")
		}
		engine.Recon = profile
		set, _ := engine.AssembleSet([]*model.WorkloadView{view}, pol)
		considered := map[model.Action]bool{}
		for _, candidate := range set.Candidates {
			considered[candidate.Action] = true
		}
		for _, exclusion := range set.Excluded {
			considered[exclusion.Action] = true
		}
		for _, action := range []model.Action{model.ActionLiteLLMClientRevoke, model.ActionRotate, model.ActionQuarantine} {
			if !considered[action] {
				t.Fatalf("normal alternative %s absent: %+v %+v", action, set.Candidates, set.Excluded)
			}
		}
		selected := engine.Decide([]*model.WorkloadView{view}, pol)
		if len(selected) != 1 || !selected[0].Selected || selected[0].Action != model.ActionLiteLLMClientRevoke ||
			selected[0].Trace == nil || selected[0].Trace.DecisionID == "" || selected[0].Trace.Validate() != nil {
			t.Fatalf("normal brain did not select exact event capability: %+v", selected)
		}
		return p
	}
	check(now, true)
	check(now.Add(70*time.Second), false) // event age reaches the bounded observation horizon
	event := &amtdv1beta1.SecurityEvent{}
	if err := c.Get(ctx, client.ObjectKey{Name: created.Name}, event); err != nil {
		t.Fatal(err)
	}
	event.Annotations[model.ConsoleTargetPodUIDAnnotation] = "foreign-pod-uid"
	if err := c.Update(ctx, event); err != nil {
		t.Fatal(err)
	}
	check(now, false)
}

func addConsoleAuthMetricsBinding(p *corev1.Pod) {
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

package console

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func leaseTestProfile() endpointLeaseProfile {
	return endpointLeaseProfile{Version: 1, ServiceName: "vllm", ServiceUID: "11111111-1111-4111-8111-111111111111",
		PolicyName: "vllm-defense", PolicyUID: "22222222-2222-4222-8222-222222222222", PolicyGeneration: 1,
		PolicyConfigMapUID: "33333333-3333-4333-8333-333333333333", JournalUID: "44444444-4444-4444-8444-444444444444",
		TenantSecretUID: "55555555-5555-4555-8555-555555555555", ConsoleSecretUID: "66666666-6666-4666-8666-666666666666",
		SourceConfigMapName: "guardrail-proxy", SourceConfigMapUID: "77777777-7777-4777-8777-777777777777",
		ProxySourceSHA256: leaseHex('c'), ProxyImage: "example/proxy@sha256:" + leaseHex('d'),
		ApprovedEngineImage: "example/engine@sha256:" + leaseHex('f'),
		SeedSHA256:          leaseHex('e'), ClientASHA256: leaseHex('a'), ClientBSHA256: leaseHex('b'),
		ClientAHMAC: leaseHex('1'), ClientBHMAC: leaseHex('2'),
		EventCreator:        "system:serviceaccount:phorvex-system:phorvex-phorvex-console",
		AuditSourceIdentity: "owned-audit-source", ModelID: endpointLeaseModel, MaxRunSeconds: 900}
}

func leaseHex(c byte) string { return string(bytes.Repeat([]byte{c}, 64)) }

func TestEndpointLeaseProfileAndPolicyCanonical(t *testing.T) {
	p := leaseTestProfile()
	structRaw, _ := json.Marshal(p)
	var generic map[string]any
	_ = json.Unmarshal(structRaw, &generic)
	raw, _ := json.Marshal(generic)
	if _, err := parseEndpointLeaseProfile(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := parseEndpointLeaseProfile(append(raw, '\n')); err == nil {
		t.Fatal("noncanonical profile accepted")
	}
	p.SourceConfigMapUID = ""
	structBad, _ := json.Marshal(p)
	_ = json.Unmarshal(structBad, &generic)
	bad, _ := json.Marshal(generic)
	if _, err := parseEndpointLeaseProfile(bad); err == nil {
		t.Fatal("missing source UID accepted")
	}
	p = leaseTestProfile()
	state := endpointLeaseState{Version: 1, ServiceUID: p.ServiceUID, ProxySourceSHA256: p.ProxySourceSHA256,
		SecretUID: p.TenantSecretUID, SeedSHA256: p.SeedSHA256,
		AllowedClientHMACs: []string{p.ClientAHMAC, p.ClientBHMAC}, RevokedClientHMACs: []string{}}
	stateRaw := endpointLeaseStateBytes(state)
	parsed, err := parseEndpointLeaseState(stateRaw, p)
	if err != nil || !endpointLeaseBefore(parsed, p) {
		t.Fatalf("valid prior rejected: %v", err)
	}
	decisionID := string(bytes.Repeat([]byte{'f'}, 32)) // real DecisionTrace ID width
	after, err := endpointLeaseDesired(parsed, p, decisionID)
	if err != nil || after.Revision != 1 || len(after.RevokedClientHMACs) != 1 || after.AllowedClientHMACs[0] != p.ClientBHMAC {
		t.Fatalf("desired revocation differs: %v", err)
	}
	if _, err := parseEndpointLeaseState(append(stateRaw, '\n'), p); err == nil {
		t.Fatal("noncanonical policy accepted")
	}
	withNullRevocations := bytes.Replace(stateRaw, []byte(`"revokedClientHMACs":[]`), []byte(`"revokedClientHMACs":null`), 1)
	if bytes.Equal(withNullRevocations, stateRaw) {
		t.Fatal("revocation list fixture absent")
	}
	if _, err := parseEndpointLeaseState(withNullRevocations, p); err == nil {
		t.Fatal("null revocation list accepted as empty array")
	}
	if accepted, err := parseEndpointLeaseState(endpointLeaseStateBytes(after), p); err != nil || accepted.LastOperationID != decisionID {
		t.Fatalf("real 32-hex selected operation rejected: %v", err)
	}
	for _, malformed := range []string{decisionID[:31], "Z" + decisionID[1:]} {
		if _, err := endpointLeaseDesired(parsed, p, malformed); err == nil {
			t.Fatalf("malformed selected operation accepted: %q", malformed)
		}
		after.LastOperationID = malformed
		if _, err := parseEndpointLeaseState(endpointLeaseStateBytes(after), p); err == nil {
			t.Fatalf("malformed stored operation accepted: %q", malformed)
		}
	}
}

func TestEndpointLeasePublicResponseRequiresRealExpectedAnswer(t *testing.T) {
	response := func(status int, body string) *http.Response {
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewBufferString(body))}
	}
	good := `{"id":"completion-1","model":"Qwen/Qwen2.5-7B-Instruct-AWQ","choices":[{"message":{"content":"OK"},"finish_reason":"stop"}]}`
	r, err := endpointLeaseParsePublicResponse(response(200, good))
	if err != nil || !r.ValidCompletion {
		t.Fatalf("real expected answer rejected: %v", err)
	}
	wrong := `{"id":"completion-2","model":"Qwen/Qwen2.5-7B-Instruct-AWQ","choices":[{"message":{"content":"not OK"},"finish_reason":"stop"}]}`
	r, err = endpointLeaseParsePublicResponse(response(200, wrong))
	if err != nil || r.ValidCompletion {
		t.Fatalf("wrong answer credited: %v", err)
	}
	r, err = endpointLeaseParsePublicResponse(response(401, `{"error":"unauthorized"}`))
	if err != nil || !r.ExactDenial {
		t.Fatalf("exact denial rejected: %v", err)
	}
	r, err = endpointLeaseParsePublicResponse(response(503, `{"error":"lease_unavailable"}`))
	if err != nil || r.ExactDenial || r.ValidCompletion {
		t.Fatalf("unavailable response credited: %v", err)
	}
}

func TestEndpointLeaseTerminalRequiresExactOldIncarnations(t *testing.T) {
	p := leaseTestProfile()
	before := endpointLeaseState{Version: 1, ServiceUID: p.ServiceUID, ProxySourceSHA256: p.ProxySourceSHA256,
		SecretUID: p.TenantSecretUID, SeedSHA256: p.SeedSHA256,
		AllowedClientHMACs: []string{p.ClientAHMAC, p.ClientBHMAC}, RevokedClientHMACs: []string{}}
	decision := endpointLeaseDecision{Action: endpointLeaseAction, DecisionID: string(bytes.Repeat([]byte{'f'}, 32)), TickID: "tick-1", Selected: true}
	desired, err := endpointLeaseDesired(before, p, decision.DecisionID)
	if err != nil {
		t.Fatal(err)
	}
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "model-0", Namespace: "vllm", UID: "88888888-8888-4888-8888-888888888888"},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "guardrail", ContainerID: "containerd://old"}, {Name: "vllm", ContainerID: "containerd://engine"}}}}
	pod = leaseTestServingPod(p, pod)
	leaseTestAddNativeMetrics(&pod)
	snap := endpointLeaseSnapshot{Pods: []corev1.Pod{pod}, State: before, StateSHA256: endpointLeaseSHA(endpointLeaseStateBytes(before))}
	event := &attackStimulusEvidence{EventName: "endpoint-lease-run", EventUID: "99999999-9999-4999-8999-999999999999"}
	r := endpointLeaseJournalReceipt{Phase: "terminal-full", Namespace: "vllm", EventName: event.EventName, EventUID: event.EventUID,
		DecisionID: decision.DecisionID, OperationID: decision.DecisionID, TickID: decision.TickID,
		PolicyName: p.PolicyName, PolicyUID: p.PolicyUID, PolicyGeneration: p.PolicyGeneration,
		TargetPodName: pod.Name, TargetPodUID: string(pod.UID), ServiceUID: p.ServiceUID,
		ProxySourceSHA256: p.ProxySourceSHA256, PolicyConfigMapUID: p.PolicyConfigMapUID,
		SecretUID: p.TenantSecretUID, SeedSHA256: p.SeedSHA256,
		RevokedClientHMAC: p.ClientAHMAC, RetainedClientHMAC: p.ClientBHMAC,
		OldStateSHA256: snap.StateSHA256, NewStateSHA256: endpointLeaseSHA(endpointLeaseStateBytes(desired)), NewRevision: 1,
		PreCASPodUIDs: []string{string(pod.UID)}, PreCASProxyContainerIDs: []string{"containerd://old"}}
	prior := endpointLeaseJournal{Version: 1, Receipts: []endpointLeaseJournalReceipt{}}
	after := endpointLeaseJournal{Version: 1, Receipts: []endpointLeaseJournalReceipt{r}}
	if !endpointLeaseTerminalRow(after, prior, snap, p, event, decision, pod, desired) {
		t.Fatal("exact terminal rejected")
	}
	snap.Pods[0].Status.InitContainerStatuses[1].ContainerID = "containerd://metrics-restarted"
	snap.Pods[0].Status.InitContainerStatuses[1].RestartCount++
	if !endpointLeaseTerminalRow(after, prior, snap, p, event, decision, pod, desired) {
		t.Fatal("metrics restart invalidated the exact serving proxy terminal")
	}
	after.Receipts[0].PreCASProxyContainerIDs[0] = "containerd://metrics-restarted"
	if endpointLeaseTerminalRow(after, prior, snap, p, event, decision, pod, desired) {
		t.Fatal("metrics container received serving proxy terminal credit")
	}
	after.Receipts[0].PreCASProxyContainerIDs[0] = "containerd://replacement"
	if endpointLeaseTerminalRow(after, prior, snap, p, event, decision, pod, desired) {
		t.Fatal("restarted old proxy accepted")
	}
	after.Receipts[0].PreCASProxyContainerIDs[0] = "containerd://old"
	badDecision := decision
	badDecision.DecisionID = "Z" + decision.DecisionID[1:]
	if endpointLeaseTerminalRow(after, prior, snap, p, event, badDecision, pod, desired) {
		t.Fatal("malformed selected decision accepted")
	}
}

func TestEndpointLeaseEngineRequiresIndependentImageLoopbackAndSecretRef(t *testing.T) {
	p := leaseTestProfile()
	engine := corev1.Container{Name: "vllm", Image: p.ApprovedEngineImage,
		Args: []string{"--model", endpointLeaseModel, "--host", "127.0.0.1", "--port", "8001"},
		Env: []corev1.EnvVar{{Name: "VLLM_API_KEY", ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "vllm-control"}, Key: "api-key"}}}}}
	statuses := []corev1.ContainerStatus{{Name: "vllm", Ready: true, ContainerID: "containerd://engine",
		ImageID: "docker-pullable://" + p.ApprovedEngineImage}}
	if !endpointLeaseEngineBound(&engine, statuses, p) {
		t.Fatal("reviewed engine refused")
	}
	wrong := engine.DeepCopy()
	wrong.Args[3] = "0.0.0.0"
	if endpointLeaseEngineBound(wrong, statuses, p) {
		t.Fatal("public raw engine accepted")
	}
	wrong = engine.DeepCopy()
	wrong.Env[0].ValueFrom = nil
	wrong.Env[0].Value = "literal-key"
	if endpointLeaseEngineBound(wrong, statuses, p) {
		t.Fatal("literal internal key accepted")
	}
	wrong = engine.DeepCopy()
	wrong.Image = p.ProxyImage
	if endpointLeaseEngineBound(wrong, statuses, p) {
		t.Fatal("proxy image substituted for reviewed engine")
	}
}

// Extend the existing profile and archived recovery Pods with the serving spec
// required by endpointLeaseReadyPod. Pod/ReplicaSet identities are synthetic.
func leaseTestServingPod(p endpointLeaseProfile, pod corev1.Pod) corev1.Pod {
	pod = *pod.DeepCopy()
	yes := true
	pod.Labels = map[string]string{"app": "vllm"}
	pod.Annotations = map[string]string{
		"phorvex.ai/endpoint-lease-source-sha256":        p.ProxySourceSHA256,
		"phorvex.ai/endpoint-lease-policy-configmap-uid": p.PolicyConfigMapUID,
		"phorvex.ai/endpoint-lease-event-creator":        p.EventCreator,
	}
	pod.OwnerReferences = []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "vllm-rs", UID: "rs-uid", Controller: &yes}}
	guardEnv := []corev1.EnvVar{{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}}}
	for _, pair := range []struct{ name, value string }{
		{"PHORVEX_ENDPOINT_LEASE_REQUIRED", "true"},
		{"PHORVEX_ENDPOINT_LEASE_SECRET_DIR", "/etc/phorvex/endpoint-lease-keys"},
		{"PHORVEX_ENDPOINT_LEASE_POLICY_CONFIGMAP_UID", p.PolicyConfigMapUID},
		{"PHORVEX_ENDPOINT_LEASE_SECRET_UID", p.TenantSecretUID},
		{"PHORVEX_ENDPOINT_LEASE_SERVICE_UID", p.ServiceUID},
		{"PHORVEX_ENDPOINT_LEASE_SOURCE_SHA256", p.ProxySourceSHA256},
	} {
		guardEnv = append(guardEnv, corev1.EnvVar{Name: pair.name, Value: pair.value})
	}
	mounts := []corev1.VolumeMount{{Name: "lease-keys", MountPath: "/etc/phorvex/endpoint-lease-keys", ReadOnly: true}}
	for _, name := range []string{"guardrail_proxy.py", "dual_server.py", "endpoint_lease.py", "drain_v11.py", "drain_v11_init.py"} {
		mounts = append(mounts, corev1.VolumeMount{Name: "lease-source", MountPath: "/src/" + name, SubPath: name, ReadOnly: true})
	}
	pod.Spec = corev1.PodSpec{
		Containers: []corev1.Container{
			{Name: "vllm", Image: p.ApprovedEngineImage, Args: []string{"--model", endpointLeaseModel, "--host", "127.0.0.1", "--port", "8001"},
				Env: []corev1.EnvVar{{Name: "VLLM_API_KEY", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{Name: "vllm-control"}, Key: "api-key"}}}}},
			{Name: "guardrail", Image: p.ProxyImage, Command: []string{"python3", "-B", "/src/dual_server.py"}, Env: guardEnv, VolumeMounts: mounts},
		},
		InitContainers: []corev1.Container{{Name: "phorvex-drain-ledger-init"}},
		Volumes: []corev1.Volume{
			{Name: "lease-source", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: p.SourceConfigMapName}}}},
			{Name: "lease-keys", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: endpointLeaseTenantSecret}}},
		},
	}
	pod.Status.Phase = corev1.PodRunning
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	pod.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "phorvex-drain-ledger-init",
		State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}}}
	for i := range pod.Status.ContainerStatuses {
		s := &pod.Status.ContainerStatuses[i]
		s.Ready = true
		s.ImageID = "docker-pullable://" + p.ProxyImage
		if s.Name == "vllm" {
			s.ImageID = "docker-pullable://" + p.ApprovedEngineImage
		}
	}
	return pod
}

func leaseTestMetricsSidecar() corev1.Container {
	restart := corev1.ContainerRestartPolicyAlways
	return corev1.Container{Name: "phorvex-vllm-metrics", Image: "example/metrics@sha256:" + leaseHex('9'),
		Command: []string{"python3", "-B", "/opt/phorvex/metrics.py"}, RestartPolicy: &restart,
		VolumeMounts: []corev1.VolumeMount{
			{Name: "metrics-source", MountPath: "/opt/phorvex/metrics.py", SubPath: "metrics.py", ReadOnly: true},
			{Name: "metrics-token", MountPath: "/etc/phorvex-vllm-metrics", ReadOnly: true},
		},
		Ports: []corev1.ContainerPort{{Name: "engine-metrics", ContainerPort: 9102, Protocol: corev1.ProtocolTCP}}}
}

func leaseTestMetricsVolumes() []corev1.Volume {
	optional, mode := false, int32(0440)
	return []corev1.Volume{
		{Name: "metrics-source", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
			LocalObjectReference: corev1.LocalObjectReference{Name: "phorvex-vllm-native-metrics-fixture"}, Optional: &optional,
			Items: []corev1.KeyToPath{{Key: "metrics.py", Path: "metrics.py"}},
		}}},
		{Name: "metrics-token", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
			SecretName: "phorvex-vllm-native-metrics-token-v1", Optional: &optional, DefaultMode: &mode,
			Items: []corev1.KeyToPath{{Key: "token", Path: "token"}},
		}}},
	}
}

func leaseTestAddNativeMetrics(pod *corev1.Pod) {
	metrics := leaseTestMetricsSidecar()
	pod.Spec.Volumes = append(pod.Spec.Volumes, leaseTestMetricsVolumes()...)
	pod.Spec.InitContainers = append(pod.Spec.InitContainers, metrics)
	pod.Status.InitContainerStatuses = append(pod.Status.InitContainerStatuses, corev1.ContainerStatus{
		Name: metrics.Name, Ready: true, ContainerID: "containerd://metrics", ImageID: metrics.Image,
		State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
	})
}

func TestEndpointLeaseNativeMetricsSidecarPreservesProtection(t *testing.T) {
	p, snap, journal := revalidationFixture(t)
	service := &corev1.Service{Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "vllm"}}}
	before := leaseTestServingPod(p, snap.Pods[0])
	snap.Pods = []corev1.Pod{before}
	stateRaw, journalRaw := endpointLeaseStateBytes(snap.State), journal.Data["receipts.json"]
	origin, err := endpointLeaseProtectionOrigin(snap, journal, p)
	if err != nil || !endpointLeaseReadyPod(&before, p, service) {
		t.Fatalf("existing protected two-container workload refused: %v", err)
	}
	native := before.DeepCopy()
	leaseTestAddNativeMetrics(native)
	if !endpointLeaseReadyPod(native, p, service) {
		t.Fatal("healthy native metrics init sidecar refused")
	}
	native.Status.InitContainerStatuses[1].RestartCount = 3
	native.Status.InitContainerStatuses[1].ContainerID = "containerd://metrics-restarted"
	if !endpointLeaseReadyPod(native, p, service) || !endpointLeaseSameProxyIncarnations([]corev1.Pod{before}, []corev1.Pod{*native}) ||
		endpointLeaseProxyContainerID(*native) != "proxy-one" || endpointLeaseEngineContainerID(*native) != "engine-one" {
		t.Fatal("native metrics changed the serving predicate or incarnation binding")
	}
	snap.Pods = []corev1.Pod{*native}
	afterOrigin, err := endpointLeaseProtectionOrigin(snap, journal, p)
	if err != nil || !reflect.DeepEqual(origin, afterOrigin) || !bytes.Equal(stateRaw, endpointLeaseStateBytes(snap.State)) || journal.Data["receipts.json"] != journalRaw ||
		snap.State.Revision != 2 || snap.State.AllowedClientHMACs[0] != p.ClientBHMAC || snap.State.RevokedClientHMACs[0] != p.ClientAHMAC {
		t.Fatalf("native metrics lost historical terminal/source-upgrade protection: %v", err)
	}
	third := native.DeepCopy()
	metrics := third.Spec.InitContainers[1]
	metrics.RestartPolicy = nil
	third.Spec.InitContainers = third.Spec.InitContainers[:1]
	third.Spec.Containers = append(third.Spec.Containers, metrics)
	third.Status.ContainerStatuses = append(third.Status.ContainerStatuses, third.Status.InitContainerStatuses[1])
	third.Status.InitContainerStatuses = third.Status.InitContainerStatuses[:1]
	if endpointLeaseReadyPod(third, p, service) {
		t.Fatal("third regular container accepted")
	}
	for _, name := range []string{"guardrail", "vllm"} {
		changed := native.DeepCopy()
		for i := range changed.Status.ContainerStatuses {
			if changed.Status.ContainerStatuses[i].Name == name {
				changed.Status.ContainerStatuses[i].ContainerID = "containerd://replacement"
			}
		}
		if endpointLeaseSameProxyIncarnations([]corev1.Pod{*native}, []corev1.Pod{*changed}) {
			t.Fatalf("%s replacement retained old incarnation credit", name)
		}
	}
	changed := native.DeepCopy()
	changed.UID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	if endpointLeaseSameProxyIncarnations([]corev1.Pod{*native}, []corev1.Pod{*changed}) {
		t.Fatal("replacement Pod retained old incarnation credit")
	}
	snap.State.AllowedClientHMACs = []string{p.ClientAHMAC, p.ClientBHMAC}
	snap.State.RevokedClientHMACs = []string{}
	if _, err := endpointLeaseProtectionOrigin(snap, journal, p); err == nil {
		t.Fatal("metrics sidecar rearmed protected A")
	}
}

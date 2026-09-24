package scenarios

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func responseManifestEnv() *core.Env {
	return &core.Env{ScenarioName: natsResponseScenario, Trial: 0,
		Config: config.TargetConfig{Namespace: natsResponseFixtureNamespace,
			NATSExposureFixture: &config.NATSExposureFixtureConfig{Nonce: "0123456789abcdef01234567", NodeName: "healthy-owned-node",
				ObserverImage: "docker.io/phorvex/console@sha256:" + strings.Repeat("a", 64)}}}
}

func TestNATSResponseEndpointSliceRequiresExactTwoOriginalReadyMembers(t *testing.T) {
	yes := true
	name := "nats-response-0123456789abcdef01234567"
	client := natsResponsePodIdentity{Name: "client", UID: "client-uid", IP: "192.0.2.7"}
	peer := natsResponsePodIdentity{Name: "peer", UID: "peer-uid", IP: "192.0.2.8"}
	portName, portNumber, protocol := "ready", int32(8080), corev1.ProtocolTCP
	slice := discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "owned-slice", Namespace: natsResponseFixtureNamespace,
		UID: "slice-uid", Labels: map[string]string{discoveryv1.LabelServiceName: name},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: name, UID: "service-uid", Controller: &yes}}},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       []discoveryv1.EndpointPort{{Name: &portName, Port: &portNumber, Protocol: &protocol}},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{client.IP}, Conditions: discoveryv1.EndpointConditions{Ready: &yes, Serving: &yes, Terminating: new(bool)}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: client.Name, Namespace: natsResponseFixtureNamespace, UID: client.UID}},
			{Addresses: []string{peer.IP}, Conditions: discoveryv1.EndpointConditions{Ready: &yes, Serving: &yes, Terminating: new(bool)}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: peer.Name, Namespace: natsResponseFixtureNamespace, UID: peer.UID}},
		}}
	if err := natsResponseEndpointMembers([]discoveryv1.EndpointSlice{slice}, name, "service-uid", client, peer); err != nil {
		t.Fatal(err)
	}
	peerOnly := slice.DeepCopy()
	peerOnly.Endpoints = peerOnly.Endpoints[1:]
	if err := natsResponseEndpointMembersAfter([]discoveryv1.EndpointSlice{*peerOnly}, name, "service-uid", client, peer); err != nil {
		t.Fatalf("legitimate peer-only route after source quarantine refused: %v", err)
	}
	peerMissing := slice.DeepCopy()
	peerMissing.Endpoints = peerMissing.Endpoints[:1]
	if err := natsResponseEndpointMembersAfter([]discoveryv1.EndpointSlice{*peerMissing}, name, "service-uid", client, peer); err == nil {
		t.Fatal("post-response Service without original peer accepted")
	}
	for label, mutate := range map[string]func(*discoveryv1.EndpointSlice){
		"wrong-service":   func(s *discoveryv1.EndpointSlice) { s.OwnerReferences[0].UID = "foreign-service" },
		"wrong-client":    func(s *discoveryv1.EndpointSlice) { s.Endpoints[0].TargetRef.UID = "replacement-client" },
		"wrong-peer-ip":   func(s *discoveryv1.EndpointSlice) { s.Endpoints[1].Addresses[0] = "192.0.2.99" },
		"wrong-peer-name": func(s *discoveryv1.EndpointSlice) { s.Endpoints[1].TargetRef.Name = "replacement-peer" },
		"not-ready":       func(s *discoveryv1.EndpointSlice) { no := false; s.Endpoints[1].Conditions.Ready = &no },
		"extra-member":    func(s *discoveryv1.EndpointSlice) { s.Endpoints = append(s.Endpoints, s.Endpoints[0]) },
		"missing-peer":    func(s *discoveryv1.EndpointSlice) { s.Endpoints = s.Endpoints[:1] },
		"wrong-port":      func(s *discoveryv1.EndpointSlice) { other := int32(8081); s.Ports[0].Port = &other },
	} {
		t.Run(label, func(t *testing.T) {
			bad := slice.DeepCopy()
			mutate(bad)
			if err := natsResponseEndpointMembers([]discoveryv1.EndpointSlice{*bad}, name, "service-uid", client, peer); err == nil {
				t.Fatal("different Service membership accepted")
			}
		})
	}
}

func TestNATSResponseReadyPodPinsOriginalOwnerProcessAndHealth(t *testing.T) {
	env := responseManifestEnv()
	nonce := env.Config.NATSExposureFixture.Nonce
	name := natsResponseName(nonce)
	dep := natsResponseDeployment(env, name)
	yes := true
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "original-0", Namespace: env.Config.Namespace,
		UID: "original-uid", Labels: dep.Spec.Template.Labels,
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: name + "-rs", UID: "rs-uid", Controller: &yes}}},
		Spec: dep.Spec.Template.Spec,
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "192.0.2.7",
			Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
			ContainerStatuses: []corev1.ContainerStatus{{Name: "observer", Ready: true, RestartCount: 0,
				ContainerID: "containerd://original", ImageID: env.Config.NATSExposureFixture.ObserverImage}}}}
	if id, err := natsResponseReadyPod(p, "rs-uid", name+"-rs", nonce, env.Config.NATSExposureFixture.NodeName, env.Config.NATSExposureFixture.ObserverImage); err != nil || id.UID != p.UID {
		t.Fatalf("original healthy Pod refused: %+v %v", id, err)
	}
	for label, mutate := range map[string]func(*corev1.Pod){
		"wrong-owner":       func(p *corev1.Pod) { p.OwnerReferences[0].UID = "replacement-rs" },
		"restarted":         func(p *corev1.Pod) { p.Status.ContainerStatuses[0].RestartCount = 1 },
		"new-container":     func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ContainerID = "" },
		"wrong-image":       func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ImageID = "foreign" },
		"downward-api-lost": func(p *corev1.Pod) { p.Spec.Containers[0].Env[0].ValueFrom.FieldRef.FieldPath = "metadata.name" },
		"config-shadow":     func(p *corev1.Pod) { p.Spec.Containers[0].VolumeMounts[0].SubPath = "other" },
		"client-not-ready":  func(p *corev1.Pod) { p.Status.ContainerStatuses[0].Ready = false },
		"foreign-component": func(p *corev1.Pod) { p.Labels[natsResponseComponentLabel] = "remote" },
	} {
		t.Run(label, func(t *testing.T) {
			bad := p.DeepCopy()
			mutate(bad)
			if _, err := natsResponseReadyPod(bad, "rs-uid", name+"-rs", nonce, env.Config.NATSExposureFixture.NodeName, env.Config.NATSExposureFixture.ObserverImage); err == nil {
				t.Fatal("changed consumer authority accepted")
			}
		})
	}
}

func TestNATSResponseOriginalClientSurvivesExactPhoenixLabelMoveOnlyAfterBarrier(t *testing.T) {
	env := responseManifestEnv()
	name := natsResponseName(env.Config.NATSExposureFixture.Nonce)
	dep := natsResponseDeployment(env, name)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name + "-pod", Namespace: env.Config.Namespace,
		UID: "original-uid", Labels: dep.Spec.Template.Labels}, Spec: dep.Spec.Template.Spec,
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "observer", RestartCount: 0,
			ContainerID: "containerd://original", ImageID: env.Config.NATSExposureFixture.ObserverImage}}}}
	pod.Labels[natsResponseRoleLabel] = "source"
	fixture := natsResponseFixture{Name: name, Client: natsResponsePodIdentity{Name: pod.Name, UID: pod.UID,
		ContainerID: "containerd://original", ImageID: env.Config.NATSExposureFixture.ObserverImage}}
	check := func(p *corev1.Pod, allow bool) error {
		env.Kube = fake.NewSimpleClientset(p)
		return natsResponseClientIncarnation(t.Context(), env, fixture, allow)
	}
	if err := check(pod, false); err != nil {
		t.Fatalf("startup original client refused: %v", err)
	}
	phoenix := pod.DeepCopy()
	delete(phoenix.Labels, natsResponseComponentLabel)
	phoenix.Annotations = map[string]string{natsResponseComponentLabel: "consumer"}
	if err := check(phoenix, false); err == nil {
		t.Fatal("Phoenix label migration accepted before selected-effect barrier")
	}
	if err := check(phoenix, true); err != nil {
		t.Fatalf("exact original client lost after Phoenix label migration: %v", err)
	}
	bad := phoenix.DeepCopy()
	bad.Annotations[natsResponseComponentLabel] = "other"
	if err := check(bad, true); err == nil {
		t.Fatal("wrong migrated component accepted")
	}
	bad = phoenix.DeepCopy()
	bad.Status.ContainerStatuses[0].RestartCount = 1
	if err := check(bad, true); err == nil {
		t.Fatal("restarted client accepted after quarantine")
	}
	bad = phoenix.DeepCopy()
	bad.UID = "replacement-uid"
	if err := check(bad, true); err == nil {
		t.Fatal("replacement Pod accepted after quarantine")
	}
}

func TestNATSResponsePeerLogIncarnationRejectsReplacementAndPhoenixLabelMove(t *testing.T) {
	env := responseManifestEnv()
	name := natsResponseName(env.Config.NATSExposureFixture.Nonce)
	dep := natsResponseDeployment(env, name)
	yes := true
	peer := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name + "-peer", Namespace: env.Config.Namespace,
		UID: "peer-uid", Labels: dep.Spec.Template.Labels,
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: name + "-rs", UID: "rs-uid", Controller: &yes}}},
		Spec: dep.Spec.Template.Spec, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "observer",
			ContainerID: "containerd://peer", ImageID: env.Config.NATSExposureFixture.ObserverImage}}}}
	fixture := natsResponseFixture{Name: name, ReplicaSetUID: "rs-uid", Peer: natsResponsePodIdentity{Name: peer.Name,
		UID: peer.UID, ContainerID: "containerd://peer", ImageID: env.Config.NATSExposureFixture.ObserverImage}}
	check := func(p *corev1.Pod) error {
		env.Kube = fake.NewSimpleClientset(p)
		return natsResponseObservedPodIncarnation(t.Context(), env, fixture, fixture.Peer, false, false)
	}
	if err := check(peer); err != nil {
		t.Fatalf("original peer refused: %v", err)
	}
	for label, mutate := range map[string]func(*corev1.Pod){
		"wrong-rs":    func(p *corev1.Pod) { p.OwnerReferences[0].UID = "replacement-rs" },
		"restart":     func(p *corev1.Pod) { p.Status.ContainerStatuses[0].RestartCount = 1 },
		"replacement": func(p *corev1.Pod) { p.UID = "replacement-peer" },
		"source-role": func(p *corev1.Pod) { p.Labels[natsResponseRoleLabel] = "source" },
		"moved-component": func(p *corev1.Pod) {
			delete(p.Labels, natsResponseComponentLabel)
			p.Annotations = map[string]string{natsResponseComponentLabel: "consumer"}
		},
	} {
		t.Run(label, func(t *testing.T) {
			bad := peer.DeepCopy()
			mutate(bad)
			if err := check(bad); err == nil {
				t.Fatal("changed legitimate peer incarnation accepted")
			}
		})
	}
}

func TestNATSResponsePolicyAdmissionRetainsRequestedContractAndDefaults(t *testing.T) {
	env := responseManifestEnv()
	wanted := natsResponsePolicy(env, natsResponseName(env.Config.NATSExposureFixture.Nonce))
	admitted := wanted.DeepCopy()
	admitted.SetUID(types.UID("api-created-policy"))
	admitted.SetGeneration(1)
	spec, _, _ := unstructured.NestedMap(admitted.Object, "spec")
	budget := spec["budget"].(map[string]any)
	budget["apiDefaultedField"] = "admitted-baseline"
	if err := unstructured.SetNestedMap(admitted.Object, spec, "spec"); err != nil {
		t.Fatal(err)
	}
	baseline, err := natsResponseAdmittedPolicySpec(wanted, admitted)
	if err != nil || baseline["budget"].(map[string]any)["apiDefaultedField"] != "admitted-baseline" {
		t.Fatalf("valid admitted default not retained: %v", err)
	}
	changed := admitted.DeepCopy()
	if err := unstructured.SetNestedField(changed.Object, "dryRun", "spec", "mode"); err != nil {
		t.Fatal(err)
	}
	if _, err := natsResponseAdmittedPolicySpec(wanted, changed); err == nil {
		t.Fatal("admission changed active mode without refusal")
	}
	changed = admitted.DeepCopy()
	changed.SetUID("")
	if _, err := natsResponseAdmittedPolicySpec(wanted, changed); err == nil {
		t.Fatal("admission without created UID accepted")
	}
}

func TestNATSResponseFixtureIsServicedTwoPodNoncePolicy(t *testing.T) {
	env := responseManifestEnv()
	nonce := env.Config.NATSExposureFixture.Nonce
	name := natsResponseName(nonce)
	route := natsRouteIdentity{Brokers: []natsBrokerIdentity{{ServerID: "N" + strings.Repeat("A", 55)}}}
	raw, err := natsResponseObserverConfig(nonce, route)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Subjects              []string `json:"subjects"`
		ExpectedPayloadSHA256 []string `json:"expectedPayloadSHA256"`
		M0TimeoutMillis       int      `json:"m0TimeoutMillis"`
		M1TimeoutMillis       int      `json:"m1TimeoutMillis"`
	}
	if json.Unmarshal(raw, &cfg) != nil || len(cfg.Subjects) != 2 || cfg.Subjects[0] == cfg.Subjects[1] ||
		len(cfg.ExpectedPayloadSHA256) != 2 || cfg.ExpectedPayloadSHA256[0] == cfg.ExpectedPayloadSHA256[1] ||
		cfg.M0TimeoutMillis != 120000 || cfg.M1TimeoutMillis != 300000 ||
		cfg.M0TimeoutMillis+cfg.M1TimeoutMillis > 420000 {
		t.Fatalf("two distinct bounded packet phases absent: %+v", cfg)
	}
	cm := natsResponseConfigMap(env, name, raw)
	if cm.Immutable == nil || !*cm.Immutable || len(cm.Data) != 1 || cm.Data["observer.json"] != string(raw) {
		t.Fatal("observer config is not exact immutable source")
	}
	dep, service, pdb, policy := natsResponseDeployment(env, name), natsResponseService(env, name), natsResponsePDB(env, name), natsResponsePolicy(env, name)
	if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 2 || dep.Spec.Template.Labels[natsResponseRoleLabel] != "" ||
		dep.Spec.Template.Spec.NodeName != env.Config.NATSExposureFixture.NodeName ||
		dep.Spec.Template.Spec.AutomountServiceAccountToken == nil || *dep.Spec.Template.Spec.AutomountServiceAccountToken {
		t.Fatal("producer does not create two initially equivalent tokenless clients on pinned node")
	}
	containers := dep.Spec.Template.Spec.Containers
	if len(containers) != 1 || len(containers[0].Command) != 3 || containers[0].Command[1] != "--response-config" ||
		len(containers[0].Env) != 2 || containers[0].Env[0].Name != "POD_UID" ||
		containers[0].Env[0].ValueFrom == nil || containers[0].Env[0].ValueFrom.FieldRef == nil ||
		containers[0].Env[0].ValueFrom.FieldRef.FieldPath != "metadata.uid" ||
		containers[0].Env[1].Name != "NATS_RESPONSE_SERVICE" || containers[0].Env[1].Value != "1" ||
		containers[0].ReadinessProbe == nil || containers[0].ReadinessProbe.HTTPGet == nil || containers[0].ReadinessProbe.HTTPGet.Path != "/ready" {
		t.Fatal("producer cannot bind real observer process/UID/broker health")
	}
	if service.Spec.Selector[natsResponseOwnerLabel] != nonce || service.Spec.Selector[natsResponseComponentLabel] != "consumer" ||
		dep.Spec.Template.Labels[natsResponseComponentLabel] != "consumer" || len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Port != 8080 ||
		pdb.Spec.MinAvailable == nil || pdb.Spec.MinAvailable.IntValue() != 1 || pdb.Spec.Selector.MatchLabels[natsResponseOwnerLabel] != nonce || pdb.Spec.Selector.MatchLabels[natsResponseComponentLabel] != "consumer" {
		t.Fatal("real consumer Service/PDB capacity contract differs")
	}
	if tenant, _, _ := unstructured.NestedString(policy.Object, "spec", "tenant"); tenant != nonce {
		t.Fatal("policy tenant is not unique run nonce")
	}
	selector, _, _ := unstructured.NestedMap(policy.Object, "spec", "selector", "matchLabels")
	if selector[natsResponseOwnerLabel] != nonce || selector[natsResponseRoleLabel] != "source" {
		t.Fatal("policy selector could catch peer or foreign Pod")
	}
	actions, _, _ := unstructured.NestedSlice(policy.Object, "spec", "actions", "enabled")
	if len(actions) != 2 || actions[0] != "rotate" || actions[1] != "quarantine" {
		t.Fatal("fixture forced or omitted a policy action")
	}
}

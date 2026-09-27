package endpointlease

import (
	"context"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testServiceUID = "11111111-1111-4111-8111-111111111111"
	testSecretUID  = "22222222-2222-4222-8222-222222222222"
	testPolicyUID  = "33333333-3333-4333-8333-333333333333"
	testPodUID     = "44444444-4444-4444-8444-444444444444"
	testDepUID     = "55555555-5555-4555-8555-555555555555"
	testRSUID      = "66666666-6666-4666-8666-666666666666"
)

func fixtureLive(t *testing.T) (client.Client, string, string, string) {
	t.Helper()
	sourceData := map[string]string{}
	for _, name := range sourceFiles {
		sourceData[name] = "# " + name + "\n"
	}
	sourceSHA := SourceSHA256([]byte(sourceData[sourceFiles[0]]), []byte(sourceData[sourceFiles[1]]), []byte(sourceData[sourceFiles[2]]), []byte(sourceData[sourceFiles[3]]), []byte(sourceData[sourceFiles[4]]))
	image := "registry.example/lease-proxy@sha256:" + strings.Repeat("d", 64)
	engineImage := "registry.example/engine@sha256:" + strings.Repeat("e", 64)
	state := fixtureState()
	state.ProxySourceSHA256 = sourceSHA
	raw, err := EncodeState(state)
	if err != nil {
		t.Fatal(err)
	}
	immutable := true
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: ServiceName, Namespace: Namespace, UID: types.UID(testServiceUID)}, Spec: corev1.ServiceSpec{
		Selector: map[string]string{"app": "vllm"}, Ports: []corev1.ServicePort{{Port: 8000, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(8000)}}}}
	policy := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: PolicyConfigMapName, Namespace: Namespace, UID: types.UID(testPolicyUID), ResourceVersion: "7"}, Data: map[string]string{PolicyKey: raw}}
	source := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: SourceConfigMapName, Namespace: Namespace, UID: types.UID("77777777-7777-4777-8777-777777777777")}, Immutable: &immutable, Data: sourceData}
	ann := map[string]string{SourceConfigMapAnnotation: SourceConfigMapName, SourceSHAAnnotation: sourceSHA, PolicyUIDAnnotation: testPolicyUID, EventCreatorAnnotation: "system:serviceaccount:phorvex-system:phorvex-phorvex-console"}
	env := []corev1.EnvVar{}
	for key, value := range map[string]string{
		"PHORVEX_ENDPOINT_LEASE_REQUIRED": "true", "PHORVEX_ENDPOINT_LEASE_SECRET_DIR": "/etc/phorvex/endpoint-lease-keys",
		"PHORVEX_ENDPOINT_LEASE_POLICY_CONFIGMAP_UID": testPolicyUID, "PHORVEX_ENDPOINT_LEASE_SECRET_UID": testSecretUID,
		"PHORVEX_ENDPOINT_LEASE_SERVICE_UID": testServiceUID, "PHORVEX_ENDPOINT_LEASE_SOURCE_SHA256": sourceSHA,
	} {
		env = append(env, corev1.EnvVar{Name: key, Value: value})
	}
	env = append(env, corev1.EnvVar{Name: "POD_UID", ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.uid"}}})
	mounts := []corev1.VolumeMount{{Name: "lease-keys", MountPath: "/etc/phorvex/endpoint-lease-keys", ReadOnly: true}}
	for _, name := range sourceFiles {
		mounts = append(mounts, corev1.VolumeMount{Name: "lease-source", MountPath: "/src/" + name, SubPath: name, ReadOnly: true})
	}
	spec := corev1.PodSpec{Volumes: []corev1.Volume{{Name: "lease-source", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: SourceConfigMapName}}}}, {Name: "lease-keys", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: SecretName}}}},
		Containers: []corev1.Container{{Name: "vllm", Image: engineImage, Args: []string{"--model", "fixture", "--port", "8001", "--host", "127.0.0.1"}, Env: []corev1.EnvVar{{Name: "VLLM_API_KEY", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "vllm-control"}, Key: "api-key"}}}}},
			{Name: ProxyContainerName, Image: image, Command: []string{"python3", "-B", "/src/dual_server.py"}, Env: env, VolumeMounts: mounts}}}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: ServiceName, Namespace: Namespace, UID: types.UID(testDepUID)}, Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Annotations: ann}, Spec: spec}}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "vllm-rs", Namespace: Namespace, UID: types.UID(testRSUID), OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: ServiceName, UID: types.UID(testDepUID), Controller: boolPtr(true)}}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "vllm-pod", Namespace: Namespace, UID: types.UID(testPodUID), Labels: map[string]string{"app": "vllm"}, Annotations: ann, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: boolPtr(true)}}}, Spec: spec,
		Status: corev1.PodStatus{PodIP: "10.0.0.7", Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}, ContainerStatuses: []corev1.ContainerStatus{{Name: "vllm", Ready: true, ContainerID: "containerd://engine", ImageID: "containerd://sha256:" + strings.Repeat("e", 64)}, {Name: ProxyContainerName, Ready: true, ContainerID: "containerd://one", ImageID: "containerd://sha256:" + strings.Repeat("d", 64)}}}}
	port := int32(8000)
	proto := corev1.ProtocolTCP
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: "vllm-slice", Namespace: Namespace, Labels: map[string]string{discoveryv1.LabelServiceName: ServiceName}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: ServiceName, UID: svc.UID, Controller: boolPtr(true)}}},
		Ports: []discoveryv1.EndpointPort{{Port: &port, Protocol: &proto}}, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.7"}, Conditions: discoveryv1.EndpointConditions{Ready: boolPtr(true)}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: Namespace, Name: pod.Name, UID: pod.UID}}}}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	_ = discoveryv1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(svc, policy, source, dep, rs, pod, slice).Build()
	return c, sourceSHA, image, engineImage
}

func boolPtr(v bool) *bool { return &v }

func TestValidateLiveBindsCurrentGraphWithoutSecretGet(t *testing.T) {
	c, source, image, engine := fixtureLive(t)
	live, err := ValidateLive(context.Background(), c, testPodUID, source, image, engine)
	if err != nil {
		t.Fatal(err)
	}
	if live.PolicyUID != testPolicyUID || live.SecretUID != testSecretUID || len(live.Pods) != 1 || live.Pods[0].UID != testPodUID {
		t.Fatalf("unexpected authority: %+v", live)
	}
	// No Secret object exists in this fake API. A manager-side Secret GET would
	// fail this test (and would require an unsafe full-data RBAC grant).
}

func TestValidateLiveRejectsSourceImageAndEndpointDrift(t *testing.T) {
	for _, mutation := range []string{"source", "source-remap", "image", "engine-host", "extra-sidecar", "endpoint", "terminating-ready", "not-serving-ready", "secret-mount", "owner"} {
		t.Run(mutation, func(t *testing.T) {
			c, source, image, engine := fixtureLive(t)
			ctx := context.Background()
			switch mutation {
			case "source":
				cm := &corev1.ConfigMap{}
				_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: SourceConfigMapName}, cm)
				cm.Data["endpoint_lease.py"] = "drift"
				_ = c.Update(ctx, cm)
			case "source-remap":
				pod := &corev1.Pod{}
				_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "vllm-pod"}, pod)
				pod.Spec.Volumes[0].ConfigMap.Items = []corev1.KeyToPath{{Key: "guardrail_proxy.py", Path: "dual_server.py"}}
				_ = c.Update(ctx, pod)
			case "image":
				pod := &corev1.Pod{}
				_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "vllm-pod"}, pod)
				pod.Status.ContainerStatuses[0].ImageID = "containerd://sha256:" + strings.Repeat("f", 64)
				_ = c.Status().Update(ctx, pod)
			case "engine-host":
				pod := &corev1.Pod{}
				_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "vllm-pod"}, pod)
				pod.Spec.Containers[0].Args[5] = "0.0.0.0"
				_ = c.Update(ctx, pod)
			case "extra-sidecar":
				pod := &corev1.Pod{}
				_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "vllm-pod"}, pod)
				pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "bypass", Image: "unreviewed"})
				_ = c.Update(ctx, pod)
			case "endpoint":
				slice := &discoveryv1.EndpointSlice{}
				_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "vllm-slice"}, slice)
				slice.Endpoints[0].Addresses[0] = "10.0.0.8"
				_ = c.Update(ctx, slice)
			case "terminating-ready":
				slice := &discoveryv1.EndpointSlice{}
				_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "vllm-slice"}, slice)
				slice.Endpoints[0].Conditions.Terminating = boolPtr(true)
				_ = c.Update(ctx, slice)
			case "not-serving-ready":
				slice := &discoveryv1.EndpointSlice{}
				_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "vllm-slice"}, slice)
				slice.Endpoints[0].Conditions.Serving = boolPtr(false)
				_ = c.Update(ctx, slice)
			case "secret-mount":
				pod := &corev1.Pod{}
				_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "vllm-pod"}, pod)
				pod.Spec.Containers[1].VolumeMounts[0].ReadOnly = false
				_ = c.Update(ctx, pod)
			case "owner":
				pod := &corev1.Pod{}
				_ = c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "vllm-pod"}, pod)
				pod.OwnerReferences[0].UID = types.UID("99999999-9999-4999-8999-999999999999")
				_ = c.Update(ctx, pod)
			}
			if _, err := ValidateLive(ctx, c, testPodUID, source, image, engine); err == nil {
				t.Fatal("authority drift accepted")
			}
		})
	}
}

func TestValidateLiveRejectsNonReadyOwnerWithPossibleOldStream(t *testing.T) {
	c, source, image, engine := fixtureLive(t)
	ctx := context.Background()
	old := &corev1.Pod{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "vllm-pod"}, old); err != nil {
		t.Fatal(err)
	}
	old.ResourceVersion = ""
	old.Name = "vllm-old-stream"
	old.UID = types.UID("88888888-8888-4888-8888-888888888888")
	old.Status.PodIP = "10.0.0.8"
	old.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse}}
	if err := c.Create(ctx, old); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateLive(ctx, c, testPodUID, source, image, engine); err == nil {
		t.Fatal("non-Ready old proxy process outside slice could retain A stream")
	}
	// A stale or unreadable ReplicaSet must not hide the same running process.
	old.OwnerReferences[0].Name = "vllm-missing-rs"
	old.OwnerReferences[0].UID = types.UID("99999999-9999-4999-8999-999999999999")
	if err := c.Update(ctx, old); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateLive(ctx, c, testPodUID, source, image, engine); err == nil {
		t.Fatal("running old proxy with unreadable ReplicaSet escaped drain inventory")
	}
}

func TestValidateLiveSecretProjectionMustBeExactIdentity(t *testing.T) {
	identity := []corev1.KeyToPath{{Key: "client-a", Path: "client-a"}, {Key: "client-b", Path: "client-b"}, {Key: "seed", Path: "seed"}}
	mode := int32(0400)
	for name, tc := range map[string]struct {
		items  []corev1.KeyToPath
		accept bool
	}{
		"installed identity": {identity, true},
		"reordered identity": {[]corev1.KeyToPath{identity[2], identity[0], identity[1]}, true},
		"renamed":            {[]corev1.KeyToPath{{Key: "client-b", Path: "client-a"}, {Key: "client-a", Path: "client-b"}, identity[2]}, false},
		"missing":            {identity[:2], false},
		"duplicate":          {[]corev1.KeyToPath{identity[0], identity[0], identity[2]}, false},
		"extra":              {append(append([]corev1.KeyToPath(nil), identity...), corev1.KeyToPath{Key: "api-key", Path: "api-key"}), false},
		"per-file mode":      {[]corev1.KeyToPath{{Key: "client-a", Path: "client-a", Mode: &mode}, identity[1], identity[2]}, false},
		"traversal":          {[]corev1.KeyToPath{identity[0], identity[1], {Key: "seed", Path: "../seed"}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			c, source, image, engine := fixtureLive(t)
			ctx := context.Background()
			dep := &appsv1.Deployment{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: ServiceName}, dep); err != nil {
				t.Fatal(err)
			}
			// Match the installed runtime shape: 0440 files and an explicit non-optional Secret.
			installedMode, optional := int32(0440), false
			secret := dep.Spec.Template.Spec.Volumes[1].Secret
			secret.Items, secret.DefaultMode, secret.Optional = tc.items, &installedMode, &optional
			if err := c.Update(ctx, dep); err != nil {
				t.Fatal(err)
			}
			pod := &corev1.Pod{}
			if err := c.Get(ctx, client.ObjectKey{Namespace: Namespace, Name: "vllm-pod"}, pod); err != nil {
				t.Fatal(err)
			}
			pod.Spec.Volumes[1].Secret.Items, pod.Spec.Volumes[1].Secret.DefaultMode, pod.Spec.Volumes[1].Secret.Optional = tc.items, &installedMode, &optional
			if err := c.Update(ctx, pod); err != nil {
				t.Fatal(err)
			}
			_, err := ValidateLive(ctx, c, testPodUID, source, image, engine)
			if tc.accept != (err == nil) {
				t.Fatalf("accept=%v err=%v", tc.accept, err)
			}
		})
	}
}

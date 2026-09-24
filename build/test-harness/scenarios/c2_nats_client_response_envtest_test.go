package scenarios

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

type natsResponseAllowGuard struct{}

func (natsResponseAllowGuard) AssertMutationAllowed(string) error { return nil }

// Fake clients do not run apps or CRD validation. This control sends every
// generated object to a local API server with server-side dry-run, while
// keeping the actual named fixture namespace and cluster untouched.
func TestNATSResponseFixtureActualAPIAdmission(t *testing.T) {
	assets := os.Getenv("KUBEBUILDER_ASSETS")
	if assets == "" {
		t.Skip("KUBEBUILDER_ASSETS is required for actual API admission")
	}
	if !filepath.IsAbs(assets) {
		t.Fatal("KUBEBUILDER_ASSETS must be absolute")
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source directory unavailable")
	}
	crds := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", "..", "phorvex", "config", "crd", "bases"))
	local := false
	api := &envtest.Environment{UseExistingCluster: &local, BinaryAssetsDirectory: assets,
		CRDDirectoryPaths: []string{crds}, ErrorIfCRDPathMissing: true}
	restConfig, err := api.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := api.Stop(); err != nil {
			t.Error(err)
		}
	})
	kube, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ctrlclient.New(restConfig, ctrlclient.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	ns, err := kube.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "nats-response-admission-", Labels: map[string]string{"phorvex.ai/nats-exposure-fixture": "true"}}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	env := responseManifestEnv()
	env.Config.Namespace = ns.Name
	env.Config.OutDir = t.TempDir()
	env.Config.NATSExposureFixture.RunID = "run-7"
	env.Ctrl, env.Kube = client, kube
	env.Guard = natsResponseAllowGuard{}
	if err := env.EnsureNamespace(ctx); err != nil {
		t.Fatal(err)
	}
	name := natsResponseName(env.Config.NATSExposureFixture.Nonce)
	route := natsRouteIdentity{Brokers: []natsBrokerIdentity{{ServerID: "NAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}}
	configData, err := natsResponseObserverConfig(env.Config.NATSExposureFixture.Nonce, route)
	if err != nil {
		t.Fatal(err)
	}
	cm := natsResponseConfigMap(env, name, configData)
	if _, err := kube.CoreV1().ConfigMaps(ns.Name).Create(ctx, cm, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}); err != nil {
		t.Fatalf("generated ConfigMap refused by actual API: %v", err)
	}
	dep := natsResponseDeployment(env, name)
	if dep.Spec.Template.Spec.ActiveDeadlineSeconds != nil {
		t.Fatal("Deployment PodTemplate must not set activeDeadlineSeconds")
	}
	if _, err := kube.AppsV1().Deployments(ns.Name).Create(ctx, dep, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}); err != nil {
		t.Fatalf("generated Deployment refused by actual API: %v", err)
	}
	if _, err := kube.CoreV1().Services(ns.Name).Create(ctx, natsResponseService(env, name), metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}); err != nil {
		t.Fatalf("generated Service refused by actual API: %v", err)
	}
	if _, err := kube.PolicyV1().PodDisruptionBudgets(ns.Name).Create(ctx, natsResponsePDB(env, name), metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}); err != nil {
		t.Fatalf("generated PDB refused by actual API: %v", err)
	}
	policy := natsResponsePolicy(env, name)
	if err := client.Create(ctx, policy, ctrlclient.DryRunAll); err != nil {
		t.Fatalf("generated PhorvexPolicy refused by actual API: %v", err)
	}
	for _, obj := range []ctrlclient.Object{
		&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns.Name}},
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns.Name}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns.Name}},
		&policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns.Name}},
		&unstructured.Unstructured{Object: map[string]any{"apiVersion": "phorvex.ai/v1alpha1", "kind": "PhorvexPolicy", "metadata": map[string]any{"name": name, "namespace": ns.Name}}},
	} {
		if err := client.Get(ctx, ctrlclient.ObjectKeyFromObject(obj), obj); !apierrors.IsNotFound(err) {
			t.Fatalf("dry-run object %T persisted or lookup failed: %v", obj, err)
		}
	}
	// A negative API control ensures the server, rather than a fake client, is
	// actually validating the Deployment PodTemplate shape.
	invalid := dep.DeepCopy()
	deadline := int64(330)
	invalid.Spec.Template.Spec.ActiveDeadlineSeconds = &deadline
	if _, err := kube.AppsV1().Deployments(ns.Name).Create(ctx, invalid, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}); !apierrors.IsInvalid(err) {
		t.Fatalf("actual apps validation accepted forbidden PodTemplate deadline: %v", err)
	}
	// Exercise the real CREATE sequence as well as dry-run. There is no
	// controller-manager in envtest, so no Pod scheduling or broker traffic.
	fixture, admittedSpec, err := createNATSResponseOwnedObjects(ctx, env, route)
	if err != nil {
		t.Fatalf("actual API producer failed: %v", err)
	}
	if fixture.NamespaceUID != ns.UID || fixture.ConfigMapUID == "" || fixture.ServiceUID == "" ||
		fixture.PDBUID == "" || fixture.PolicyUID == "" || fixture.PolicyGen < 1 || fixture.DeploymentUID == "" {
		t.Fatalf("create-response identities incomplete: %+v", fixture)
	}
	if err := natsResponseCurrentPolicy(ctx, env, name, fixture.PolicyUID, fixture.PolicyGen, admittedSpec); err != nil {
		t.Fatalf("admitted policy current recheck failed: %v", err)
	}
	// envtest does not run the Deployment controller. Construct its exact API
	// output, then exercise the actual Pod role JSONPatch producer against the
	// apiserver rather than trusting a fake patch reaction.
	createdDep, err := kube.AppsV1().Deployments(ns.Name).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	yes := true
	rsName := name + "-rs"
	createdRS, err := kube.AppsV1().ReplicaSets(ns.Name).Create(ctx, &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Name: rsName, Labels: createdDep.Spec.Template.Labels,
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: name, UID: createdDep.UID, Controller: &yes}}},
		Spec: appsv1.ReplicaSetSpec{Replicas: createdDep.Spec.Replicas, Selector: createdDep.Spec.Selector, Template: createdDep.Spec.Template}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i, podName := range []string{name + "-a", name + "-b"} {
		createdPod, err := kube.CoreV1().Pods(ns.Name).Create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: podName, Labels: createdDep.Spec.Template.Labels,
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rsName, UID: createdRS.UID, Controller: &yes}}},
			Spec: createdDep.Spec.Template.Spec}, metav1.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		createdPod.Status.Phase, createdPod.Status.PodIP = corev1.PodRunning, fmt.Sprintf("192.0.2.%d", i+7)
		createdPod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
		createdPod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "observer", Ready: true,
			ImageID: env.Config.NATSExposureFixture.ObserverImage, ContainerID: fmt.Sprintf("containerd://owned-%d", i)}}
		if _, err := kube.CoreV1().Pods(ns.Name).UpdateStatus(ctx, createdPod, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	createdDep.Status.ObservedGeneration = createdDep.Generation
	createdDep.Status.Replicas, createdDep.Status.ReadyReplicas, createdDep.Status.UpdatedReplicas = 2, 2, 2
	if _, err := kube.AppsV1().Deployments(ns.Name).UpdateStatus(ctx, createdDep, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	pods, rsUID, err := natsResponseAwaitConsumers(ctx, env, fixture)
	if err != nil || rsUID != createdRS.UID {
		t.Fatalf("actual API two-original consumer selection failed: %v", err)
	}
	if err := natsResponseAssignSource(ctx, env, &fixture, pods, rsUID); err != nil {
		t.Fatalf("actual API source-role patch failed: %v", err)
	}
	if fixture.Client.Name != name+"-a" || fixture.Client.UID != pods[0].UID || fixture.Peer.UID != pods[1].UID {
		t.Fatalf("source assignment changed original two-Pod identity: %+v", fixture)
	}
	service, err := kube.CoreV1().Services(ns.Name).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	portName, portNumber, protocol := "ready", int32(8080), corev1.ProtocolTCP
	endpointSlice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Name: name + "-slice", Namespace: ns.Name,
		Labels:          map[string]string{discoveryv1.LabelServiceName: name},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: name, UID: service.UID, Controller: &yes}}},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       []discoveryv1.EndpointPort{{Name: &portName, Port: &portNumber, Protocol: &protocol}},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{fixture.Client.IP}, Conditions: discoveryv1.EndpointConditions{Ready: &yes, Serving: &yes, Terminating: new(bool)}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: fixture.Client.Name, Namespace: ns.Name, UID: fixture.Client.UID}},
			{Addresses: []string{fixture.Peer.IP}, Conditions: discoveryv1.EndpointConditions{Ready: &yes, Serving: &yes, Terminating: new(bool)}, TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: fixture.Peer.Name, Namespace: ns.Name, UID: fixture.Peer.UID}},
		}}
	if _, err := kube.DiscoveryV1().EndpointSlices(ns.Name).Create(ctx, endpointSlice, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := natsResponseCurrentControls(ctx, env, fixture, admittedSpec, true); err != nil {
		t.Fatalf("full actual API current-source/service control refused: %v", err)
	}
	if err := natsResponseClientIncarnation(ctx, env, fixture, false); err != nil {
		t.Fatalf("original client process recheck refused: %v", err)
	}
	changedSlice, err := kube.DiscoveryV1().EndpointSlices(ns.Name).Get(ctx, endpointSlice.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	changedSlice.Endpoints[1].TargetRef.UID = "replacement-peer-uid"
	if _, err := kube.DiscoveryV1().EndpointSlices(ns.Name).Update(ctx, changedSlice, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := natsResponseCurrentControls(ctx, env, fixture, admittedSpec, true); err == nil {
		t.Fatal("actual API same-name replacement endpoint accepted as legitimate peer")
	}
	changedClient, err := kube.CoreV1().Pods(ns.Name).Get(ctx, fixture.Client.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	changedClient.Status.ContainerStatuses[0].RestartCount = 1
	if _, err := kube.CoreV1().Pods(ns.Name).UpdateStatus(ctx, changedClient, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := natsResponseClientIncarnation(ctx, env, fixture, false); err == nil {
		t.Fatal("same Pod UID with restarted observer container accepted as M1 source")
	}
	journal, err := os.ReadFile(filepath.Join(env.Config.OutDir, "nats-response-phases.jsonl"))
	if err != nil || len(journal) == 0 {
		t.Fatalf("fsynced create journal unavailable: %v", err)
	}
	lines := bytes.Split(bytes.TrimSuffix(journal, []byte{'\n'}), []byte{'\n'})
	if len(lines) != 12 {
		t.Fatalf("create journal rows=%d want five create pairs and one UID-bound role patch pair", len(lines))
	}
	for j, phase := range []string{"SOURCE_ROLE_PATCH_INTENT", "SOURCE_ROLE_PATCHED"} {
		var row struct {
			Phase, Resource, Name, UID string
		}
		if err := json.Unmarshal(lines[10+j], &row); err != nil || row.Phase != phase || row.Resource != "pods" ||
			row.Name != fixture.Client.Name || row.UID != string(fixture.Client.UID) {
			t.Fatalf("source role journal row not exact: %+v %v", row, err)
		}
	}
	for i, resource := range []string{"configmaps", "services", "poddisruptionbudgets", "phorvexpolicies", "deployments"} {
		for j, phase := range []string{"CREATE_INTENT", "CREATED"} {
			var row struct {
				Phase, Resource string
				UID             string
			}
			if err := json.Unmarshal(lines[i*2+j], &row); err != nil || row.Phase != phase || row.Resource != resource ||
				(j == 0 && row.UID != "") || (j == 1 && row.UID == "") {
				t.Fatalf("create journal row %d does not bind %s/%s: %+v %v", i*2+j, resource, phase, row, err)
			}
		}
	}
	journalPath := filepath.Join(env.Config.OutDir, "nats-response-phases.jsonl")
	link := filepath.Join(env.Config.OutDir, "linked-journal")
	if err := os.Link(journalPath, link); err != nil {
		t.Fatal(err)
	}
	if err := natsResponsePhase(env, "CREATED", "deployments", name, fixture.DeploymentUID); err == nil {
		t.Fatal("hard-linked phase journal accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(journalPath, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(link, journalPath); err != nil {
		t.Fatal(err)
	}
	if err := natsResponsePhase(env, "CREATED", "deployments", name, fixture.DeploymentUID); err == nil {
		t.Fatal("symbolic-linked phase journal accepted")
	}
}

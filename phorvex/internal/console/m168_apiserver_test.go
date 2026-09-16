package console

import (
	"context"
	"os"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestM168APIServerPolicyCASAndIdentity(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated local envtest API server")
	}
	e := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases", "../../../build/phoenix-extended/config/crd/bases"}, ErrorIfCRDPathMissing: true}
	cfg, err := e.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := e.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	}()
	d := dynamicExperimentCluster{cfg: cfg}
	cli, err := d.client()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	nsGVR := schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}
	if _, err = cli.Resource(nsGVR).Create(ctx, &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "voice"}}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	obj := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "phorvex.ai/v1alpha1", "kind": "PhorvexPolicy", "metadata": map[string]any{"name": "voice-policy", "namespace": "voice"}, "spec": map[string]any{"tenant": "voice", "selector": map[string]any{"matchLabels": map[string]any{"app": "voice"}}, "mode": "active", "actions": map[string]any{}, "assetValue": map[string]any{}, "budget": map[string]any{}, "objective": map[string]any{}, "slo": map[string]any{}, "triggers": map[string]any{}}}}
	if _, err = cli.Resource(phorvexPolicyGVR).Namespace("voice").Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	p, err := d.Policy(ctx, "voice")
	if err != nil {
		t.Fatal(err)
	}
	owned, err := d.SetPolicyMode(ctx, p, "dryRun", "op-1", false)
	if err != nil {
		t.Fatal(err)
	}
	if owned.Marker != "op-1" || owned.Mode != "dryRun" || owned.ResourceVersion == p.ResourceVersion {
		t.Fatalf("owned transition missing: %+v", owned)
	}
	if _, err = d.SetPolicyMode(ctx, p, "active", "op-1", true); err == nil {
		t.Fatal("stale resourceVersion patch succeeded")
	}
	if err = cli.Resource(phorvexPolicyGVR).Namespace("voice").Delete(ctx, p.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	obj.SetResourceVersion("")
	obj.SetUID("")
	if _, err = cli.Resource(phorvexPolicyGVR).Namespace("voice").Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = d.SetPolicyMode(ctx, owned, "active", "op-1", true); err == nil {
		t.Fatal("same-name replacement accepted old identity/version")
	}
}

func TestM168APIServerClusterScopedSignalCleanupRequiresAbsence(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated local envtest API server")
	}
	e := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases", "../../../build/phoenix-extended/config/crd/bases"}, ErrorIfCRDPathMissing: true}
	cfg, err := e.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := e.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	}()
	d := dynamicExperimentCluster{cfg: cfg}
	ctx := context.Background()
	uid, err := d.CreateEvent(ctx, "m168-signal", "op-1", "voice", "voice-0")
	if err != nil {
		t.Fatal(err)
	}
	gotUID, token, found, err := d.EventIdentity(ctx, "voice", "m168-signal")
	if err != nil || !found || gotUID != uid || token != "op-1" {
		t.Fatalf("cluster-scoped signal identity mismatch: uid=%q token=%q found=%v err=%v", gotUID, token, found, err)
	}
	cli, err := d.client()
	if err != nil {
		t.Fatal(err)
	}
	u, err := cli.Resource(securityEventGVR).Get(ctx, "m168-signal", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	u.SetFinalizers([]string{"test.phorvex.ai/retain"})
	if _, err = cli.Resource(securityEventGVR).Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	serverCfg := Config{StateDir: t.TempDir(), ExperimentRESTConfig: cfg, Sleep: func(time.Duration) {}}
	s := &Server{cfg: serverCfg, runs: NewRunManager(serverCfg)}
	receipt := experimentStimulusReceipt{Event: "m168-signal", EventUID: uid, Token: "op-1"}
	if err = s.cleanupExperimentSignal("voice", receipt); err == nil {
		t.Fatal("finalizer-retained signal was accepted as absent")
	}
	u, err = cli.Resource(securityEventGVR).Get(ctx, "m168-signal", metav1.GetOptions{})
	if err != nil || u.GetDeletionTimestamp() == nil {
		t.Fatalf("delete was not acknowledged by the API server: deletionTimestamp=%v err=%v", u.GetDeletionTimestamp(), err)
	}
	u.SetFinalizers(nil)
	if _, err = cli.Resource(securityEventGVR).Update(ctx, u, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err = s.cleanupExperimentSignal("voice", receipt); err != nil {
		t.Fatalf("cleanup did not observe final absence: %v", err)
	}
}

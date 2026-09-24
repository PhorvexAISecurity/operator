package scenarios

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
)

type natsReconcileGuard struct{}

func (natsReconcileGuard) AssertMutationAllowed(string) error { return nil }

func natsReconcileFixture(t *testing.T) (*core.Env, *k8sfake.Clientset, string, natsRouteIdentity) {
	t.Helper()
	const ns = "phorvex-nats-exposure-fixture"
	const nonce = "0123456789abcdef01234567"
	client := k8sfake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, UID: "namespace-original", Labels: map[string]string{"phorvex.ai/nats-exposure-fixture": "true"}}})
	out := t.TempDir()
	env := &core.Env{Kube: client, Guard: natsReconcileGuard{}, NATSFenceIdentity: "flock-v1:1:2", Config: config.TargetConfig{Namespace: ns, OutDir: out, NATSExposureFixture: &config.NATSExposureFixtureConfig{RunID: "run-4", Nonce: nonce, ClusterUID: "cluster-original"}}}
	if err := env.EnsureNamespace(context.Background()); err != nil {
		t.Fatal(err)
	}
	route := natsRouteIdentity{ClusterUID: "cluster-original", ServiceUID: "service-original"}
	anchor := natsRecoveryAnchor{Schema: "nats-baseline-anchor-v1", RunID: "run-4", Nonce: nonce, ClusterUID: route.ClusterUID, Namespace: ns, NamespaceUID: env.NamespaceUID(), ObserverName: "nats-observer-" + nonce, Stream: "CAT_" + nonce, Route: route, PID: 99999999, ProcessStartTicks: "123", FenceIdentity: env.NATSFenceIdentity}
	raw, err := json.Marshal(anchor)
	if err != nil || writeNATSBaselineArtifact(filepath.Join(out, "nats-baseline-anchor.json"), raw) != nil {
		t.Fatalf("write anchor: %v", err)
	}
	return env, client, out, route
}

func TestNATSReadOnlyReconciliationRequiresExactAbsentOwnedState(t *testing.T) {
	ctx := context.Background()
	env, client, out, route := natsReconcileFixture(t)
	routeSource := func(context.Context, *core.Env) (natsRouteIdentity, error) { return route, nil }
	checks := 0
	streamAbsent := func(_ context.Context, _ *core.Env, _ natsRouteIdentity, name string) error {
		checks++
		if name != "CAT_0123456789abcdef01234567" {
			t.Fatalf("wrong stream checked: %q", name)
		}
		return nil
	}
	if err := reconcileNATSWithSources(ctx, env, out, "0123456789abcdef0123456789abcdef", routeSource, streamAbsent); err != nil || checks != 1 {
		t.Fatalf("exact absence rejected: %v, checks=%d", err, checks)
	}
	for _, a := range client.Actions() {
		if a.GetVerb() != "get" {
			t.Fatalf("read-only reconciliation mutated Kubernetes: %#v", a)
		}
	}
	var receipt natsReconciliationReceipt
	raw, err := os.ReadFile(filepath.Join(out, "nats-baseline-reconciliation.json"))
	if err != nil || json.Unmarshal(raw, &receipt) != nil || !receipt.SafeToRetry || !receipt.StreamAbsent || receipt.NamespaceUID != "namespace-original" {
		t.Fatalf("reconciliation receipt incomplete: %+v %v", receipt, err)
	}
	if err := os.Remove(filepath.Join(out, "nats-baseline-anchor.json")); err != nil {
		t.Fatal(err)
	}
	if err := reconcileNATSWithSources(ctx, env, out, "0123456789abcdef0123456789abcdef", routeSource, streamAbsent); err == nil {
		t.Fatal("missing durable anchor accepted")
	}
}

func TestNATSReconciliationRejectsChangedRouteStreamAndNamespace(t *testing.T) {
	ctx := context.Background()
	env, client, out, route := natsReconcileFixture(t)
	changed := route
	changed.ServiceUID = "replacement-service"
	if err := reconcileNATSWithSources(ctx, env, out, "0123456789abcdef0123456789abcdef", func(context.Context, *core.Env) (natsRouteIdentity, error) { return changed, nil }, func(context.Context, *core.Env, natsRouteIdentity, string) error { return nil }); err == nil {
		t.Fatal("changed broker route accepted")
	}
	if err := reconcileNATSWithSources(ctx, env, out, "0123456789abcdef0123456789abcdef", func(context.Context, *core.Env) (natsRouteIdentity, error) { return route, nil }, func(context.Context, *core.Env, natsRouteIdentity, string) error { return errors.New("stream present") }); err == nil {
		t.Fatal("present or unverified stream accepted")
	}
	ns, err := client.CoreV1().Namespaces().Get(ctx, env.Config.Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ns.UID = types.UID("replacement-namespace")
	if _, err := client.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := reconcileNATSWithSources(ctx, env, out, "0123456789abcdef0123456789abcdef", func(context.Context, *core.Env) (natsRouteIdentity, error) { return route, nil }, func(context.Context, *core.Env, natsRouteIdentity, string) error { return nil }); err == nil {
		t.Fatal("same-name replacement fixture namespace accepted")
	}
}

func TestNATSReconciliationRejectsLegacyOrWrongProcessFence(t *testing.T) {
	ctx := context.Background()
	env, _, out, route := natsReconcileFixture(t)
	routeSource := func(context.Context, *core.Env) (natsRouteIdentity, error) { return route, nil }
	streamCheck := func(context.Context, *core.Env, natsRouteIdentity, string) error { return nil }
	env.NATSFenceIdentity = "flock-v1:1:3"
	if err := reconcileNATSWithSources(ctx, env, out, "0123456789abcdef0123456789abcdef", routeSource, streamCheck); err == nil {
		t.Fatal("replaced lock inode accepted")
	}
	env.NATSFenceIdentity = "flock-v1:1:2"
	path := filepath.Join(out, "nats-baseline-anchor.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var a map[string]any
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	delete(a, "fenceIdentity")
	raw, _ = json.Marshal(a)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := reconcileNATSWithSources(ctx, env, out, "0123456789abcdef0123456789abcdef", routeSource, streamCheck); err == nil {
		t.Fatal("legacy unfenced anchor accepted")
	}
}

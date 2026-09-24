package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
)

type natsTerminalGuard struct{}

func (natsTerminalGuard) AssertMutationAllowed(string) error { return nil }

type natsTerminalLogger struct{}

func (*natsTerminalLogger) Logf(string, ...any) {}
func (*natsTerminalLogger) Command(string)      {}
func (*natsTerminalLogger) Commands() []string  { return nil }
func (*natsTerminalLogger) RawLogPath() string  { return "" }

func natsTerminalEnv(t *testing.T) (*core.Env, *k8sfake.Clientset) {
	t.Helper()
	ns := "phorvex-nats-exposure-fixture"
	client := k8sfake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, UID: "namespace-original", Labels: map[string]string{"phorvex.ai/nats-exposure-fixture": "true"}}})
	env := &core.Env{Kube: client, Guard: natsTerminalGuard{}, Log: &natsTerminalLogger{}, Config: config.TargetConfig{Namespace: ns, NATSExposureFixture: &config.NATSExposureFixtureConfig{RunID: "run-4", Nonce: "0123456789abcdef01234567"}}}
	if err := env.EnsureNamespace(context.Background()); err != nil {
		t.Fatal(err)
	}
	return env, client
}

func natsTerminalArtifact(t *testing.T, env *core.Env, namespaceUID string) string {
	t.Helper()
	out := t.TempDir()
	raw, _ := json.Marshal(map[string]any{"runId": "run-4", "nonce": "0123456789abcdef01234567", "namespace": env.Config.Namespace, "namespaceUID": namespaceUID})
	if err := os.WriteFile(filepath.Join(out, "nats-baseline.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestNATSTerminalReceiptRequiresSameNamespaceAndExactResourceAbsence(t *testing.T) {
	ctx := context.Background()
	env, client := natsTerminalEnv(t)
	out := natsTerminalArtifact(t, env, string(env.NamespaceUID()))
	name := "nats-observer-" + env.Config.NATSExposureFixture.Nonce
	_, err := client.CoreV1().Pods(env.Config.Namespace).Create(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: env.Config.Namespace, UID: "present-pod"}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeNATSTerminalReceipt(ctx, env, out); err == nil {
		t.Fatal("present fixture Pod accepted as cleaned")
	}
	if err := client.CoreV1().Pods(env.Config.Namespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := writeNATSTerminalReceipt(ctx, env, out); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(out, "nats-baseline-terminal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		NamespaceUID           string `json:"namespaceUID"`
		ArtifactSHA256         string `json:"artifactSHA256"`
		FixtureResourcesAbsent bool   `json:"fixtureResourcesAbsent"`
		NamespacePreserved     bool   `json:"namespacePreserved"`
	}
	if json.Unmarshal(raw, &receipt) != nil || receipt.NamespaceUID != string(env.NamespaceUID()) || !receipt.FixtureResourcesAbsent || !receipt.NamespacePreserved || len(receipt.ArtifactSHA256) != 64 {
		t.Fatalf("terminal producer lost exact UID/digest: %+v", receipt)
	}
	if _, err := client.CoreV1().Namespaces().Get(ctx, env.Config.Namespace, metav1.GetOptions{}); err != nil {
		t.Fatalf("precreated fixture namespace deleted: %v", err)
	}
}

func TestNATSTerminalReceiptRejectsArtifactOrNamespaceReplacement(t *testing.T) {
	ctx := context.Background()
	env, client := natsTerminalEnv(t)
	out := natsTerminalArtifact(t, env, "replacement")
	if err := writeNATSTerminalReceipt(ctx, env, out); err == nil {
		t.Fatal("mismatched artifact namespace UID accepted")
	}
	out = natsTerminalArtifact(t, env, string(env.NamespaceUID()))
	ns, err := client.CoreV1().Namespaces().Get(ctx, env.Config.Namespace, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ns.UID = "same-name-replacement"
	if _, err := client.CoreV1().Namespaces().Update(ctx, ns, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := writeNATSTerminalReceipt(ctx, env, out); err == nil {
		t.Fatal("same-name replacement namespace accepted")
	}
}

func TestNATSClusterPinRejectsWrongUIDBeforeAnyMutation(t *testing.T) {
	ctx := context.Background()
	client := k8sfake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: "live-cluster-uid"}})
	cfg := config.TargetConfig{Context: "reviewed-dev-cluster", NATSExposureFixture: &config.NATSExposureFixtureConfig{Transport: "in-cluster", ClusterUID: "admitted-other-cluster"}}
	if err := assertNATSClusterPin(ctx, cfg, client); err == nil {
		t.Fatal("wrong cluster UID accepted")
	}
	for _, action := range client.Actions() {
		if action.GetVerb() != "get" || action.GetResource().Resource != "namespaces" {
			t.Fatalf("cluster refusal performed unexpected API action: %#v", action)
		}
	}
	cfg.NATSExposureFixture.ClusterUID = "live-cluster-uid"
	if err := assertNATSClusterPin(ctx, cfg, client); err != nil {
		t.Fatalf("matching cluster UID rejected: %v", err)
	}
	cfg.NATSExposureFixture.Transport = "other-transport"
	if err := assertNATSClusterPin(ctx, cfg, client); err == nil {
		t.Fatal("NATS fixture accepted unrelated context")
	}
	cfg.NATSExposureFixture = nil
	if err := assertNATSClusterPin(ctx, cfg, client); err != nil {
		t.Fatalf("ordinary suites changed by NATS pin: %v", err)
	}
}

func TestNATSRunContextUsesConfiguredBoundAndParentDeadline(t *testing.T) {
	start := time.Now()
	ctx, cancel := natsRunContext(context.Background(), &config.NATSExposureFixtureConfig{MaxRunSeconds: 60})
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || deadline.Before(start.Add(59*time.Second)) || deadline.After(start.Add(61*time.Second)) {
		t.Fatalf("configured NATS bound ignored: %v", deadline)
	}
	parent, stop := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer stop()
	child, childStop := natsRunContext(parent, &config.NATSExposureFixtureConfig{MaxRunSeconds: 600})
	defer childStop()
	parentDeadline, _ := parent.Deadline()
	childDeadline, _ := child.Deadline()
	if !parentDeadline.Equal(childDeadline) {
		t.Fatal("NATS child extended a shorter parent deadline")
	}
}

func TestNATSProcessFenceExcludesLiveRunAndBindsInode(t *testing.T) {
	out := t.TempDir()
	first, identity, err := acquireNATSFence(out)
	if err != nil || identity == "" {
		t.Fatalf("acquire original process fence: %v", err)
	}
	if second, _, err := acquireNATSFence(out); err == nil {
		second.Close()
		t.Fatal("second process acquired held NATS fence")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, same, err := acquireNATSFence(out)
	if err != nil || same != identity {
		t.Fatalf("stable fence inode unavailable after original exits: %s %v", same, err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(out, "nats-baseline.lock")); err != nil {
		t.Fatal(err)
	}
	replacement, changed, err := acquireNATSFence(out)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if changed == identity {
		t.Fatal("replaced lock inode retained original fence identity")
	}
}

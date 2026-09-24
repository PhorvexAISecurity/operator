package safety

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/r6security/phoenix-test-harness/internal/config"
)

// writeKubeconfig writes a minimal kubeconfig with one context -> cluster -> host.
func writeKubeconfig(t *testing.T, contextName, clusterName, host string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "kubeconfig")
	content := `
apiVersion: v1
kind: Config
current-context: ` + contextName + `
clusters:
- name: ` + clusterName + `
  cluster:
    server: ` + host + `
    insecure-skip-tls-verify: true
contexts:
- name: ` + contextName + `
  context:
    cluster: ` + clusterName + `
    user: u
users:
- name: u
  user:
    token: fake
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	return path
}

func baseCfg(kubeconfig, ctxName, ns string, ack bool) config.TargetConfig {
	return config.TargetConfig{
		Kubeconfig: kubeconfig,
		Context:    ctxName,
		Namespace:  ns,
		OwnedAck:   ack,
	}
}

func TestGuardRefusesMissingAck(t *testing.T) {
	kc := writeKubeconfig(t, "kind-amtd-test", "kind", "https://127.0.0.1:62067")
	cfg := baseCfg(kc, "kind-amtd-test", "sandbox", false)
	_, err := NewGuard(cfg, "kind-amtd-test", "https://127.0.0.1:62067")
	if !IsRefusal(err) {
		t.Fatalf("expected refusal for missing ack, got %v", err)
	}
}

func TestGuardRefusesWrongContext(t *testing.T) {
	kc := writeKubeconfig(t, "kind-amtd-test", "kind", "https://127.0.0.1:62067")
	cfg := baseCfg(kc, "kind-amtd-test", "sandbox", true)
	// Live context differs from the configured one.
	_, err := NewGuard(cfg, "some-other-context", "https://127.0.0.1:62067")
	if !IsRefusal(err) {
		t.Fatalf("expected refusal for wrong live context, got %v", err)
	}
}

func TestGuardRefusesWrongHost(t *testing.T) {
	kc := writeKubeconfig(t, "kind-amtd-test", "kind", "https://127.0.0.1:62067")
	cfg := baseCfg(kc, "kind-amtd-test", "sandbox", true)
	// Live host differs from the host declared for the named context.
	_, err := NewGuard(cfg, "kind-amtd-test", "https://10.0.0.1:6443")
	if !IsRefusal(err) {
		t.Fatalf("expected refusal for host mismatch, got %v", err)
	}
}

func TestGuardAllowsMatchingTarget(t *testing.T) {
	host := "https://127.0.0.1:62067"
	kc := writeKubeconfig(t, "kind-amtd-test", "kind", host)
	cfg := baseCfg(kc, "kind-amtd-test", "sandbox", true)
	g, err := NewGuard(cfg, "kind-amtd-test", host)
	if err != nil {
		t.Fatalf("guard should allow matching target: %v", err)
	}
	if g.LiveHost() != host {
		t.Fatalf("live host want %s got %s", host, g.LiveHost())
	}
}

func TestSandboxNamespaceGuard(t *testing.T) {
	host := "https://127.0.0.1:62067"
	kc := writeKubeconfig(t, "kind-amtd-test", "kind", host)
	cfg := baseCfg(kc, "kind-amtd-test", "sandbox", true)
	g, err := NewGuard(cfg, "kind-amtd-test", host)
	if err != nil {
		t.Fatalf("guard build: %v", err)
	}
	// Mutation in the sandbox namespace is allowed.
	if err := g.AssertMutationAllowed("sandbox"); err != nil {
		t.Fatalf("sandbox mutation must be allowed: %v", err)
	}
	// Mutation in ANY other namespace is REFUSED.
	if err := g.AssertMutationAllowed("kube-system"); !IsRefusal(err) {
		t.Fatalf("mutation outside sandbox must be refused, got %v", err)
	}
	if err := g.AssertMutationAllowed("default"); !IsRefusal(err) {
		t.Fatalf("mutation in default must be refused, got %v", err)
	}
}

func TestHostsEqualTolerance(t *testing.T) {
	if !hostsEqual("https://127.0.0.1:62067", "https://127.0.0.1:62067/") {
		t.Fatalf("trailing slash should be tolerated")
	}
	if hostsEqual("https://127.0.0.1:62067", "https://127.0.0.1:6443") {
		t.Fatalf("different ports must not be equal")
	}
	if hostsEqual("https://a.example", "https://b.example") {
		t.Fatalf("different hosts must not be equal")
	}
}

func TestPodBoundTokenUsesOnlyExplicitInClusterTransport(t *testing.T) {
	cfg := baseCfg("", "reviewed-voice", "voice", true)
	cfg.PodBoundTokenFixture = &config.PodBoundTokenFixtureConfig{}
	if !fixedInClusterFixture(cfg) {
		t.Fatal("named Pod token fixture did not select in-cluster transport")
	}
	cfg.Kubeconfig = "/unexpected/kubeconfig"
	if fixedInClusterFixture(cfg) {
		t.Fatal("Pod token fixture accepted an alternate kubeconfig")
	}
}

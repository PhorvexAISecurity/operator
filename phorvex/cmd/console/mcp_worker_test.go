package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/phorvex/phorvex/internal/cataloguev1"
)

func TestMCPSessionWorkerSelectsKubernetesRuntime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kubeconfig")
	config := []byte("apiVersion: v1\nkind: Config\nclusters:\n- name: fixed\n  cluster:\n    server: https://127.0.0.1:6443\ncontexts:\n- name: fixed\n  context:\n    cluster: fixed\n    user: fixed\ncurrent-context: fixed\nusers:\n- name: fixed\n  user: {}\n")
	if err := os.WriteFile(path, config, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := cataloguev1.RuntimeConfig{KubeconfigPath: path, KubeContext: "fixed"}
	restConfig, kube, err := workerKubernetesRuntime(cataloguev1.MCPSessionBaseline, cfg)
	if err != nil || restConfig == nil || kube == nil || restConfig.Host != "https://127.0.0.1:6443" {
		t.Fatalf("MCP worker lacks selected Kubernetes runtime: rest=%v kube=%v err=%v", restConfig != nil, kube != nil, err)
	}
	cfg.KubeconfigPath = filepath.Join(t.TempDir(), "missing")
	if restConfig, kube, err = workerKubernetesRuntime(cataloguev1.MCPSessionBaseline, cfg); err == nil || restConfig != nil || kube != nil {
		t.Fatalf("MCP worker did not read selected runtime authority: rest=%v kube=%v err=%v", restConfig != nil, kube != nil, err)
	}
	if restConfig, kube, err = workerKubernetesRuntime(cataloguev1.AuthUnauth, cfg); err != nil || restConfig != nil || kube != nil {
		t.Fatalf("HTTP-only worker unexpectedly selected Kubernetes runtime: rest=%v kube=%v err=%v", restConfig != nil, kube != nil, err)
	}
}

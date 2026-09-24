package main

import (
	"context"
	"errors"

	"github.com/r6security/phoenix-test-harness/internal/config"
	"github.com/r6security/phoenix-test-harness/internal/core"
	"github.com/r6security/phoenix-test-harness/internal/kube"
	"github.com/r6security/phoenix-test-harness/scenarios"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func assertMongoClusterPin(ctx context.Context, cfg config.TargetConfig, kc kubernetes.Interface) error {
	if cfg.MongoExposureFixture == nil {
		return nil
	}
	f := cfg.MongoExposureFixture
	if f.Transport != "in-cluster" || cfg.Context == "" || cfg.Context == "in-cluster" || cfg.Kubeconfig != "" {
		return errors.New("Mongo named suite requires explicit server-owned logical target and in-cluster transport")
	}
	ns, err := kc.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil || ns.UID == "" || string(ns.UID) != f.ClusterUID {
		return errors.New("Mongo installed cluster UID differs from server-owned admission pin")
	}
	return nil
}

func runMongoExposureCase(ctx context.Context, cfg config.TargetConfig, clients *kube.Clients, guard core.SafetyGuard, caps core.Capabilities) error {
	if cfg.MongoExposureFixture == nil || cfg.Namespace != "document-store" {
		return errors.New("Mongo named suite fixture missing")
	}
	// Read first and transfer the exact UID into Env's existing no-create path.
	// A missing or replaced namespace is a refusal, never a fresh namespace.
	ns, err := clients.Kube.CoreV1().Namespaces().Get(ctx, cfg.Namespace, metav1.GetOptions{})
	if err != nil || ns.UID == "" || ns.DeletionTimestamp != nil {
		return errors.New("Mongo existing namespace unavailable; no creation")
	}
	cfg.ExpectedNamespaceUID = string(ns.UID)
	env := &core.Env{Kube: clients.Kube, Ctrl: clients.Ctrl, Rest: clients.Rest, Config: cfg, Guard: guard, Caps: caps,
		ScenarioName: "c2-mongo-uncredentialed-service-exposure", DefenderName: "configuration-baseline", Trial: 0, RestConfigHost: clients.LiveHost}
	if err := env.EnsureNamespace(ctx); err != nil {
		return err
	}
	return scenarios.RunMongoExposure(ctx, env)
}

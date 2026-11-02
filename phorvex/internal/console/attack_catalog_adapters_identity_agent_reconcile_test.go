package console

import (
	"context"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

type agentRetryTestCluster struct {
	identityAgentCatalogueCluster
	safety     AttackCatalogRetrySafety
	gotProfile identityAgentServerProfile
	gotSignal  string
}

func (c *agentRetryTestCluster) reconcileRetrySafety(_ context.Context, p identityAgentServerProfile, signalName string) (AttackCatalogRetrySafety, error) {
	c.gotProfile, c.gotSignal = p, signalName
	return c.safety, nil
}

func TestAgentCatalogueRetryReconciliationIsWiredAndExact(t *testing.T) {
	server := NewServer(agentCatalogueTestConfig())
	for _, id := range agentActionCatalogueIDs {
		adapter, ok := server.attackCatalogAdapters.Lookup(id)
		if !ok {
			t.Fatalf("adapter %s is not registered", id)
		}
		if _, ok := attackCatalogReconcilerFor(adapter); !ok {
			t.Fatalf("agent-action adapter %s is not a retry reconciler", id)
		}
	}

	profile := identityTestProfile(t, identityCatalogueAgent)
	cluster := &agentRetryTestCluster{safety: AttackCatalogRetrySafety{Verified: true, RetrySafe: true}}
	binding := &identityAgentCatalogueBinding{cfg: agentCatalogueTestConfig(), fixedCluster: cluster}
	safety, err := binding.reconcileRetrySafety(context.Background(), profile,
		AttackCatalogResult{CatalogueID: profile.ID, Signal: AttackCatalogSignalResult{Name: "catalogue-event"}})
	if err != nil || !safety.RetrySafe || cluster.gotSignal != "catalogue-event" || cluster.gotProfile != agentCatalogueServerProfiles[profile.ID] {
		t.Fatalf("delegation safety=%+v err=%v signal=%q profile=%+v", safety, err, cluster.gotSignal, cluster.gotProfile)
	}
	if _, err := binding.reconcileRetrySafety(context.Background(), profile, AttackCatalogResult{CatalogueID: "AML.T0012"}); err == nil {
		t.Fatal("reconciliation accepted a different catalogue ID")
	}
}

func TestAgentCatalogueClusterRetryReconciliationRefusesResidue(t *testing.T) {
	profile := agentCatalogueServerProfiles[agentActionCatalogueIDs[0]]
	newCluster := func(events ...runtime.Object) *kubernetesAgentCatalogueCluster {
		dynamic := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
			map[schema.GroupVersionResource]string{securityEventGVR: "SecurityEventList"}, events...)
		return &kubernetesAgentCatalogueCluster{cfg: agentCatalogueTestConfig(), kube: kubefake.NewSimpleClientset(), dynamic: dynamic}
	}
	event := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "amtd.r6security.com/v1beta1", "kind": "SecurityEvent", "metadata": map[string]any{"name": "catalogue-event"}}}

	safety, err := newCluster(event).reconcileRetrySafety(context.Background(), profile, "catalogue-event")
	if err != nil || safety.RetrySafe || !strings.Contains(safety.Reason, "still present") {
		t.Fatalf("present event: safety=%+v err=%v", safety, err)
	}
	// Event absent but the fixture is not the clean reviewed one: never retry-safe.
	safety, err = newCluster().reconcileRetrySafety(context.Background(), profile, "catalogue-event")
	if err != nil || safety.RetrySafe || !strings.Contains(safety.Reason, "not clean or healthy") {
		t.Fatalf("unclean fixture: safety=%+v err=%v", safety, err)
	}
}

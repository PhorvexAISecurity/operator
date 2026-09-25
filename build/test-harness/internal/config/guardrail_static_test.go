package config

import (
	"os"
	"strings"
	"testing"
)

func TestGuardrailStaticShippedTemplateValidAfterReviewPins(t *testing.T) {
	raw, err := os.ReadFile("../../config.guardrail-confidentiality-static.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	uid := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	for placeholder, value := range map[string]string{
		"__SET_LOGICAL_CLUSTER_TARGET__":           "reviewed-cluster",
		"__SET_REVIEWED_KUBE_SYSTEM_UID__":         uid,
		"__SET_REVIEWED_VLLM_POD_NAME__":           "reviewed-vllm-pod",
		"__SET_REVIEWED_VLLM_POD_UID__":            uid,
		"__SET_REVIEWED_VLLM_SERVICE_UID__":        uid,
		"__SET_REVIEWED_GUARDRAIL_SOURCE_SHA256__": strings.Repeat("a", 64),
		"__SET_REVIEWED_GUARDRAIL_JOURNAL_NAME__":  "reviewed-gj",
		"__SET_REVIEWED_GUARDRAIL_JOURNAL_UID__":   uid,
		"__SET_REVIEWED_KV_JOURNAL_NAME__":         "reviewed-kj",
		"__SET_REVIEWED_KV_JOURNAL_UID__":          uid,
	} {
		s = strings.ReplaceAll(s, placeholder, value)
	}
	c, err := Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Validate(); err != nil {
		t.Fatalf("shipped static template cannot launch after pinning: %v", err)
	}
}

func TestGuardrailStaticRequiresExactReadOnlyPins(t *testing.T) {
	uid := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	base := WithDollarDefaults(TargetConfig{Kubeconfig: "", Context: "reviewed-cluster", Namespace: "vllm", OwnedAck: true, TrialsPerArm: 1, GuardrailStaticFixture: &GuardrailStaticFixtureConfig{RunID: "run-1", Transport: "in-cluster", ClusterUID: uid, PodName: "reviewed-vllm-pod", PodUID: uid, Variant: "pgv1", ServiceUID: uid, SourceSHA256: strings.Repeat("a", 64), GuardrailJournalName: "reviewed-gj", GuardrailJournalUID: uid, KVJournalName: "reviewed-kj", KVJournalUID: uid, MaxRunSeconds: 600}})
	if err := base.Validate(); err != nil {
		t.Fatalf("valid static fixture rejected: %v", err)
	}
	pgv2 := base
	pgv2Fixture := *base.GuardrailStaticFixture
	pgv2Fixture.Variant = "pgv2"
	pgv2.GuardrailStaticFixture = &pgv2Fixture
	if err := pgv2.Validate(); err != nil {
		t.Fatalf("exact pgv2 static fixture rejected: %v", err)
	}
	current := base
	currentFixture := *base.GuardrailStaticFixture
	currentFixture.Variant = "observe-current"
	current.GuardrailStaticFixture = &currentFixture
	if err := current.Validate(); err != nil {
		t.Fatalf("observe-current static fixture rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*TargetConfig)
	}{{"missing source", func(c *TargetConfig) { c.GuardrailStaticFixture.SourceSHA256 = "" }}, {"unknown variant", func(c *TargetConfig) { c.GuardrailStaticFixture.Variant = "pgv3" }}, {"missing variant", func(c *TargetConfig) { c.GuardrailStaticFixture.Variant = "" }}, {"wrong namespace", func(c *TargetConfig) { c.Namespace = "customer" }}, {"kubeconfig override", func(c *TargetConfig) { c.Kubeconfig = "/tmp/other" }}, {"extra scenario", func(c *TargetConfig) { c.ScenarioFilter = []string{"ai-probe"} }}, {"longer time", func(c *TargetConfig) { c.GuardrailStaticFixture.MaxRunSeconds = 601 }}} {
		t.Run(tc.name, func(t *testing.T) {
			copy := base
			fixture := *base.GuardrailStaticFixture
			copy.GuardrailStaticFixture = &fixture
			tc.change(&copy)
			if err := copy.Validate(); err == nil {
				t.Fatal("unsafe static fixture accepted")
			}
		})
	}
}

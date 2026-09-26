package config

import (
	"os"
	"strings"
	"testing"
)

func reviewedGuardrailOutputProfile(t *testing.T) TargetConfig {
	t.Helper()
	raw, err := os.ReadFile("../../config.guardrail-output-response.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	uid := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	image := "registry.example/reviewed@sha256:" + strings.Repeat("a", 64)
	for placeholder, value := range map[string]string{
		"__SET_LOGICAL_CLUSTER_TARGET__":           "reviewed-cluster",
		"__SET_REVIEWED_VLLM_POD_NAME__":           "support-fixture-1",
		"__SET_REVIEWED_MODEL_TARGET_POD_NAME__":   "reviewed-model-1",
		"__SET_REVIEWED_FIXTURE_SERVICE_NAME__":    "reviewed-fixture",
		"__SET_REVIEWED_MODEL_SERVICE_NAME__":      "reviewed-model",
		"__SET_REVIEWED_MANAGER_POD_NAME__":        "reviewed-manager-1",
		"__SET_REVIEWED_CONSOLE_DEPLOYMENT_NAME__": "reviewed-console",
		"__SET_REVIEWED_CONSOLE_EVENT_CREATOR__":   "system:serviceaccount:phorvex-system:reviewed-console",
		"__SET_REVIEWED_AUDIT_SOURCE_URL__":        "https://audit.phorvex-system.svc:8445",
		"__SET_REVIEWED_AUDIT_SERVER_DNS__":        "audit.phorvex-system.svc",
	} {
		s = strings.ReplaceAll(s, placeholder, value)
	}
	for _, placeholder := range []string{"KUBE_SYSTEM_UID", "VLLM_POD_UID", "VLLM_SERVICE_UID", "GUARDRAIL_SOURCE_CONFIGMAP_UID", "MODEL_TARGET_POD_UID", "MODEL_SERVICE_UID", "OUTPUT_POLICY_CONFIGMAP_UID", "MANAGER_POD_UID", "CONSOLE_DEPLOYMENT_UID", "POLICY_UID"} {
		s = strings.ReplaceAll(s, "__SET_REVIEWED_"+placeholder+"__", uid)
	}
	s = strings.ReplaceAll(s, "modelTargetPodUID: \""+uid+"\"", "modelTargetPodUID: \"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\"")
	for _, placeholder := range []string{"VLLM_IMAGE_ID", "SUPPORT_IMAGE_ID", "MODEL_TARGET_IMAGE_ID", "MANAGER_IMAGE_ID", "CONSOLE_IMAGE_ID"} {
		s = strings.ReplaceAll(s, "__SET_REVIEWED_"+placeholder+"__", image)
	}
	for _, placeholder := range []string{"GUARDRAIL_SOURCE_SHA256", "SUPPORT_SOURCE_SHA256", "OUTPUT_POLICY_RULE_SHA256"} {
		s = strings.ReplaceAll(s, "__SET_REVIEWED_"+placeholder+"__", strings.Repeat("a", 64))
	}
	s = strings.ReplaceAll(s, "__SET_REVIEWED_POLICY_GENERATION__", "1")
	c, err := Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGuardrailOutputReviewedProfileAndIsolation(t *testing.T) {
	c := reviewedGuardrailOutputProfile(t)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*TargetConfig)
	}{
		{"wrong source", func(c *TargetConfig) { c.GuardrailOutputFixture.SupportSourceSHA256 = "" }},
		{"wrong rule", func(c *TargetConfig) { c.GuardrailOutputFixture.OutputPolicyRuleSHA256 = "" }},
		{"wrong policy name", func(c *TargetConfig) { c.GuardrailOutputFixture.OutputPolicyConfigMapName = "other" }},
		{"active baseline", func(c *TargetConfig) { c.GuardrailOutputFixture.InitialActivationRevision = 1 }},
		{"same model pod", func(c *TargetConfig) { c.GuardrailOutputFixture.ModelTargetPodUID = c.GuardrailOutputFixture.PodUID }},
		{"v1 overlap", func(c *TargetConfig) { c.GuardrailStaticFixture = &GuardrailStaticFixtureConfig{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := c
			fixture := *c.GuardrailOutputFixture
			copy.GuardrailOutputFixture = &fixture
			tc.change(&copy)
			if err := copy.Validate(); err == nil {
				t.Fatal("unsafe output profile accepted")
			}
		})
	}
}

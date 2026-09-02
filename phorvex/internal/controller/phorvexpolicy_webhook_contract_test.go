package controller

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"sigs.k8s.io/yaml"
)

func TestGeneratedWebhookContractIsFailClosed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "webhook", "manifests.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var config admissionregistrationv1.ValidatingWebhookConfiguration
	if err := yaml.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Webhooks) != 1 {
		t.Fatalf("webhooks = %d, want 1", len(config.Webhooks))
	}
	hook := config.Webhooks[0]
	if hook.Name != "vphorvexpolicy.phorvex.ai" || hook.FailurePolicy == nil || *hook.FailurePolicy != admissionregistrationv1.Fail {
		t.Fatalf("webhook identity/failure policy = %q/%v", hook.Name, hook.FailurePolicy)
	}
	if hook.ClientConfig.Service == nil || hook.ClientConfig.Service.Path == nil || *hook.ClientConfig.Service.Path != policyValidationPath {
		t.Fatalf("service path = %+v, want %q", hook.ClientConfig.Service, policyValidationPath)
	}
	if len(hook.Rules) != 1 || len(hook.Rules[0].Operations) != 2 ||
		hook.Rules[0].Operations[0] != admissionregistrationv1.Create || hook.Rules[0].Operations[1] != admissionregistrationv1.Update {
		t.Fatalf("webhook operations = %+v, want CREATE/UPDATE", hook.Rules)
	}

	chart, err := os.ReadFile(filepath.Join("..", "..", "charts", "phorvex", "templates", "admission-webhook.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		policyValidationPath,
		"failurePolicy: Fail",
		`operations: ["CREATE", "UPDATE"]`,
		"caBundle:",
		"genSignedCert",
	} {
		if !strings.Contains(string(chart), required) {
			t.Fatalf("chart webhook template lacks %q", required)
		}
	}
}

package startupauthz

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"

	"github.com/phorvex/phorvex/api/v1alpha1"
	"github.com/phorvex/phorvex/internal/actuator"
)

func m093StartupConfig(t *testing.T, bindings []actuator.ServingSecurityBinding) *actuator.ServingSecurityConfig {
	t.Helper()
	payload, err := json.Marshal(struct {
		Version  int                               `json:"version"`
		Bindings []actuator.ServingSecurityBinding `json:"bindings"`
	}{Version: 1, Bindings: bindings})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "serving-security.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := actuator.LoadServingSecurityFile(path, actuator.ServingSecuritySecureRequired, "operator")
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestM093StartupRequiresOnlyConfiguredExactSecretGets(t *testing.T) {
	binding := func(policy, uid, secret string) actuator.ServingSecurityBinding {
		return actuator.ServingSecurityBinding{Namespace: "tenant", PolicyName: policy, PolicyUID: uid, ServiceAccount: "model-sa", ProfileID: policy, SecretName: secret, BearerKey: "bearer", CAKey: "ca.crt", ServerName: "model-admin.example"}
	}
	config := m093StartupConfig(t, []actuator.ServingSecurityBinding{
		binding("policy-a", "uid-a", "credential-a"),
		binding("policy-b", "uid-b", "credential-a"),
		binding("policy-c", "uid-c", "credential-b"),
	})
	reviews := &recordingSSAR{}
	_, err := Check(t.Context(), policyReader(t, policy("tenant", "p", v1alpha1.ModeActive, v1alpha1.ActionRotate)), reviews, Config{Backend: actuator.BackendNative, OperatorNamespace: "operator", ServingSecurity: config})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, attributes := range reviews.attributes {
		if attributes.Resource == "secrets" {
			if attributes.Namespace != "operator" || attributes.Verb != "get" || attributes.Name == "" || attributes.Subresource != "" {
				t.Fatalf("Secret authority was not exact get: %+v", attributes)
			}
			seen[attributes.Name]++
		}
	}
	if seen["credential-a"] != 1 || seen["credential-b"] != 1 || len(seen) != 2 {
		t.Fatalf("configured Secret requirements=%v", seen)
	}
}

func TestM093StartupNoBindingsAddsNoSecretAuthorityAndDenialFailsBoot(t *testing.T) {
	empty, err := actuator.LoadServingSecurityFile("", actuator.ServingSecuritySecureRequired, "operator")
	if err != nil {
		t.Fatal(err)
	}
	reviews := &recordingSSAR{}
	if _, err := Check(t.Context(), policyReader(t, policy("tenant", "p", v1alpha1.ModeActive, v1alpha1.ActionRotate)), reviews, Config{Backend: actuator.BackendNative, OperatorNamespace: "operator", ServingSecurity: empty}); err != nil {
		t.Fatal(err)
	}
	for _, attributes := range reviews.attributes {
		if attributes.Resource == "secrets" {
			t.Fatalf("empty secure configuration requested Secret authority: %+v", attributes)
		}
	}

	configured := m093StartupConfig(t, []actuator.ServingSecurityBinding{{Namespace: "tenant", PolicyName: "policy", PolicyUID: "uid", ServiceAccount: "model-sa", ProfileID: "profile", SecretName: "credential", BearerKey: "bearer", CAKey: "ca.crt", ServerName: "model-admin.example"}})
	phoenixReviews := &recordingSSAR{}
	if _, err := Check(t.Context(), policyReader(t, policy("tenant", "p", v1alpha1.ModeActive, v1alpha1.ActionRotate)), phoenixReviews, Config{Backend: actuator.BackendPhoenix, OperatorNamespace: "operator", ServingSecurity: configured}); err != nil {
		t.Fatal(err)
	}
	for _, attributes := range phoenixReviews.attributes {
		if attributes.Resource == "secrets" {
			t.Fatalf("Phoenix-only backend requested unused serving Secret authority: %+v", attributes)
		}
	}
	denied := &recordingSSAR{deny: func(attributes authorizationv1.ResourceAttributes) bool { return attributes.Resource == "secrets" }}
	if _, err := Check(t.Context(), policyReader(t, policy("tenant", "p", v1alpha1.ModeActive, v1alpha1.ActionRotate)), denied, Config{Backend: actuator.BackendNative, OperatorNamespace: "operator", ServingSecurity: configured}); err == nil {
		t.Fatal("denied exact Secret read did not fail startup")
	}
}

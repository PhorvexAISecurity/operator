package console

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLiteLiveReviewedProfileRejectsUnpinnedOrAmbiguousAuthority(t *testing.T) {
	hash := strings.Repeat("a", 64)
	image := "example.invalid/litellm@sha256:" + hash
	profile := liteLLMLiveProfile{
		Version: 1, ClusterUID: "cluster", NamespaceUID: "namespace", DeploymentUID: "deployment",
		ServiceUID: "service", SourceConfigMapUID: "source", SourceSHA256: hash,
		GatewayImage: image, ClientsConfigMapUID: "clients", ClientsSHA256: hash,
		PolicyConfigMapUID: "policy-cm", PolicyName: "litellm-trial", PolicyUID: "policy",
		PolicyGeneration: 1, ModelAlias: "gpt-4o-mini", AttackerSHA256: hash,
		ControlSHA256: strings.Repeat("b", 64),
		Pods: []liteLivePod{{Name: "pod-b", UID: "pod-b-uid", BackendImageID: image, GatewayImageID: image},
			{Name: "pod-a", UID: "pod-a-uid", BackendImageID: image, GatewayImageID: image}},
		EventCreator:        "system:serviceaccount:phorvex-system:phorvex-phorvex-console",
		AuditSourceIdentity: "reviewed-audit", MaxRunSeconds: 900,
	}
	encode := func(value liteLLMLiveProfile) []byte {
		b, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	got, err := parseLiteLiveProfile(encode(profile))
	if err != nil || got.Pods[0].Name != "pod-a" {
		t.Fatalf("valid pinned profile rejected or unsorted: %v", err)
	}
	invalid := profile
	invalid.GatewayImage = "example.invalid/litellm:latest"
	if _, err := parseLiteLiveProfile(encode(invalid)); err == nil {
		t.Fatal("mutable gateway image accepted")
	}
	invalid = profile
	invalid.Pods[1].UID = invalid.Pods[0].UID
	if _, err := parseLiteLiveProfile(encode(invalid)); err == nil {
		t.Fatal("ambiguous Pod incarnation accepted")
	}
	if _, err := parseLiteLiveProfile(append(encode(profile), []byte(`{"extra":true}`)...)); err == nil {
		t.Fatal("additional top-level JSON accepted")
	}
}

func TestLiteLiveJournalNameBindsPolicyAndClient(t *testing.T) {
	a := liteJournalName("policy-uid", strings.Repeat("a", 64))
	if !strings.HasPrefix(a, "phorvex-litellm-revoke-") || len(a) != len("phorvex-litellm-revoke-")+24 ||
		a == liteJournalName("other-policy", strings.Repeat("a", 64)) ||
		a == liteJournalName("policy-uid", strings.Repeat("b", 64)) {
		t.Fatal("protected journal identity not bound to policy and client")
	}
}

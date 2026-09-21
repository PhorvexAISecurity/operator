package disclosure

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/phorvex/phorvex/internal/model"
)

func validPayload() model.CompletedDisclosureV1 {
	now := time.Unix(100, 1).UTC()
	digest := strings.Repeat("a", 64)
	return model.CompletedDisclosureV1{
		SchemaVersion: model.CompletedDisclosureSchemaV1, EvidenceID: "evidence-1",
		PolicyEpoch:         model.PolicyEpoch{Namespace: "ns", Name: "policy", UID: "policy-uid", Generation: 2},
		DecisionAsset:       model.DecisionAssetIdentity{Namespace: "ns", Name: "pod", TargetUID: "pod-uid"},
		ImmediateController: model.ObjectIdentity{APIVersion: "apps/v1", Kind: "ReplicaSet", Namespace: "ns", Name: "rs", UID: "rs-uid"},
		StableWorkloadOwner: model.ObjectIdentity{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "ns", Name: "app", UID: "dep-uid"},
		ProtectedScope:      model.ProtectedScope{Tenant: "tenant", Asset: "synthetic/customer-row", Version: "v3", Property: "confidentiality"},
		Classification: model.DisclosureClassification{RuleVersion: "synthetic-v1", RuleDigest: digest,
			ObserverClass: model.CompletedDisclosureClass, ObserverIdentity: "system:serviceaccount:ns:observer"},
		Observation: model.DisclosureObservation{StartedAt: now, CompletedAt: now.Add(time.Second), StatusCode: 200,
			ExpectedBytes: 32, ObservedBytes: 32, ReachedEOF: true, ExpectedSHA256: digest, ObservedSHA256: digest},
		Synthetic: true,
	}
}

func TestM100CompletedDisclosureStrictContract(t *testing.T) {
	base := validPayload()
	raw, digest, err := Marshal(base)
	if err != nil || len(digest) != 64 {
		t.Fatalf("valid payload: digest=%q err=%v", digest, err)
	}
	parsed, canonical, parsedDigest, err := Parse(raw)
	if err != nil || parsed.EvidenceID != base.EvidenceID || string(canonical) != raw || parsedDigest != digest {
		t.Fatalf("round trip failed: %+v %q %q %v", parsed, canonical, parsedDigest, err)
	}
	cases := map[string]func(*model.CompletedDisclosureV1){
		"202":                       func(p *model.CompletedDisclosureV1) { p.Observation.StatusCode = 202 },
		"partial":                   func(p *model.CompletedDisclosureV1) { p.Observation.ObservedBytes-- },
		"extra":                     func(p *model.CompletedDisclosureV1) { p.Observation.ObservedBytes++ },
		"no EOF":                    func(p *model.CompletedDisclosureV1) { p.Observation.ReachedEOF = false },
		"wrong digest":              func(p *model.CompletedDisclosureV1) { p.Observation.ObservedSHA256 = strings.Repeat("b", 64) },
		"non synthetic":             func(p *model.CompletedDisclosureV1) { p.Synthetic = false },
		"missing observer identity": func(p *model.CompletedDisclosureV1) { p.Classification.ObserverIdentity = "" },
		"missing UID":               func(p *model.CompletedDisclosureV1) { p.StableWorkloadOwner.UID = "" },
		"backward interval": func(p *model.CompletedDisclosureV1) {
			p.Observation.CompletedAt = p.Observation.StartedAt.Add(-time.Second)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := base
			mutate(&p)
			if _, _, err := Marshal(p); err == nil {
				t.Fatal("invalid completed response accepted")
			}
		})
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	doc["body"] = "synthetic-secret"
	unknown, _ := json.Marshal(doc)
	if _, _, _, err := Parse(string(unknown)); err == nil {
		t.Fatal("unknown response body field accepted")
	}
}

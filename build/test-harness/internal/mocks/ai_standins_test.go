package mocks

import (
	"strings"
	"testing"
)

// These tests pin the BEHAVIOR of the AI stand-ins WITHOUT a live cluster: each
// stand-in's wire behavior is produced by a pure builder (the inference responder
// + work counter, the MCP tool manifest, the model registry golden/poisoned
// manifest, the retriever store/poison, the agent loop), so asserting the builders
// here proves the mocks "behave" and locks in the CONTAINMENT invariants
// (busybox-only, no real LLM/registry/cloud/network egress, distinct markers).

// TestInferenceServerAccruesWorkAndServesModelCard asserts the inference responder
// accrues work_accrued per request (the GPU-util CPU proxy) and serves a model card
// with the fake weights digest.
func TestInferenceServerAccruesWorkAndServesModelCard(t *testing.T) {
	s := simpleInferenceScript()
	for _, want := range []string{"/tmp/work_accrued", "prev + 1", MockWeightsDigest, "HTTP/1.0 200 OK", "nc -l -p $PORT"} {
		if !strings.Contains(s, want) {
			t.Errorf("inference script must contain %q, got: %q", want, s)
		}
	}
	assertNoNetworkEgress(t, "simpleInferenceScript", s)
}

// TestMCPServesToolManifest asserts the MCP responder serves a tools manifest and
// keeps it writable in /tmp (the tool-poisoning surface), and the rogue flavor
// writes its rogue id.
func TestMCPServesToolManifest(t *testing.T) {
	trusted := mcpScript(false)
	for _, want := range []string{"/tmp/tools_manifest", "tools", "HTTP/1.0 200 OK"} {
		if !strings.Contains(trusted, want) {
			t.Errorf("trusted MCP script must contain %q, got: %q", want, trusted)
		}
	}
	if strings.Contains(trusted, RogueServerMarker) {
		t.Errorf("trusted MCP script must NOT carry the rogue marker")
	}
	rogue := mcpScript(true)
	if !strings.Contains(rogue, RogueServerMarker) {
		t.Errorf("rogue MCP script must carry the rogue marker %q", RogueServerMarker)
	}
	assertNoNetworkEgress(t, "mcpScript", trusted)
}

// TestModelRegistryGoldenManifest asserts the model registry serves the signed
// golden digest by default and keeps a writable /tmp/manifest.json for the tamper
// oracle.
func TestModelRegistryGoldenManifest(t *testing.T) {
	s := modelRegistryScript()
	for _, want := range []string{GoldenModelDigest, "signature", "/tmp/manifest.json", "/tmp/served_digest", "HTTP/1.0 200 OK"} {
		if !strings.Contains(s, want) {
			t.Errorf("model registry script must contain %q, got: %q", want, s)
		}
	}
	if strings.Contains(s, PoisonedModelDigest) {
		t.Errorf("model registry must serve GOLDEN by default, not the poisoned digest")
	}
	assertNoNetworkEgress(t, "modelRegistryScript", s)
}

// TestRetrieverSeedsCorpus asserts the retriever seeds a benign corpus in
// /tmp/store.jsonl (the poison/tamper are appended observably at attack time).
func TestRetrieverSeedsCorpus(t *testing.T) {
	s := retrieverScript()
	for _, want := range []string{"/tmp/store.jsonl", "benign", "HTTP/1.0 200 OK"} {
		if !strings.Contains(s, want) {
			t.Errorf("retriever script must contain %q, got: %q", want, s)
		}
	}
	if strings.Contains(s, RAGPoisonMarker) || strings.Contains(s, EmbeddingTamperMarker) {
		t.Errorf("retriever must seed a CLEAN corpus (no poison/tamper at startup)")
	}
	assertNoNetworkEgress(t, "retrieverScript", s)
}

// TestAgentLoopIsContainmentSafe asserts the agent loop is a benign busybox loop
// that seeds its local memory/action files and never dials out.
func TestAgentLoopIsContainmentSafe(t *testing.T) {
	cmd := agentLoopScript()
	joined := strings.Join(cmd, " ")
	for _, want := range []string{"/tmp/agent_mem", "/tmp/agent_actions"} {
		if !strings.Contains(joined, want) {
			t.Errorf("agent loop must seed %q, got: %q", want, joined)
		}
	}
	assertNoNetworkEgress(t, "agentLoopScript", joined)
}

// TestAIDigestsAreFakeAndDistinct asserts the model digests are self-evidently
// mock and distinct (golden != poisoned != weights), so an oracle cannot confuse a
// poisoned serve with a golden one.
func TestAIDigestsAreFakeAndDistinct(t *testing.T) {
	for _, d := range []string{MockWeightsDigest, GoldenModelDigest, PoisonedModelDigest} {
		if !strings.Contains(d, "r6th") {
			t.Errorf("digest %q must be self-evidently a mock (contain r6th)", d)
		}
	}
	if GoldenModelDigest == PoisonedModelDigest || GoldenModelDigest == MockWeightsDigest || PoisonedModelDigest == MockWeightsDigest {
		t.Errorf("model digests must be distinct: weights=%q golden=%q poisoned=%q", MockWeightsDigest, GoldenModelDigest, PoisonedModelDigest)
	}
}

// TestAIMarkersAreDistinct asserts every AI observable marker is unique, so one
// scenario's oracle cannot cross-read another's marker (false-positive guard).
func TestAIMarkersAreDistinct(t *testing.T) {
	markers := map[string]string{
		"injection":      InjectionMarker,
		"rag-poison":     RAGPoisonMarker,
		"tool-poison":    ToolPoisonMarker,
		"rogue-server":   RogueServerMarker,
		"toolresp-inj":   ToolResponseInjMarker,
		"mem-contam":     MemoryContaminationMarker,
		"rogue-tool":     RogueToolMarker,
		"confused-deputy": ConfusedDeputyMarker,
		"agent-backdoor": AgentBackdoorMarker,
		"sensitive":      SensitiveSecretMarker,
		"system-prompt":  SystemPromptMarker,
		"kv-leak":        KVLeakMarker,
		"embed-tamper":   EmbeddingTamperMarker,
		"malicious-art":  MaliciousArtifactMarker,
		"shadow":         ShadowComputeMarker,
	}
	seen := map[string]string{}
	for name, v := range markers {
		if strings.TrimSpace(v) == "" {
			t.Errorf("AI marker %q is empty", name)
			continue
		}
		if prev, dup := seen[v]; dup {
			t.Errorf("AI marker collision: %q and %q share value %q", prev, name, v)
		}
		seen[v] = name
	}
}

// TestRotationTargetLabelKeyMatchesDefenders asserts the mocks-local
// RotationTargetLabelKey is the SAME value as defenders.RotationTargetLabel — the
// rotation arms only churn pods carrying this exact key, so a drift would silently
// stop the AI stand-ins from being rotated. (The defenders value is restated here
// by literal to avoid a defenders import in the low-level mocks package.)
func TestRotationTargetLabelKeyMatchesDefenders(t *testing.T) {
	const defendersRotationTargetLabel = "r6th.io/rotation-target"
	if RotationTargetLabelKey != defendersRotationTargetLabel {
		t.Fatalf("RotationTargetLabelKey %q must equal defenders.RotationTargetLabel %q", RotationTargetLabelKey, defendersRotationTargetLabel)
	}
}

// TestAIStandinsUseBusyboxOnly is a containment guard: every AI responder script is
// served by the pinned busybox image (no custom/exotic image), inherited from the
// shared deployServer path; assert the constant remains busybox-pinned.
func TestAIStandinsUseBusyboxOnly(t *testing.T) {
	if !strings.HasPrefix(BusyboxImage, "busybox:") || strings.HasSuffix(BusyboxImage, ":latest") {
		t.Fatalf("AI stand-ins must use a pinned busybox tag, got %q", BusyboxImage)
	}
}

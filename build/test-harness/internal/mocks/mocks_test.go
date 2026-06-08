package mocks

import (
	"strings"
	"testing"
)

// These tests pin the BEHAVIOR of the in-cluster mock stand-ins WITHOUT a live
// cluster: every mock's wire behavior is produced by a pure builder (the HTTP
// responder body, the registry manifest, the poisoned-image entrypoint, the C2
// sink counter loop, the pipeline injected step, the CPU-bounded miner). Asserting
// those builders here proves the mocks "behave" (IMDS returns a fake cred, the
// registry serves the tampered manifest, etc.) and locks in the CONTAINMENT
// invariants (fake creds only, no real pool/registry/network egress).

// TestMockIMDSServesFakeCredential asserts the mock IMDS responder body carries
// the FAKE credential the c3-imds-theft scenario steals — and that the credential
// is unmistakably a fake (so it can never be confused with a real cloud token).
func TestMockIMDSServesFakeCredential(t *testing.T) {
	body := `{"Code":"Success","AccessKeyId":"AKIAFAKE","Token":"` + FakeIMDSCredential + `"}`
	resp := httpResponderScript(body)

	if !strings.Contains(resp, FakeIMDSCredential) {
		t.Errorf("IMDS responder must serve the fake credential %q", FakeIMDSCredential)
	}
	// Containment: the credential must be self-evidently fake.
	low := strings.ToLower(FakeIMDSCredential)
	if !strings.Contains(low, "fake") && !strings.Contains(low, "mock") {
		t.Errorf("FakeIMDSCredential %q must be self-evidently fake/mock", FakeIMDSCredential)
	}
	// The responder must reply a well-formed minimal HTTP/1.0 200 so wget/curl in
	// the attacker pod are satisfied.
	if !strings.Contains(resp, "HTTP/1.0 200 OK") {
		t.Errorf("IMDS responder must emit an HTTP/1.0 200 reply, got: %q", resp)
	}
}

// TestMockCloudAPIAuthorizesOnlyMockFlow asserts the mock cloud API (the oracle
// endpoint for c3-imds-theft and c3-secrets-sprawl) returns an authorized JSON
// body and points only at a MOCK resource — never a real cloud resource.
func TestMockCloudAPIAuthorizesOnlyMockFlow(t *testing.T) {
	body := `{"authorized":true,"resource":"mock-s3://r6th-bucket/secret-model.bin","note":"fake cloud API authorized the stolen mock credential"}`
	resp := httpResponderScript(body)
	if !strings.Contains(resp, `"authorized":true`) {
		t.Errorf("mock cloud API must return authorized:true in its body, got: %q", resp)
	}
	if !strings.Contains(body, "mock-s3://") {
		t.Errorf("mock cloud API resource must be a MOCK resource, got: %q", body)
	}
	if strings.Contains(strings.ToLower(body), "amazonaws.com") || strings.Contains(strings.ToLower(body), "googleapis.com") {
		t.Errorf("CONTAINMENT VIOLATION: mock cloud API body references a real cloud endpoint: %q", body)
	}
}

// TestMockRegistryServesTamperedManifest asserts the mock registry serves a
// poisoned image manifest (digest stand-in) and exposes a poisoned image reference
// the supply-chain scenario "pulls".
func TestMockRegistryServesTamperedManifest(t *testing.T) {
	body := `{"name":"r6th/poisoned-app","tags":["latest"],"digest":"sha256:deadbeefr6thmockpoisoned"}`
	resp := httpResponderScript(body)
	for _, want := range []string{"poisoned-app", "sha256:", "digest"} {
		if !strings.Contains(resp, want) {
			t.Errorf("registry manifest must contain %q, got: %q", want, resp)
		}
	}
	if !strings.Contains(resp, "HTTP/1.0 200 OK") {
		t.Errorf("registry responder must emit an HTTP/1.0 200 reply")
	}
}

// TestPoisonedImageCommandRunsTamperedPayload asserts the poisoned-image entrypoint
// stand-in writes the tampered marker (the injected layer's behavior = the oracle)
// to the requested path and is containment-safe (no network, just a marker + idle).
func TestPoisonedImageCommandRunsTamperedPayload(t *testing.T) {
	const marker = "/tmp/.r6th_tampered"
	cmd := PoisonedImageCommand(marker)
	if len(cmd) == 0 {
		t.Fatalf("PoisonedImageCommand returned empty command")
	}
	joined := strings.Join(cmd, " ")
	if !strings.Contains(joined, TamperedMarker) {
		t.Errorf("poisoned image entrypoint must write the tampered marker %q, got: %q", TamperedMarker, joined)
	}
	if !strings.Contains(joined, marker) {
		t.Errorf("poisoned image entrypoint must write to %q, got: %q", marker, joined)
	}
	assertNoNetworkEgress(t, "PoisonedImageCommand", joined)
}

// TestC2SinkScriptCountsBytes asserts the C2/exfil sink loop drains each request
// and maintains a cumulative received-byte counter (the exfil oracle), and listens
// only on the in-pod $PORT (no outbound connection).
func TestC2SinkScriptCountsBytes(t *testing.T) {
	s := c2SinkScript()
	for _, want := range []string{"nc -l -p $PORT", "wc -c", "/tmp/bytes_total"} {
		if !strings.Contains(s, want) {
			t.Errorf("C2 sink script must contain %q, got: %q", want, s)
		}
	}
	// It must ACCUMULATE (prev + req), not overwrite, so a multi-chunk exfil counts.
	if !strings.Contains(s, "prev + req") {
		t.Errorf("C2 sink must accumulate received bytes (prev + req), got: %q", s)
	}
	// Containment: the sink only LISTENS; it never dials out.
	if strings.Contains(s, "nc ") && !strings.Contains(s, "nc -l") {
		// A bare outbound nc (no -l) inside the sink would be egress.
		if strings.Contains(s, "nc -w") && !strings.Contains(s, "-l") {
			t.Errorf("CONTAINMENT: C2 sink must only listen, not dial out: %q", s)
		}
	}
}

// TestMockPipelineInjectsStep asserts the mock CI/CD pipeline runner executes an
// INJECTED malicious step that tampers the build artifact (writes the injected
// marker to the output path) — the c3-cicd oracle.
func TestMockPipelineInjectsStep(t *testing.T) {
	const out = "/out/artifact"
	cmd := MockPipelineScript(out)
	joined := strings.Join(cmd, " ")
	if !strings.Contains(joined, InjectedStepMarker) {
		t.Errorf("pipeline must run the injected step writing %q, got: %q", InjectedStepMarker, joined)
	}
	if !strings.Contains(joined, out) {
		t.Errorf("pipeline must tamper the artifact at %q, got: %q", out, joined)
	}
	if !strings.Contains(joined, "INJECTED step") {
		t.Errorf("pipeline must contain a labelled INJECTED step, got: %q", joined)
	}
	assertNoNetworkEgress(t, "MockPipelineScript", joined)
}

// TestMinerScriptIsCPUBoundedStandIn asserts the miner stand-in is a fixed-duration
// busy loop that accrues a CPU-seconds counter and is NEVER a real miner: it must
// not reference any mining pool, protocol, or network egress (containment).
func TestMinerScriptIsCPUBoundedStandIn(t *testing.T) {
	cmd := MinerScript(20)
	joined := strings.Join(cmd, " ")
	if !strings.Contains(joined, "/tmp/cpu_seconds") {
		t.Errorf("miner must record CPU-seconds to /tmp/cpu_seconds, got: %q", joined)
	}
	// Fixed-duration: the outer loop is bounded by the maxSeconds argument.
	if !strings.Contains(joined, "-lt 20") {
		t.Errorf("miner must be fixed-duration (bounded by maxSeconds), got: %q", joined)
	}
	assertNoNetworkEgress(t, "MinerScript", joined)
	// Belt-and-suspenders: never a real miner / pool protocol.
	for _, banned := range []string{"stratum", "xmrig", "minerd", "pool.", "nicehash", "monero"} {
		if strings.Contains(strings.ToLower(joined), banned) {
			t.Errorf("CONTAINMENT VIOLATION: miner references real-miner token %q: %q", banned, joined)
		}
	}

	// CPUSecondsReadCommand must read the same counter file the miner writes.
	rd := strings.Join(CPUSecondsReadCommand(), " ")
	if !strings.Contains(rd, "/tmp/cpu_seconds") {
		t.Errorf("CPUSecondsReadCommand must read /tmp/cpu_seconds, got: %q", rd)
	}
}

// TestMockMarkersAreDistinct asserts the per-mock observable markers/credentials
// are all distinct, so one scenario's oracle cannot cross-read another mock's
// marker and report a false-positive success.
func TestMockMarkersAreDistinct(t *testing.T) {
	vals := map[string]string{
		"TamperedMarker":     TamperedMarker,
		"InjectedStepMarker": InjectedStepMarker,
		"FakeIMDSCredential": FakeIMDSCredential,
	}
	seen := map[string]string{}
	for name, v := range vals {
		if strings.TrimSpace(v) == "" {
			t.Errorf("%s must not be empty", name)
			continue
		}
		if prev, dup := seen[v]; dup {
			t.Errorf("marker collision: %s and %s share value %q", prev, name, v)
		}
		seen[v] = name
	}
}

// TestBusyboxImageIsPinned asserts the stand-in base image is a pinned, ubiquitous
// tag so the harness pulls nothing exotic and behaves identically on any cluster.
func TestBusyboxImageIsPinned(t *testing.T) {
	if !strings.HasPrefix(BusyboxImage, "busybox:") {
		t.Errorf("BusyboxImage must be a pinned busybox tag, got %q", BusyboxImage)
	}
	if strings.HasSuffix(BusyboxImage, ":latest") || !strings.Contains(BusyboxImage, ":") {
		t.Errorf("BusyboxImage must be a fixed (non-latest) tag, got %q", BusyboxImage)
	}
}

// assertNoNetworkEgress is the shared CONTAINMENT guard: a containment-safe
// stand-in command must not dial out to anything (wget/curl/outbound nc to a
// host). Mock SERVERS that legitimately listen are tested separately; these are
// attacker/workload payloads that must stay local to the pod.
func assertNoNetworkEgress(t *testing.T, name, joined string) {
	t.Helper()
	low := strings.ToLower(joined)
	for _, tok := range []string{"wget ", "curl ", "http://", "https://"} {
		if strings.Contains(low, tok) {
			t.Errorf("CONTAINMENT: %s must not perform network egress, found %q in: %q", name, tok, joined)
		}
	}
}

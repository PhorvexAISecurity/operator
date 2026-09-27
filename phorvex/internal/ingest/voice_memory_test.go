package ingest

import (
	"strings"
	"testing"
)

func TestVoiceMemoryObservationPayloadExactShape(t *testing.T) {
	valid := `{"version":1,"scenarioId":"voice-live","caseId":"owned-note","callerId":"+15551234567","noteSHA256":"` + strings.Repeat("a", 64) + `","deploymentUID":"11111111-1111-4111-8111-111111111111","podUID":"pod-uid","sourceSHA256":"` + strings.Repeat("b", 64) + `","policyName":"policy","policyUID":"22222222-2222-4222-8222-222222222222","policyGeneration":1,"observedAt":"2026-09-27T00:00:00Z","evidenceSource":"TEST_INJECTED","observed":true}`
	if _, ok := decodeVoiceMemoryPayload(valid); !ok {
		t.Fatal("exact producer payload rejected")
	}
	for name, raw := range map[string]string{
		"duplicate": strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		"unknown":   strings.Replace(valid, `"observed":true`, `"observed":true,"unexpected":1`, 1),
		"trailing":  valid + `{}`,
		"oversize":  valid + strings.Repeat("x", 2049),
	} {
		if _, ok := decodeVoiceMemoryPayload(raw); ok {
			t.Fatalf("%s payload accepted", name)
		}
	}
}

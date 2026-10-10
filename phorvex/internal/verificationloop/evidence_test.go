package verificationloop

import (
	"encoding/json"
	"math"
	"testing"
	"time"
)

func TestProbeAcceptanceDistinguishesAdmissionFromOutageAndBackendRefusal(t *testing.T) {
	makeProbe := func(status, before, after int, body string) Probe {
		return Probe{Name: "A", Status: status, Body: json.RawMessage(body), BodySHA256: SHA256([]byte(body)), BeforeCalls: before, AfterCalls: after, Nonce: "fresh", LatencyMS: 1}
	}
	for _, tc := range []struct {
		name          string
		p             Probe
		allowed, want bool
	}{
		{"real-denial", makeProbe(401, 7, 7, `{"error":"unauthorized"}`), false, true},
		{"authority-outage", makeProbe(503, 7, 7, `{"error":"lease_unavailable"}`), false, false},
		{"wrong-denial", makeProbe(403, 7, 7, `{"error":"forbidden"}`), false, false},
		{"backend-denial", makeProbe(401, 7, 8, `{"error":"unauthorized"}`), false, false},
		{"attack-still-landed", makeProbe(200, 7, 8, `{"marker":"verification-loop-synthetic-downstream","nonce":"fresh","call_count":8}`), false, false},
		{"legitimate", makeProbe(200, 7, 8, `{"marker":"verification-loop-synthetic-downstream","nonce":"fresh","call_count":8}`), true, true},
		{"cached-success", makeProbe(200, 7, 7, `{"marker":"verification-loop-synthetic-downstream","nonce":"fresh","call_count":8}`), true, false},
		{"nonce-replay", makeProbe(200, 7, 8, `{"marker":"verification-loop-synthetic-downstream","nonce":"old"}`), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateProbe(tc.p, tc.allowed, 2*time.Second)
			if (err == nil) != tc.want {
				t.Fatalf("accepted=%v want=%v: %v", err == nil, tc.want, err)
			}
		})
	}
}

func TestProbeAcceptanceRequiresDigestAndLatency(t *testing.T) {
	body := json.RawMessage(`{"marker":"verification-loop-synthetic-downstream","nonce":"n","call_count":1}`)
	p := Probe{Name: "B", Status: 200, Nonce: "n", BeforeCalls: 0, AfterCalls: 1, Body: body, BodySHA256: SHA256(body), LatencyMS: 2001}
	if ValidateProbe(p, true, 2*time.Second) == nil {
		t.Fatal("latency violation accepted")
	}
	p.LatencyMS = 1
	p.BodySHA256 = "tampered"
	if ValidateProbe(p, true, 2*time.Second) == nil {
		t.Fatal("tampered body accepted")
	}
}

func TestProbeAcceptanceBindsParsedAndRawBody(t *testing.T) {
	raw := `{"marker":"verification-loop-synthetic-downstream","nonce":"n","call_count":1}`
	p := Probe{Name: "B", Status: 200, Nonce: "n", BeforeCalls: 0, AfterCalls: 1, Body: json.RawMessage(raw), RawBody: `{"error":"lease_unavailable"}`, LatencyMS: 1}
	p.BodySHA256 = SHA256([]byte(p.RawBody))
	if ValidateProbe(p, true, 2*time.Second) == nil {
		t.Fatal("independently forged parsed body accepted")
	}
}

func TestProbeAcceptanceSurvivesEvidenceSerialization(t *testing.T) {
	raw := `{"call_count":1,"marker":"verification-loop-synthetic-downstream","nonce":"n"}`
	p := Probe{Name: "B", Status: 200, Nonce: "n", AfterCalls: 1, Body: json.RawMessage(raw), RawBody: raw, BodySHA256: SHA256([]byte(raw)), LatencyMS: 1}
	encoded, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var decoded Probe
	if err = json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if err = ValidateProbe(decoded, true, time.Second); err != nil {
		t.Fatalf("serialized valid evidence refused: %v", err)
	}
}

func TestProbeAcceptanceRejectsInvalidMeasurements(t *testing.T) {
	raw := `{"error":"unauthorized"}`
	base := Probe{Name: "A", Status: 401, BeforeCalls: 1, AfterCalls: 1, Body: json.RawMessage(raw), BodySHA256: SHA256([]byte(raw)), LatencyMS: 1}
	for _, latency := range []float64{-1, math.NaN(), math.Inf(1)} {
		p := base
		p.LatencyMS = latency
		if ValidateProbe(p, false, time.Second) == nil {
			t.Fatalf("invalid latency %v accepted", latency)
		}
	}
	p := base
	p.BeforeCalls = -1
	p.AfterCalls = -1
	if ValidateProbe(p, false, time.Second) == nil {
		t.Fatal("negative counters accepted")
	}
	if ValidateProbe(base, false, 0) == nil {
		t.Fatal("zero budget accepted")
	}
}

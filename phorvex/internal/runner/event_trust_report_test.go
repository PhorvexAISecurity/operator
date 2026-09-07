package runner

import (
	"strings"
	"testing"

	"github.com/go-logr/logr/funcr"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

// PHORVEXSEC-193 / M-94: an unattributed SecurityEvent stream is reported once per transition,
// not once per tick, and clears with one line.
func TestUntrustedEventStreamIsReportedOncePerTransition(t *testing.T) {
	var lines []string
	m := &Manager{Log: funcr.New(func(prefix, args string) { lines = append(lines, args) }, funcr.Options{})}

	forged := []model.SecurityEventInfo{
		{Name: "v10-forged", Source: "K3Detector", Trust: ingest.TrustUnstamped},
		{Name: "kv-1", Source: "kv-canary", Trust: ingest.TrustTrusted},
	}
	for i := 0; i < 100; i++ {
		m.observeEventTrust(forged)
	}
	errs := 0
	for _, l := range lines {
		if strings.Contains(l, "carry NO belief evidence") {
			errs++
		}
	}
	if errs != 1 {
		t.Fatalf("100 ticks with an untrusted stream produced %d reports, want exactly 1", errs)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "v10-forged") {
		t.Fatalf("the report must name the offending event:\n%s", strings.Join(lines, "\n"))
	}

	before := len(lines)
	m.observeEventTrust([]model.SecurityEventInfo{{Name: "kv-1", Trust: ingest.TrustTrusted}})
	m.observeEventTrust([]model.SecurityEventInfo{{Name: "kv-1", Trust: ingest.TrustTrusted}})
	cleared := 0
	for _, l := range lines[before:] {
		if strings.Contains(l, "fully attributed again") {
			cleared++
		}
	}
	if cleared != 1 {
		t.Fatalf("recovery produced %d lines, want exactly 1", cleared)
	}
}

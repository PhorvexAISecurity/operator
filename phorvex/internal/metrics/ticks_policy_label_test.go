package metrics

import (
	"testing"

	dto "github.com/prometheus/client_model/go"
)

func counterValue(t *testing.T, tenant, policy string) float64 {
	t.Helper()
	var m dto.Metric
	if err := ticksTotal.WithLabelValues(tenant, policy).Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

// PHORVEXSEC-205 / M-145: two policies sharing one tenant name must not collapse into one
// phorvex_ticks_total series.
func TestTicksTotalCarriesPolicyLabel(t *testing.T) {
	PublishTick("voice", "voice-defense", nil, nil, 0, 0.01, "dryRun")
	PublishTick("voice", "voice-defense", nil, nil, 0, 0.01, "dryRun")
	PublishTick("voice", "voice-canary", nil, nil, 0, 0.01, "dryRun")
	if got := counterValue(t, "voice", "voice-defense"); got != 2 {
		t.Fatalf("voice/voice-defense ticks = %v, want 2", got)
	}
	if got := counterValue(t, "voice", "voice-canary"); got != 1 {
		t.Fatalf("voice/voice-canary ticks = %v, want 1 (series must not collapse by tenant name)", got)
	}
}

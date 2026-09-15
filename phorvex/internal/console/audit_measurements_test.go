package console

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditFieldAvailableHonorsMeasurementEnvelope(t *testing.T) {
	measuredZero := map[string]any{"perDollar": float64(0), "measurements": map[string]any{"perDollar": map[string]any{"present": true, "value": float64(0)}}}
	if !auditFieldAvailable(measuredZero, "perDollar") {
		t.Fatal("measured zero reported unavailable")
	}
	unavailable := map[string]any{"measurements": map[string]any{"perDollar": map[string]any{"present": false, "value": float64(0)}}}
	if auditFieldAvailable(unavailable, "perDollar") {
		t.Fatal("unavailable field reported as measured zero")
	}
	legacy := map[string]any{"perDollar": float64(2)}
	if !auditFieldAvailable(legacy, "perDollar") {
		t.Fatal("explicit legacy scalar was discarded")
	}
	legacyNull := map[string]any{"perDollar": nil}
	if auditFieldAvailable(legacyNull, "perDollar") {
		t.Fatal("legacy null was treated as a measurement")
	}
}

func TestRedteamLivePreservesMeasuredZeroThroughHTTPAndRender(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out-redteam-live-pump")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	line := `{"pod":"target-fh","action":"rotate","actuated":true,"perDollar":0,"lambda":0,"measurements":{"perDollar":{"present":true,"value":0},"lambda":{"present":true,"value":0}}}`
	if err := os.WriteFile(filepath.Join(path, "phorvex-audit-d-phorvex.jsonl"), []byte(line+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	NewServer(Config{HarnessDir: dir}).redteamLive(w, httptest.NewRequest("GET", "/api/redteam/live", nil))
	var body struct {
		Proofs []struct {
			PerDollar          float64 `json:"perDollar"`
			PerDollarAvailable bool    `json:"perDollarAvailable"`
			LambdaMax          float64 `json:"lambdaMax"`
			LambdaAvailable    bool    `json:"lambdaAvailable"`
		} `json:"proofs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Proofs) != 1 || !body.Proofs[0].PerDollarAvailable || !body.Proofs[0].LambdaAvailable || body.Proofs[0].PerDollar != 0 || body.Proofs[0].LambdaMax != 0 {
		t.Fatalf("measured zero lost at HTTP boundary: %s", w.Body.String())
	}
	for _, want := range []string{"p.perDollarAvailable?p.perDollar.toFixed(2):'—'", "p.lambdaAvailable?p.lambdaMax.toFixed(2):'—'", "p.perDollarAvailable?p.perDollar.toFixed(2):\"unavailable\""} {
		if !strings.Contains(redteamHTML, want) {
			t.Fatalf("render path ignores availability token %q", want)
		}
	}
}

package identityfixture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"sigs.k8s.io/yaml"
)

// TestStagingRenderProfileLoadsAsBindToLive is the chart/render profile guard.
// The phorvex-sensor and phorvex-attacks identity-fixture ConfigMaps both render
// `profile.json: {{ .Values.phorvex.identityRotate.profile | toJson | quote }}`,
// and the runtime reads that file with LoadFile. This test reproduces that path
// against the committed staging values so a drift between the render profile and
// the loader (the kind that pinned a stale generation) fails here, not in prod.
func TestStagingRenderProfileLoadsAsBindToLive(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "environments", "staging", "phorvex.yaml"))
	if err != nil {
		t.Fatalf("read staging values: %v", err)
	}
	var doc struct {
		Phorvex struct {
			IdentityRotate struct {
				Enabled bool    `json:"enabled"`
				Profile Profile `json:"profile"`
			} `json:"identityRotate"`
		} `json:"phorvex"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode staging values: %v", err)
	}
	ir := doc.Phorvex.IdentityRotate
	if !ir.Enabled {
		t.Fatal("staging identityRotate is not enabled")
	}
	// Mimic the chart's `toJson` of the profile map, then the runtime's LoadFile.
	rendered, err := json.Marshal(ir.Profile)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(path, rendered, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatalf("rendered staging profile did not load: %v (rendered=%s)", err, rendered)
	}
	if loaded.PolicyGeneration != 0 {
		t.Fatalf("staging render pins a static policy generation (%d); it must be 0 to bind to the live policy", loaded.PolicyGeneration)
	}
	if loaded.Namespace != "console-identity-shared" || loaded.PolicyName != "console-id-fixture" || loaded.PolicyUID == "" {
		t.Fatalf("staging render lost the pinned policy identity: %+v", loaded)
	}
}

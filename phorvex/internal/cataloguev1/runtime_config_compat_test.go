package cataloguev1

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// This is the compact JSON persisted by the pre-calibration RuntimeConfig.
// Its SHA is a pending-job authority, so an absent new field must remain absent.
const legacyRuntimeJSON = `{"version":1,"stateDir":"/tmp/legacy","fixedLoopback":"","scopedTokenFile":"","allowedTenant":"","deniedTenant":"","deniedTarget":"","expectedSubject":"","grantFile":"","voice":{"enabled":false,"namespace":"","deployment":"","service":"","container":"","servicePort":0,"pdb":"","transcriptPodSelector":"","transcriptContainer":""},"gpu":{"enabled":false,"namespace":"","fixtureConfigFile":"","harnessBinary":"","harnessDir":"","kubeconfigPath":"","kubeContext":""}}`
const legacyRuntimeSHA = "e2d4820a04a5248c44db9f44bae8e1309659e1eaf4c4bb5a7f91a4629e501461"

func TestLegacyRuntimeConfigHashSurvivesGuardrailField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	if err := os.WriteFile(path, []byte(legacyRuntimeJSON+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadRuntimeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Guardrail != nil || config.MCP != nil || config.Chroma != nil || config.LiteLLM != nil {
		t.Fatal("absent legacy optional runtime field became nonnil")
	}
	got, err := config.SHA256()
	if err != nil || got != legacyRuntimeSHA {
		t.Fatalf("legacy saved runtime hash changed: %s, %v", got, err)
	}
	raw, err := json.Marshal(config)
	if err != nil || string(raw) != legacyRuntimeJSON {
		t.Fatalf("legacy runtime JSON shape changed: %s, %v", raw, err)
	}
}

package v1alpha1

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestActionsPrinterColumnShowsCapabilityMessage(t *testing.T) {
	configPath := filepath.Join("..", "..", "config", "crd", "bases", "phorvex.ai_phorvexpolicies.yaml")
	chartPath := filepath.Join("..", "..", "charts", "phorvex", "crds", "phorvex.ai_phorvexpolicies.yaml")
	configCRD, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	chartCRD, err := os.ReadFile(chartPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(configCRD, chartCRD) {
		t.Fatal("config and chart CRD copies differ")
	}
	want := []byte(`jsonPath: .status.conditions[?(@.type=="ActionsSupported")].message`)
	if !bytes.Contains(configCRD, want) {
		t.Fatalf("Actions printer column does not expose the condition message containing action names and reasons")
	}
	old := []byte(`jsonPath: .status.conditions[?(@.type=="ActionsSupported")].status`)
	if bytes.Contains(configCRD, old) {
		t.Fatal("Actions printer column still exposes only True/False")
	}
}

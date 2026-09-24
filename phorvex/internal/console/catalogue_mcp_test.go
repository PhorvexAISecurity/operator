package console

import (
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/cataloguev1"
)

func configuredMCP() CatalogueV1Config {
	return CatalogueV1Config{Enabled: true, MCPEnabled: true, MCPNamespace: "mcp", MCPDeployment: "mcp-server", MCPService: "mcp-server", MCPContainer: "mcp-server", MCPPort: 8000,
		MCPSourceConfigMap: "mcp-code", MCPSourceKey: "server.py", MCPImageID: "docker.io/library/python@sha256:90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff",
		MCPSourceSHA256: "483009cd01640e9f604a21f16aa890539566f53a25fd7dc478bc43c1831212c5"}
}

func TestMCPBaselineVisibleDisabledAndScopedWhenConfigured(t *testing.T) {
	cfg := Config{}
	var row CatalogItem
	found := false
	for _, item := range cfg.limitedV1Catalogue() {
		if item.EntryID == string(cataloguev1.MCPSessionBaseline) {
			row = item
			found = true
		}
	}
	if !found || row.Available || row.LaunchKind != "fixed-suite" || row.ClaimClass != "functional" || row.BenignControl == nil || !*row.BenignControl ||
		len(row.ExpectedActuators) != 0 || row.ResponseGuidanceBasis != "none" || len(row.Techniques) != 0 {
		t.Fatalf("disabled benign MCP row inaccurate: %+v", row)
	}
	cfg.CatalogueV1 = configuredMCP()
	available, reason := cfg.functionalProfileAvailable(cataloguev1.MCPSessionBaseline)
	if !available || !strings.Contains(reason, "launch checks") {
		t.Fatalf("configured MCP row unavailable: %t %s", available, reason)
	}
	rm := NewRunManager(cfg)
	destination, err := rm.FunctionalDestination(cataloguev1.MCPSessionBaseline)
	if err != nil || destination.ScopeTenant != "mcp" || destination.ScopeTarget != "default" || len(destination.Tenants) != 1 || destination.Tenants[0] != "mcp" {
		t.Fatalf("MCP grant destination differs: %+v %v", destination, err)
	}
	runtime := cfg.catalogueV1RuntimeConfig()
	if runtime.MCP == nil || runtime.MCP.ExpectedSourceSHA256 != cfg.CatalogueV1.MCPSourceSHA256 || runtime.MCP.ExpectedImageID != cfg.CatalogueV1.MCPImageID {
		t.Fatalf("MCP authority not persisted: %+v", runtime.MCP)
	}
	cfg.CatalogueV1.MCPNamespace = "foreign"
	if ready, _ := cfg.functionalProfileAvailable(cataloguev1.MCPSessionBaseline); ready {
		t.Fatal("unreviewed tenant shown runnable")
	}
}

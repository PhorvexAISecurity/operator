package config

import (
	"strings"
	"testing"
)

func validNativeRouteConfig(action, scenario string) TargetConfig {
	return TargetConfig{
		Context: "owned", Namespace: "fixture", ExpectedNamespaceUID: "00000000-0000-4000-8000-000000000001", OwnedAck: true,
		TrialsPerArm: 1, ScenarioFilter: []string{scenario}, DefenderFilter: []string{"d-nomtd"},
		NativeRouteFixture: &NativeRouteFixtureConfig{
			Action: action, NamespaceUID: "00000000-0000-4000-8000-000000000001", SourceRevision: strings.Repeat("a", 40),
			JournalNamespaceUID: "00000000-0000-4000-8000-000000000002", PolicyUID: "00000000-0000-4000-8000-000000000003", PolicyGeneration: 1,
			TargetUID: "00000000-0000-4000-8000-000000000004", PeerUID: "00000000-0000-4000-8000-000000000005", ServiceUID: "00000000-0000-4000-8000-000000000006", OperationID: strings.Repeat("d", 64),
			AdapterBinary: "/private/native-route-catalogue", AdapterBinarySHA256: strings.Repeat("b", 64),
			AdapterConfig: "/private/route.json", AdapterConfigSHA256: strings.Repeat("c", 64), ReceiptPath: "/private/receipt.json",
		},
	}
}

func TestNativeRouteFixtureFixedActionScenarioContract(t *testing.T) {
	for action, scenario := range map[string]string{"route-rotate": "c2-native-route-cutover", "endpoint-rotate": "c2-native-endpoint-cutover"} {
		cfg := validNativeRouteConfig(action, scenario)
		if err := cfg.Validate(); err != nil {
			t.Fatalf("valid %s handoff rejected: %v", action, err)
		}
		cfg.NativeRouteFixture.Action = "rotate"
		if err := cfg.Validate(); err == nil {
			t.Fatalf("arbitrary action accepted for %s profile", action)
		}
		cfg = validNativeRouteConfig(action, scenario)
		cfg.ScenarioFilter[0] = "c2-stealth-foothold"
		if err := cfg.Validate(); err == nil {
			t.Fatalf("mismatched scenario accepted for %s profile", action)
		}
	}
}

package consoleserver

import (
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/console"
)

func TestNamedProfileMountEnvironmentRequiresReviewedHashes(t *testing.T) {
	values := map[string]string{}
	lookup := func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	var cfg console.Config
	if err := applyCatalogueV1Environment(&cfg, lookup); err != nil || cfg.MongoExposureEnabled || cfg.GuardrailStaticEnabled || cfg.GuardrailEffectEnabled || cfg.NATSExposureEnabled || cfg.NATSClientResponseEnabled {
		t.Fatalf("default-off named profiles: %+v %v", cfg, err)
	}
	for _, tc := range []struct{ enabled, hash string }{
		{"PHORVEX_CONSOLE_MONGO_EXPOSURE_ENABLED", "PHORVEX_CONSOLE_MONGO_EXPOSURE_PROFILE_SHA256"},
		{"PHORVEX_CONSOLE_GUARDRAIL_STATIC_ENABLED", "PHORVEX_CONSOLE_GUARDRAIL_STATIC_PROFILE_SHA256"},
		{"PHORVEX_CONSOLE_GUARDRAIL_EFFECT_ENABLED", "PHORVEX_CONSOLE_GUARDRAIL_EFFECT_PROFILE_SHA256"},
		{"PHORVEX_CONSOLE_NATS_EXPOSURE_ENABLED", "PHORVEX_CONSOLE_NATS_EXPOSURE_PROFILE_SHA256"},
	} {
		values[tc.enabled] = "true"
		for _, bad := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("g", 64)} {
			values[tc.hash] = bad
			if err := applyCatalogueV1Environment(&cfg, lookup); err == nil {
				t.Fatalf("%s accepted unreviewed hash %q", tc.enabled, bad)
			}
		}
		values[tc.hash] = strings.Repeat("a", 64)
		if err := applyCatalogueV1Environment(&cfg, lookup); err != nil {
			t.Fatalf("%s rejected reviewed hash: %v", tc.enabled, err)
		}
		values[tc.enabled] = "false"
	}
	values["PHORVEX_CONSOLE_NATS_CLIENT_RESPONSE_ENABLED"] = "true"
	values["PHORVEX_CONSOLE_NATS_CLIENT_RESPONSE_PROFILE_SHA256"] = strings.Repeat("b", 64)
	if err := applyCatalogueV1Environment(&cfg, lookup); err == nil {
		t.Fatal("NATS response enabled without baseline")
	}
	values["PHORVEX_CONSOLE_NATS_EXPOSURE_ENABLED"] = "true"
	for _, bad := range []string{"", strings.Repeat("A", 64), "broken"} {
		values["PHORVEX_CONSOLE_NATS_CLIENT_RESPONSE_PROFILE_SHA256"] = bad
		if err := applyCatalogueV1Environment(&cfg, lookup); err == nil {
			t.Fatalf("NATS response accepted invalid hash %q", bad)
		}
	}
	values["PHORVEX_CONSOLE_NATS_CLIENT_RESPONSE_PROFILE_SHA256"] = strings.Repeat("b", 64)
	if err := applyCatalogueV1Environment(&cfg, lookup); err != nil || !cfg.NATSClientResponseEnabled {
		t.Fatalf("reviewed NATS response refused: %+v %v", cfg, err)
	}
}

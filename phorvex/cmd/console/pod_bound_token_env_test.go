package main

import (
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/console"
)

func TestPodBoundTokenEnvironmentRequiresReviewedProfileHash(t *testing.T) {
	values := map[string]string{}
	lookup := func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	var cfg console.Config
	if err := applyCatalogueV1Environment(&cfg, lookup); err != nil || cfg.PodBoundTokenEnabled {
		t.Fatalf("default-off Pod-bound token environment: enabled=%v err=%v", cfg.PodBoundTokenEnabled, err)
	}
	values["PHORVEX_CONSOLE_POD_BOUND_TOKEN_ENABLED"] = "true"
	for _, bad := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("g", 64), " " + strings.Repeat("a", 64)} {
		values["PHORVEX_CONSOLE_POD_BOUND_TOKEN_PROFILE_SHA256"] = bad
		if err := applyCatalogueV1Environment(&cfg, lookup); err == nil {
			t.Fatalf("accepted unreviewed profile hash %q", bad)
		}
	}
	good := strings.Repeat("a", 64)
	values["PHORVEX_CONSOLE_POD_BOUND_TOKEN_PROFILE_SHA256"] = good
	if err := applyCatalogueV1Environment(&cfg, lookup); err != nil || !cfg.PodBoundTokenEnabled || cfg.PodBoundTokenProfileSHA256 != good {
		t.Fatalf("reviewed profile hash lost: enabled=%v hash=%q err=%v", cfg.PodBoundTokenEnabled, cfg.PodBoundTokenProfileSHA256, err)
	}
}

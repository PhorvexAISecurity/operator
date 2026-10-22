package consoleserver

import (
	"github.com/phorvex/phorvex/internal/console"
	"testing"
)

func TestNewstackEnvironmentDefaultsOffAndRequiresStaging(t *testing.T) {
	values := map[string]string{}
	lookup := func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	var cfg console.Config
	if err := applyCatalogueV1Environment(&cfg, lookup); err != nil || cfg.NewstackLoopsEnabled {
		t.Fatalf("default newstack configuration: %+v %v", cfg, err)
	}
	values["PHORVEX_NEWSTACK_LOOPS_ENABLED"] = "true"
	for _, namespace := range []string{"", "voice", "phorvex-system", "phorvex-staging-extra"} {
		values["POD_NAMESPACE"] = namespace
		if err := applyCatalogueV1Environment(&cfg, lookup); err == nil {
			t.Fatalf("newstack enabled in %q", namespace)
		}
	}
	values["POD_NAMESPACE"] = "phorvex-staging"
	values["PHORVEX_EVENT_IDENTITY_POLICY"] = "reviewed-creator-guard"
	if err := applyCatalogueV1Environment(&cfg, lookup); err != nil || !cfg.NewstackLoopsEnabled || cfg.PodNamespace != "phorvex-staging" || cfg.NewstackIdentityPolicy != "reviewed-creator-guard" {
		t.Fatalf("fixed staging environment lost: %+v %v", cfg, err)
	}
	values["PHORVEX_NEWSTACK_LOOPS_ENABLED"] = "yes"
	if err := applyCatalogueV1Environment(&cfg, lookup); err == nil {
		t.Fatal("nonboolean opt-in accepted")
	}
}

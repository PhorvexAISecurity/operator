package consoleserver

import (
	"strings"
	"testing"

	"github.com/phorvex/phorvex/internal/console"
)

func TestVoiceAgencyEnvironmentDefaultOffAndPinnedProfile(t *testing.T) {
	values := map[string]string{}
	lookup := func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	var cfg console.Config
	if err := applyCatalogueV1Environment(&cfg, lookup); err != nil || cfg.VoiceAgencyLiveEnabled {
		t.Fatalf("Voice agency must default off: %+v %v", cfg, err)
	}
	values["PHORVEX_CONSOLE_VOICE_AGENCY_LIVE_ENABLED"] = "true"
	for _, bad := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		values["PHORVEX_CONSOLE_VOICE_AGENCY_LIVE_PROFILE_SHA256"] = bad
		if err := applyCatalogueV1Environment(&cfg, lookup); err == nil {
			t.Fatalf("Voice agency accepted unreviewed profile hash %q", bad)
		}
	}
	good := strings.Repeat("a", 64)
	values["PHORVEX_CONSOLE_VOICE_AGENCY_LIVE_PROFILE_SHA256"] = good
	if err := applyCatalogueV1Environment(&cfg, lookup); err != nil || !cfg.VoiceAgencyLiveEnabled ||
		cfg.VoiceAgencyLiveProfileSHA256 != good || cfg.VoiceAgencyLiveProfilePath != "/etc/phorvex-voice-agency/profile.json" {
		t.Fatalf("reviewed Voice agency profile lost: %+v %v", cfg, err)
	}
}

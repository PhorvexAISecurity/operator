package console

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// A sweeper beside another environment reaps only its own environment's events.
func TestTheSweeperReapsOnlyItsOwnNamespacesEvents(t *testing.T) {
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	young := time.Now().UTC().Format(time.RFC3339)
	listed := strings.Join([]string{
		"own|" + old + "|phorvex-staging/demo-api-1",
		"production|" + old + "|voice/voice-bot-1",
		"mixed|" + old + "|phorvex-staging/demo-api-1 voice/voice-bot-1",
		"untargeted|" + old + "|",
		"recent|" + young + "|phorvex-staging/demo-api-2",
	}, "\n")
	for name, c := range map[string]struct {
		scope []string
		want  []string
	}{
		"confined":   {[]string{"phorvex-staging"}, []string{"own"}},
		"unconfined": {nil, []string{"own", "production", "mixed", "untargeted"}},
	} {
		t.Run(name, func(t *testing.T) {
			var deleted []string
			s := &Server{cfg: Config{SweepNamespaces: c.scope, Exec: func(_ time.Duration, bin string, args ...string) (string, error) {
				if bin == "kubectl" && args[0] == "delete" {
					deleted = append(deleted, args[2])
					return "", nil
				}
				return listed, nil
			}}}
			s.sweepEventsBySelector("phorvex.ai/redteam=true", redTeamEventTTL)
			if !slices.Equal(deleted, c.want) {
				t.Fatalf("deleted %v, want %v", deleted, c.want)
			}
		})
	}
}

package console

import (
	"context"
	"errors"
	"time"
)

const (
	// ConfigMap volume projection and native journal recovery took about 75s
	// in DEV. Follow exact effect evidence beyond the former 90s cutoff.
	voicePolicyEffectWait = 180 * time.Second
	voicePolicyEffectPoll = 2 * time.Second
)

var errVoicePolicyEffectTimeout = errors.New("Voice protected effect confirmation timed out")

// The probe retains each action's exact terminal-journal and all-Pod predicates.
// A longer window gives recovery time; it never turns selection into effect.
func waitVoicePolicyEffect(ctx context.Context, window, poll time.Duration, probe func(context.Context) bool) error {
	bounded, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		if err := bounded.Err(); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errVoicePolicyEffectTimeout
		}
		confirmed := probe(bounded)
		if err := bounded.Err(); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return errVoicePolicyEffectTimeout
		}
		if confirmed {
			return nil
		}
		select {
		case <-bounded.Done():
		case <-ticker.C:
		}
	}
}

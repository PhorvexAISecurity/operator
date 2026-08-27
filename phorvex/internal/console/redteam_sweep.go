/*
 * Phorvex Console — red-team SecurityEvent TTL sweeper.
 *
 * Every attack the console fires (foothold, vLLM attacks, catalogue Fire-live) applies a
 * SecurityEvent labeled phorvex.ai/redteam=true. Nothing deleted them automatically, so a fired
 * attack that was never explicitly cleared pinned its app to "under attack" indefinitely —
 * dozens of them accumulated over hours and left the dashboard showing permanent, un-actuated
 * threat. This sweeper reaps any red-team event older than redTeamEventTTL: long enough for the
 * operator to react and the End-to-End suite to read the outcome, short enough that a leaked
 * event clears on its own instead of piling up.
 *
 * Best-effort and non-blocking, in the same shape as StartUptimeSampler. A restart just re-arms
 * it, and because the cut is by creation-timestamp it also cleans up whatever leaked while the
 * pod was down.
 */

package console

import (
	"context"
	"strings"
	"time"
)

const (
	redTeamEventTTL      = 5 * time.Minute
	redTeamSweepInterval = 60 * time.Second
)

// StartRedTeamSweeper launches the background reaper. Safe to call once at startup.
func (s *Server) StartRedTeamSweeper(ctx context.Context) {
	go func() {
		t := time.NewTicker(redTeamSweepInterval)
		defer t.Stop()
		// One immediate pass so a restart clears whatever leaked while the pod was down,
		// rather than waiting a full interval.
		s.sweepRedTeamEvents()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.sweepRedTeamEvents()
			}
		}
	}()
}

// sweepRedTeamEvents deletes every phorvex.ai/redteam=true SecurityEvent older than the TTL.
// SecurityEvents are cluster-scoped, so this is a single unnamespaced list + per-item delete.
func (s *Server) sweepRedTeamEvents() {
	out, err := s.cfg.execText(10*time.Second, "kubectl", "get", "securityevent",
		"-l", "phorvex.ai/redteam=true",
		"-o", `jsonpath={range .items[*]}{.metadata.name}|{.metadata.creationTimestamp}{"\n"}{end}`)
	if err != nil {
		return // best-effort: a transient API error just skips this pass
	}
	cutoff := time.Now().Add(-redTeamEventTTL)
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.SplitN(strings.TrimSpace(ln), "|", 2)
		if len(f) < 2 || f[0] == "" {
			continue
		}
		ts, perr := time.Parse(time.RFC3339, strings.TrimSpace(f[1]))
		if perr != nil || ts.After(cutoff) {
			continue // unparseable or still within its window — leave it
		}
		_, _ = s.cfg.execText(8*time.Second, "kubectl", "delete", "securityevent", f[0], "--ignore-not-found")
	}
}

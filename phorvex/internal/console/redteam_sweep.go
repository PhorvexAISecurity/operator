/*
 * Phorvex Console — SecurityEvent TTL sweeper.
 *
 * Two classes of SecurityEvent accumulate on the cluster and, un-expired, pin an app to a
 * stale state on the dashboard forever:
 *
 *  1. RED-TEAM inputs (phorvex.ai/redteam=true) — every attack the console fires (foothold,
 *     vLLM attacks, catalogue Fire-live). An un-cleared one leaves the app showing "under
 *     attack" indefinitely.
 *
 *  2. The operator's OWN action records (app.kubernetes.io/managed-by=phorvex, with a
 *     phorvex.ai/action label and source=PhorvexController) — one is emitted per rotate /
 *     quarantine / … the brain enacts. These are audit records, NOT threat inputs (nothing
 *     re-ingests them), but the dashboard reads them to show "actuator fired / app quarantined",
 *     so an old quarantine record pins voice/litellm to "quarantined" long after the pod is
 *     healthy again. They carry NO redteam label, so the pass for (1) never touched them — 130+
 *     accumulated over days.
 *
 * The sweeper reaps BOTH by creation-timestamp: red-team inputs after redTeamEventTTL (short —
 * long enough for the operator to react and the E2E suite to read the outcome), operator action
 * records after phorvexActionEventTTL (a bit longer so recent decisions still render).
 *
 * Best-effort and non-blocking, in the same shape as StartUptimeSampler. A restart just re-arms
 * it, and because the cut is by creation-timestamp it also cleans up whatever leaked while the
 * pod was down.
 *
 * SecurityEvents are cluster-scoped, so an environment beside another on one cluster
 * (Config.SweepNamespaces) reaps only the events every target of which is its own; the other
 * environment's events stay its own sweeper's.
 */

package console

import (
	"context"
	"slices"
	"strings"
	"time"
)

const (
	redTeamEventTTL       = 5 * time.Minute
	phorvexActionEventTTL = 15 * time.Minute
	redTeamSweepInterval  = 60 * time.Second
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

// sweepRedTeamEvents reaps both event classes by their own TTL. SecurityEvents are
// cluster-scoped, so each pass is a single unnamespaced list + per-item delete.
func (s *Server) sweepRedTeamEvents() {
	s.sweepEventsBySelector("phorvex.ai/redteam=true", redTeamEventTTL)
	s.sweepEventsBySelector("app.kubernetes.io/managed-by=phorvex", phorvexActionEventTTL)
}

// sweepEventsBySelector deletes every SecurityEvent matching the label selector whose
// creationTimestamp is older than ttl. Best-effort: a transient API error skips the pass.
func (s *Server) sweepEventsBySelector(selector string, ttl time.Duration) {
	out, err := s.cfg.execText(10*time.Second, "kubectl", "get", "securityevent",
		"-l", selector,
		"-o", `jsonpath={range .items[*]}{.metadata.name}|{.metadata.creationTimestamp}|{.spec.targets[*]}{"\n"}{end}`)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-ttl)
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.SplitN(strings.TrimSpace(ln), "|", 3)
		if len(f) < 2 || f[0] == "" {
			continue
		}
		ts, perr := time.Parse(time.RFC3339, strings.TrimSpace(f[1]))
		if perr != nil || ts.After(cutoff) {
			continue // unparseable or still within its window — leave it
		}
		if len(f) < 3 || !s.cfg.sweeps(strings.Fields(f[2])) {
			continue // another environment's event
		}
		_, _ = s.cfg.execText(8*time.Second, "kubectl", "delete", "securityevent", f[0], "--ignore-not-found")
	}
}

// sweeps reports whether the sweeper may reap an event with these targets
// ("namespace/name"): any, unless Config.SweepNamespaces confines it, and then only one
// every target of which is in those namespaces.
func (c Config) sweeps(targets []string) bool {
	if len(c.SweepNamespaces) == 0 {
		return true
	}
	if len(targets) == 0 {
		return false
	}
	for _, target := range targets {
		namespace, _, ok := strings.Cut(target, "/")
		if !ok || !slices.Contains(c.SweepNamespaces, namespace) {
			return false
		}
	}
	return true
}

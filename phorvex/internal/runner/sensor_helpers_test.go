package runner

import (
	"context"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/sensorapi"
	"github.com/phorvex/phorvex/internal/sensorsvc"
)

// observationOf is the in-process sensor's observation of a collected snapshot,
// with the context of every Pod derived.
func observationOf(snap *ingest.Snapshot) *sensorapi.Observation {
	seen := map[string]bool{}
	var scopes []sensorapi.Scope
	for _, p := range snap.Pods {
		if !seen[p.Namespace] {
			seen[p.Namespace] = true
			scopes = append(scopes, sensorapi.Scope{Namespace: p.Namespace})
		}
	}
	obs, err := sensorsvc.FromSnapshot(snap, scopes)
	if err != nil {
		panic(err)
	}
	return obs
}

// processTenant runs one policy's tick on a snapshot fixture with the legacy
// kill-switch observation.
func (m *Manager) processTenant(ctx context.Context, snap *ingest.Snapshot, e *policyEntry, killEngaged bool) {
	observation := legacyKillSwitchObservation(killEngaged)
	m.processTenantObserved(ctx, observationOf(snap), e, &observation)
}

// processTenantWithPhysicsObserved runs one policy's tick on a snapshot fixture with
// the given physics witnesses.
func (m *Manager) processTenantWithPhysicsObserved(ctx context.Context, snap *ingest.Snapshot, e *policyEntry,
	killObservation *KillSwitchObservation, physicsByKey map[string]model.PhysicsWitness) {
	obs := observationOf(snap)
	obs.Physics = physicsByKey
	m.processTenantObserved(ctx, obs, e, killObservation)
}

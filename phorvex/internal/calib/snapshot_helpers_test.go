package calib

import (
	"fmt"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

// The tests drive calibration from sensor snapshot fixtures; production passes the
// fleet the sensor observed (ObserveFleet, NodesFromFleet, AssetsFromFleet).

func fleetOf(snap *ingest.Snapshot) Fleet {
	return Fleet{Now: snap.Now, Pods: snap.Pods, Nodes: snap.Nodes}
}

func (r *Runtime) ObserveSnapshot(snap *ingest.Snapshot, witness map[string]model.PhysicsWitness) (RefreshResult, bool, error) {
	if r == nil || snap == nil {
		return RefreshResult{}, false, fmt.Errorf("calibration snapshot is nil")
	}
	return r.ObserveFleet(fleetOf(snap), witness)
}

func NodesFromSnapshot(snap *ingest.Snapshot) []NodeObservation {
	if snap == nil {
		return nil
	}
	return NodesFromFleet(fleetOf(snap))
}

func AssetsFromSnapshot(snap *ingest.Snapshot, witness map[string]model.PhysicsWitness) []AssetObservation {
	if snap == nil {
		return nil
	}
	return AssetsFromFleet(fleetOf(snap), witness)
}

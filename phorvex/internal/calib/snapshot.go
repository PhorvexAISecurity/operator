/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package calib

import (
	"sort"

	"github.com/phorvex/phorvex/internal/ingest"
)

// snapshot.go is the ONLY file in this package that knows about cluster types. Everything else
// works on plain observations, so the calibration arithmetic can be tested and reviewed without
// a cluster, and so this package has exactly one seam to audit for coupling.

// NodesFromSnapshot projects a cluster snapshot into co-residency observations.
//
// Nodes come from snap.Nodes rather than from the pods, so a schedulable node carrying no pods
// is still counted at X=0. Deriving the node set from pods instead would silently drop empty
// nodes and bias the distribution upward — the fleet would look more tenant-dense than it is,
// which is the direction that hides the problem this ticket is about.
func NodesFromSnapshot(snap *ingest.Snapshot) []NodeObservation {
	if snap == nil {
		return nil
	}
	tenants := map[string]map[string]struct{}{}
	pods := map[string]int{}
	for i := range snap.Pods {
		p := &snap.Pods[i]
		if p.Node == "" {
			continue // unscheduled: belongs to no node's tenancy yet
		}
		if tenants[p.Node] == nil {
			tenants[p.Node] = map[string]struct{}{}
		}
		tenants[p.Node][p.Namespace] = struct{}{}
		pods[p.Node]++
	}

	out := make([]NodeObservation, 0, len(snap.Nodes))
	for i := range snap.Nodes {
		n := &snap.Nodes[i]
		out = append(out, NodeObservation{
			Name:        n.Name,
			Namespaces:  len(tenants[n.Name]),
			Pods:        pods[n.Name],
			Schedulable: n.Schedulable,
		})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}

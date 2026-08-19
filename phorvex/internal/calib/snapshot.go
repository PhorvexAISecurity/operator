/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD.
 */

package calib

import (
	"sort"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
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

// AssetsFromSnapshot projects the fleet into dispersion observations, using the physics witness a
// platform adapter derived plus the RAW node tenancy.
//
// witness is keyed "namespace/name", matching platform.Derive's output.
//
// Co-residency is deliberately NOT read from the witness. The witness carries the multiplier
// already computed at the SHIPPED cap, so a percentile taken from products containing it would be
// a percentile of an already-clipped distribution — exactly what the spec forbids. The raw
// namespace count is carried instead so the term can be recomputed at a candidate scale.
func AssetsFromSnapshot(snap *ingest.Snapshot, witness map[string]model.PhysicsWitness) []AssetObservation {
	if snap == nil {
		return nil
	}
	tenants := map[string]map[string]struct{}{}
	for i := range snap.Pods {
		p := &snap.Pods[i]
		if p.Node == "" {
			continue
		}
		if tenants[p.Node] == nil {
			tenants[p.Node] = map[string]struct{}{}
		}
		tenants[p.Node][p.Namespace] = struct{}{}
	}

	out := make([]AssetObservation, 0, len(snap.Pods))
	for i := range snap.Pods {
		p := &snap.Pods[i]
		key := p.Namespace + "/" + p.Name
		w, ok := witness[key]
		if !ok || !w.Scanned {
			// No witness means the scanner did not answer for this pod. Substituting neutral
			// values would add a synthetic 1.0 to the distribution the cap is fitted from, which
			// drags the percentile down by however many pods the scanner missed.
			continue
		}
		out = append(out, AssetObservation{
			Key:         key,
			ImageRarity: w.ImageRarity,
			EPSS:        w.EPSS,
			ModelRarity: w.ModelRarity,
			Namespaces:  len(tenants[p.Node]),
			// Mirrors the production gate in recon: a GPU pod takes the ModelRarity term even
			// with no model annotation.
			AIFactEligible: p.ModelID != "" || p.HasGPU,
		})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Key < out[b].Key })
	return out
}

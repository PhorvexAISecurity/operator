/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-PHYSICS / UCW)
 */

// Package platform is the DISCOVERED-PHYSICS scanner: a PlatformPhysics adapter
// introspects a live cluster snapshot and DERIVES a per-pod model.PhysicsWitness — the
// measured supply/demand + recon-surface dispersion that REPLACES hand-specced
// constants. It is per-platform because AWS/EKS, CoreWeave and GPU-marketplaces expose
// physics differently (K8s API, DCGM/NVML, cloud metadata). Adding a platform = ONE
// adapter file with an init() that registers; adding a parameter = ONE more derived
// field. The optimizer/proactive engine/actuation never import this package — the runner
// stamps view.Physics and the recon-EMR + feasibility layers read it through model.
//
// HONESTY: every value is honest-absent. The K8s half (image-rarity, co-residency,
// scheduler-slack, live PDB, MIG-geometry) is MEASURABLE on any real cluster TODAY. The
// AI/GPU half is populated from live DCGM values when an adapter answers. With no DCGM
// series GPUPresent=false, so consumers degrade to neutral values and the 1.62x baseline
// reproduces bit-for-bit on kind.
package platform

import (
	"math"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
	"github.com/phorvex/phorvex/internal/recon"
	"github.com/phorvex/phorvex/internal/registry"
)

// PlatformPhysics derives per-pod discovered physics from a cluster snapshot.
type PlatformPhysics interface {
	registry.Named
	// Detected reports whether this adapter recognizes the scanned platform (so the
	// runner can pick the most specific one; the generic-K8s adapter always matches).
	Detected(snap *ingest.Snapshot) bool
	// Derive returns a witness per pod key ("ns/name"). Missing keys => NeutralPhysics.
	Derive(snap *ingest.Snapshot) map[string]model.PhysicsWitness
}

// Registry holds the registered platform adapters.
var Registry = registry.New[PlatformPhysics]()

// CoResidencyCap is the documented denominator for the co-residency multiplier: a node
// with CoResidencyCap+1 distinct tenants saturates at the max +1.0 surcharge.
const CoResidencyCap = 4.0

// Derive runs the most specific Detected() adapter (generic-K8s is the fallback).
func Derive(snap *ingest.Snapshot) (string, map[string]model.PhysicsWitness) {
	var chosen PlatformPhysics
	for _, a := range Registry.All() {
		if a.Name() == "generic-k8s" {
			continue
		}
		if a.Detected(snap) {
			chosen = a
			break
		}
	}
	if chosen == nil {
		if g, ok := Registry.Get("generic-k8s"); ok {
			chosen = g
		}
	}
	if chosen == nil {
		return "", nil
	}
	return chosen.Name(), chosen.Derive(snap)
}

// genericK8s is the platform-INVARIANT adapter: every field it derives is readable from
// the core K8s API on kind/EKS/GKE/CoreWeave alike (only signal strength varies). It
// derives the full K8s half live and leaves the AI/GPU half honest-absent (GPUPresent
// =false) — a DCGM/NVML-equipped adapter (CoreWeave/EKS-GPU) overrides those.
type genericK8s struct{}

func (genericK8s) Name() string                     { return "generic-k8s" }
func (genericK8s) Detected(_ *ingest.Snapshot) bool { return true }

// contributesToFleetPhysics excludes completed/failed workload history from the CURRENT fleet
// statistics. An empty phase is accepted for synthetic callers and old unit fixtures; Kubernetes
// snapshots always carry an explicit phase.
func contributesToFleetPhysics(p *model.Pod) bool {
	return p != nil && (p.Phase == "" || p.Phase == string(corev1.PodRunning))
}

func (genericK8s) Derive(snap *ingest.Snapshot) map[string]model.PhysicsWitness {
	out := make(map[string]model.PhysicsWitness, len(snap.Pods))
	if snap == nil {
		return out
	}

	// --- fleet dispersion statistics (ONE O(pods) pass; NFR1-safe) ---
	imgFreq := map[string]int{}
	modelFreq := map[string]int{}
	nodeTenants := map[string]map[string]struct{}{}
	withImage := 0
	for i := range snap.Pods {
		p := &snap.Pods[i]
		if !contributesToFleetPhysics(p) {
			continue
		}
		if p.ImageID != "" {
			imgFreq[p.ImageID]++
			withImage++
		}
		if p.ModelID != "" {
			modelFreq[p.ModelID]++
		}
		if p.Node != "" {
			if nodeTenants[p.Node] == nil {
				nodeTenants[p.Node] = map[string]struct{}{}
			}
			nodeTenants[p.Node][p.Namespace] = struct{}{}
		}
	}

	// --- per-node scheduler slack (allocatable - sum requests)/allocatable ---
	nodeByName := map[string]*ingest.NodeInfo{}
	for i := range snap.Nodes {
		nodeByName[snap.Nodes[i].Name] = &snap.Nodes[i]
	}
	nodeReqCPU := map[string]int64{}
	nodeReqMem := map[string]int64{}
	for i := range snap.Pods {
		p := &snap.Pods[i]
		if !contributesToFleetPhysics(p) {
			continue
		}
		if p.Node != "" {
			nodeReqCPU[p.Node] += p.CPURequestMilli
			nodeReqMem[p.Node] += p.MemRequestBytes
		}
	}
	nodeSlack := map[string]float64{}
	for name, ni := range nodeByName {
		nodeSlack[name] = slackOf(ni, nodeReqCPU[name], nodeReqMem[name])
	}

	for i := range snap.Pods {
		p := &snap.Pods[i]
		w := model.NeutralPhysics()
		w.Scanned = true

		// image-rarity (heavy-tailed surprisal), K8s measurable now
		if p.ImageID != "" && withImage > 0 {
			w.ImageRarity = rarity(imgFreq[p.ImageID], withImage)
			w.ImageRarityPresent = true
		}
		// CVE/EPSS exploitability prior (offline cache; honest-absent = 1.0)
		lk := lookupEPSS(p.ImageID)
		// The multiplier is recon's (M-104, one layer); the witness carries it for the
		// calibration snapshot and the scan report, plus the raw pair and the reason.
		w.EPSS, w.EPSSPresent, w.EPSSReason = recon.EPSSMultiplier(lk.EPSS, lk.CVSS, lk.Present)
		w.EPSSScore, w.CVSS = lk.EPSS, lk.CVSS
		w.EPSSBasis, w.EPSSCachedDigest, w.EPSSScanTS = lk.Basis, lk.CachedDigest, lk.ScanTS
		// model-rarity (AI fact dispersion). rarity() is population-relative, so ModelRarity is 1.0 in
		// TWO cases, not one: when the fleet has no model servers at all, and — the more common one —
		// when every model-serving pod runs the SAME model, because that model then occupies 100% of
		// its own population. A sole model scoring 1.0 is correct and must not be "fixed" to 2.0; see
		// TestRarityIsPopulationRelative. It lifts as soon as the population diversifies: measured on
		// the live fleet 2026-08-19, two distinct models on two pods make each 1-of-2, scoring 2.0.
		if p.ModelID != "" {
			tot := 0
			for _, c := range modelFreq {
				tot += c
			}
			w.ModelRarity = rarity(modelFreq[p.ModelID], tot)
			w.ModelRarityPresent = true
		}
		// co-residency (distinct tenants sharing the node)
		if t := nodeTenants[p.Node]; t != nil {
			w.CoResidency = 1 + clamp01(float64(len(t)-1)/CoResidencyCap)
			w.CoResidencyPresent = true
		}
		// scheduler slack of the pod's node
		if s, ok := nodeSlack[p.Node]; ok {
			w.SchedulerSlack = s
		}
		// live PDB match
		if mn, da, ok := matchPDB(snap.PDBs, p); ok {
			w.PDBMinAvailable, w.PDBDisruptionsAllowed = mn, da
		}
		// MIG legal-partition geometry (zero DCGM dependency)
		w.MIGGeometryValid = migValid(p, nodeByName)

		// AI/GPU half: genericK8s cannot measure VRAM/SM/interconnect (no DCGM) ->
		// GPUPresent=false, values 0. A GPU adapter overrides these from live DCGM.
		out[p.Namespace+"/"+p.Name] = w
	}
	return out
}

// rarity = 1 + log2(N/count)/log2(N) in [1,2]: a digest seen everywhere (count=N) -> 1.0
// (neutral); a singleton -> ~2.0. Honest-neutral at N<2.
func rarity(count, n int) float64 {
	if count <= 0 || n < 2 {
		return 1.0
	}
	surprisal := math.Log2(float64(n) / float64(count))
	return 1 + clamp01(surprisal/math.Log2(float64(n)))
}

func slackOf(ni *ingest.NodeInfo, reqCPU, reqMem int64) float64 {
	cpu, mem := 1.0, 1.0
	if ni.AllocatableCPUMilli > 0 {
		cpu = float64(ni.AllocatableCPUMilli-reqCPU) / float64(ni.AllocatableCPUMilli)
	}
	if ni.AllocatableMemBytes > 0 {
		mem = float64(ni.AllocatableMemBytes-reqMem) / float64(ni.AllocatableMemBytes)
	}
	return clamp01(minf(cpu, mem))
}

// matchPDB finds the live PDB in the pod's namespace whose selector matches its labels.
func matchPDB(pdbs []ingest.PDBInfo, p *model.Pod) (minAvail, disruptionsAllowed int, ok bool) {
	for i := range pdbs {
		if pdbs[i].Namespace != p.Namespace || pdbs[i].Selector == nil {
			continue
		}
		if pdbs[i].Selector.Matches(labels.Set(p.Labels)) {
			return pdbs[i].MinAvailable, pdbs[i].DisruptionsAllowed, true
		}
	}
	return -1, -1, false
}

// migValid: a pod with a MIG device is valid iff some node advertises that MIG resource
// key (a legal partition geometry). No MIG device => trivially valid (true).
func migValid(p *model.Pod, nodes map[string]*ingest.NodeInfo) bool {
	if p.MIGDevice == "" {
		return true
	}
	for _, ni := range nodes {
		if _, ok := ni.MIGResources[p.MIGDevice]; ok {
			return true
		}
	}
	return false
}

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}
func minf(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// hasGPUNode reports whether any scanned node advertises a GPU (used by GPU adapters'
// Detected()).
func hasGPUNode(snap *ingest.Snapshot) bool {
	for i := range snap.Nodes {
		if snap.Nodes[i].AllocatableGPU > 0 || len(snap.Nodes[i].MIGResources) > 0 {
			return true
		}
	}
	return false
}

func init() { Registry.Register(genericK8s{}) }

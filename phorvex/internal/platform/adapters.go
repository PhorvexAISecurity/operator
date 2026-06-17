/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-PHYSICS / UCW)
 */

package platform

import (
	"strings"

	"github.com/phorvex/phorvex/internal/ingest"
	"github.com/phorvex/phorvex/internal/model"
)

// stampGPU fills the GPU half of the witness from the live DCGM feed (snap.GPUWitness, populated
// by ingest.PopulateGPUWitness). It is the Derive() override the GPU adapters share: the K8s half
// is inherited from genericK8s; the GPU floats are stamped ONLY for pods DCGM actually reported a
// GPU for — so with no DCGM feed the GPU half stays [SP-0-PENDING] (GPUPresent=false), never faked.
func stampGPU(base genericK8s, snap *ingest.Snapshot) map[string]model.PhysicsWitness {
	out := base.Derive(snap)
	for key, gw := range snap.GPUWitness {
		w := out[key]
		w.GPUPresent = true
		w.VRAMFraction = gw.VRAMFraction
		w.SMOccupancy = gw.SMOccupancy
		w.LinkBandwidth = gw.LinkBandwidth
		out[key] = w
	}
	return out
}

// This file is the EXTENSIBILITY PROOF: each per-platform adapter is ONE self-
// registering module. The platform-INVARIANT K8s half is inherited from genericK8s
// (embedding); a platform adapter overrides ONLY Name()/Detected() and — once a real
// DCGM/NVML/cloud-metadata feed is wired — Derive() to fill the GPU/AI half. Until that
// feed exists, the GPU values stay [SP-0-PENDING] (GPUPresent=false), so these adapters
// are HONEST today: they recognize the platform and derive the full K8s half, and never
// fabricate a GPU number.
//
// Three source tiers (from the decision): (A) K8s-API-invariant (slack/PDB/rarity/
// co-residency/MIG-geometry) — LIVE here; (B) DCGM/NVML-conditional (VRAM/SM/NVLink) —
// add one Sig query to ingest.DefaultPromQueries when dcgm-exporter is present; (C)
// runtime-conditional NIM (KV/session/cold-load/tokens) — nim_* exporter scrape.

// eksGPU is the AWS/EKS adapter. SOURCE for the GPU half (SP-0 until wired): node label
// node.kubernetes.io/instance-type -> a static instance-type table for NVLink/PCIe/NIC
// ceilings; DCGM_FI_DEV_* via dcgm-exporter for VRAM/SM; IMDS for placement. It detects
// the platform by the presence of GPU-advertising nodes (the invariant signal we carry
// today); a richer detector keys on the instance-type label once node labels are
// projected.
type eksGPU struct{ genericK8s }

func (eksGPU) Name() string { return "eks-gpu" }

// Derive: K8s half (inherited) + the live DCGM GPU half stamped from snap.GPUWitness.
func (e eksGPU) Derive(snap *ingest.Snapshot) map[string]model.PhysicsWitness {
	return stampGPU(e.genericK8s, snap)
}

// Detected: a GPU-advertising node carrying an EKS-specific node label (eks.amazonaws.com/*,
// e.g. eks.amazonaws.com/nodegroup or .../compute-type). LABEL-DRIVEN, not registration order,
// so it never mis-fires on kind/CoreWeave. On kind there are no eks.amazonaws.com labels => false.
func (eksGPU) Detected(s *ingest.Snapshot) bool {
	return hasGPUNode(s) && nodeLabelKeyPrefix(s, "eks.amazonaws.com/")
}

// coreWeave is the CoreWeave GPU-cluster adapter. SOURCE for the GPU half (SP-0 until
// wired): nvidia.com/gpu.product + gpu-feature-discovery node labels for topology, DCGM
// (dcgm-exporter native) for VRAM/SM/NVLink, and the NIM exporter (nim_tokens_total,
// already in the PromQL seam) for KV/cold-load. Detected by GPU-advertising nodes.
type coreWeave struct{ genericK8s }

func (coreWeave) Name() string { return "coreweave" }

func (c coreWeave) Derive(snap *ingest.Snapshot) map[string]model.PhysicsWitness {
	return stampGPU(c.genericK8s, snap)
}

// Detected: a GPU node carrying a CoreWeave-specific label. [PENDING-P4] — the exact label
// keys are confirmed on real CoreWeave hardware at P4; false on kind/EKS today.
func (coreWeave) Detected(s *ingest.Snapshot) bool {
	return hasGPUNode(s) && nodeLabelKeyPrefix(s, "node.coreweave.cloud/")
}

// nodeLabelKeyPrefix reports whether any scanned node carries a label whose KEY starts with
// prefix (the cloud-platform marker). Reads NodeInfo.Labels (collected within `list nodes`).
func nodeLabelKeyPrefix(s *ingest.Snapshot, prefix string) bool {
	for i := range s.Nodes {
		for k := range s.Nodes[i].Labels {
			if strings.HasPrefix(k, prefix) {
				return true
			}
		}
	}
	return false
}

// gpuMarketplace is the generic GPU-marketplace adapter (e.g. rented bare-metal/MIG).
// SOURCE for the GPU half (SP-0 until wired): the marketplace's own capacity API /
// annotations + DCGM where exposed. Detected by GPU-advertising nodes. Lowest priority
// (only used if neither eks nor coreweave matched first).
type gpuMarketplace struct{ genericK8s }

func (gpuMarketplace) Name() string                     { return "gpu-marketplace" }
func (gpuMarketplace) Detected(s *ingest.Snapshot) bool { return hasGPUNode(s) }
func (g gpuMarketplace) Derive(snap *ingest.Snapshot) map[string]model.PhysicsWitness {
	return stampGPU(g.genericK8s, snap)
}

func init() {
	Registry.Register(eksGPU{})
	Registry.Register(coreWeave{})
	Registry.Register(gpuMarketplace{})
}

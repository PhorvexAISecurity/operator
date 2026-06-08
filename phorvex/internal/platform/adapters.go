/*
 * Phorvex — the deterministic intelligence layer for R6/Phoenix AMTD. (P-PHYSICS / UCW)
 */

package platform

import (
	"github.com/phorvex/phorvex/internal/ingest"
)

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

func (eksGPU) Name() string                      { return "eks-gpu" }
func (eksGPU) Detected(s *ingest.Snapshot) bool  { return hasGPUNode(s) }

// coreWeave is the CoreWeave GPU-cluster adapter. SOURCE for the GPU half (SP-0 until
// wired): nvidia.com/gpu.product + gpu-feature-discovery node labels for topology, DCGM
// (dcgm-exporter native) for VRAM/SM/NVLink, and the NIM exporter (nim_tokens_total,
// already in the PromQL seam) for KV/cold-load. Detected by GPU-advertising nodes.
type coreWeave struct{ genericK8s }

func (coreWeave) Name() string                     { return "coreweave" }
func (coreWeave) Detected(s *ingest.Snapshot) bool { return hasGPUNode(s) }

// gpuMarketplace is the generic GPU-marketplace adapter (e.g. rented bare-metal/MIG).
// SOURCE for the GPU half (SP-0 until wired): the marketplace's own capacity API /
// annotations + DCGM where exposed. Detected by GPU-advertising nodes. Lowest priority
// (only used if neither eks nor coreweave matched first).
type gpuMarketplace struct{ genericK8s }

func (gpuMarketplace) Name() string                     { return "gpu-marketplace" }
func (gpuMarketplace) Detected(s *ingest.Snapshot) bool { return hasGPUNode(s) }

func init() {
	Registry.Register(eksGPU{})
	Registry.Register(coreWeave{})
	Registry.Register(gpuMarketplace{})
}

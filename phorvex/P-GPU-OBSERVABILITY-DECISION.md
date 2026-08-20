# P-GPU-OBSERVABILITY — what the GPU physics half can and cannot measure on our hardware

**Scope.** PHVX-3 / PHORVEXSEC-85, step 1: for every GPU-dependent term in
`model.PhysicsWitness`, state the DCGM metric it needs, whether that metric exists on the
production fleet, and what the code does when it does not.

**Fleet this describes.** The production EKS GPU node pool is **NVIDIA Tesla T4** (Turing,
`sm_75`), PCIe Gen3 x16, time-sliced, scraped by `dcgm-exporter` through Prometheus at a 5 s
interval. Everything below was observed against that exporter, not inferred from vendor
documentation.

**One-line summary.** Everything the witness needs is measurable on T4 **except true SM
occupancy**. `DCGM_FI_PROF_SM_ACTIVE` is not exposed by the live exporter, so `SMOccupancy=0` and
`SMSource=""` remain honest-absent. `DCGM_FI_DEV_GPU_UTIL` is retained as general GPU telemetry but
is not substituted for occupancy.

**This gap is treated as temporary.** The team intends to enable the profiling counter on the
fleet. The formula remains calibrated for true occupancy, and the collector accepts only
`PROF_SM_ACTIVE`, so the day the series appears the witness corrects itself without another code
change. See "Decision" at the end. This document assumes the honest-absence code change in PR #52
lands before or with this documentation PR.

---

## Term-by-term

| Witness field | DCGM metric it needs | On our T4 | What the code does |
|---|---|---|---|
| `GPUPresent` | any DCGM series answering for the node's pods | **yes** | `true` when a scan answered; `false` on kind |
| `VRAMFraction` | `DCGM_FI_DEV_FB_USED`, `DCGM_FI_DEV_FB_FREE` | **yes** | `used / (used + free)`, `prometheus.go:350-351` |
| `SMOccupancy` | `DCGM_FI_PROF_SM_ACTIVE` (true occupancy) | **NO** | remains `0` (honest-absent); `GPU_UTIL` is not an occupancy fallback |
| `SMSource` | — | — | `DCGM_FI_PROF_SM_ACTIVE` when measured; empty when absent |
| `LinkBandwidth` | `DCGM_FI_PROF_PCIE_RX_BYTES` + `DCGM_FI_PROF_PCIE_TX_BYTES` | **yes** | rate-summed and normalized by the PCIe ceiling, `prometheus.go:360-362` |
| `LinkSource` | — | — | records the exact interconnect metric pair used |
| `ModelRarity` | none — derived from served `ModelID` across the fleet | n/a | hardware-independent |
| `CoResidency` | none — derived from Kubernetes tenancy on the node | n/a | hardware-independent |
| `KVRebuildSec`, `ColdLoadSec` | none wired | n/a | still `[SP-0-PENDING]`, `0` |

### Metrics that are absent, and what they would have given us

| Absent metric | What it would measure | Consequence |
|---|---|---|
| `DCGM_FI_PROF_SM_ACTIVE` | fraction of SMs with at least one active warp — true occupancy | `SMOccupancy` remains honest-absent |
| `DCGM_FI_PROF_SM_OCCUPANCY` | resident warps / maximum resident warps | no finer occupancy signal available |
| `DCGM_FI_PROF_GR_ENGINE_ACTIVE` | graphics/compute engine active fraction | no independent engine-busy cross-check |
| `DCGM_FI_PROF_DRAM_ACTIVE` | device-memory bandwidth utilization | memory-bandwidth pressure is unobservable |

### Why they are absent: the exporter's counter list, not the hardware

This was checked on the live cluster rather than assumed, and the answer is **configuration**.

`dcgm-exporter` runs as a DaemonSet in `gpu-telemetry` with no `--collectors` argument and no
mounted counter file, so it uses the counter list baked into its image,
`/etc/dcgm-exporter/default-counters.csv`. That file is 65 lines and contains exactly **two**
profiling fields:

```
DCGM_FI_PROF_PCIE_TX_BYTES,  counter, Total number of bytes transmitted through PCIe TX via NVML.
DCGM_FI_PROF_PCIE_RX_BYTES,  counter, Total number of bytes received through PCIe RX via NVML.
```

`DCGM_FI_PROF_SM_ACTIVE` does not appear in it at all. In the other two counter files shipped in
the same image it is present but **commented out**:

```
# DCGM_FI_PROF_SM_ACTIVE,          gauge, The ratio of cycles an SM has at least 1 warp assigned.
# DCGM_FI_PROF_SM_OCCUPANCY,       gauge, The ratio of number of warps resident on an SM.
```

So the metric is missing because **nothing asks for it**. And because the two PCIe fields are
themselves `PROF_*` and do return data, DCP profiling demonstrably functions on this T4 — the
hardware is not the constraint we assumed it was.

**What is still unproven:** that `SM_ACTIVE` will produce data once uncommented. NVIDIA ships
those lines commented for a reason, and profiling fields can still be refused per device, driver
or DCGM version. The claim here is narrower and evidence-backed: *the observed absence is fully
explained by the counter list, and the hardware hypothesis is not supported.* Enabling it is the
experiment that settles it.

**Do not read the absent-metrics table as "these arrive on Ampere" either.** Availability depends
on architecture, driver, DCGM version and the exporter's counter list. If the fleet gains
non-Turing nodes, re-measure rather than assume.

---

## The one place this leaks into behaviour

`internal/killchain/hazard.go:239` computes the model-theft leakage gate as:

```go
leakage := ph.SMOccupancy + ph.VRAMFraction
if p.HasGPU && ph.CoResidency > 1 && ph.ModelRarity > 1.3 && leakage > 0.8 {
    return StageModelTheft, true
}
```

It reads `SMOccupancy` without consulting `SMSource`, so passing `GPU_UTIL` through this field would
silently treat duty cycle as occupancy. PR #52 removes that substitution. While the true counter is
absent, the leakage term therefore contains only the measured VRAM fraction. This is conservative:
the model-theft gate can miss an SM-dependent signal, but it cannot manufacture one from a metric
with different semantics.

## Decision

**Leave the formula and the `0.8` threshold calibrated for true occupancy. Do not re-derive the
threshold against `GPU_UTIL`, and do not substitute `GPU_UTIL` into the SM term.**

The threshold was set for true occupancy. Re-deriving it for a duty-cycle proxy would leave a
number that is correct for neither signal. PR #52 therefore makes the unavailable term
honest-absent while preserving the formula for the genuine counter. **The day DCP profiling is
enabled, `SMOccupancy` becomes a true occupancy number with no code change or re-calibration.**

What is consciously accepted until then is a visible loss of one signal, not a mislabeled proxy.
`GPU_UTIL` remains available through `Telemetry.GPUUtil` for uses that actually require device duty
cycle.

**Follow-up that closes this properly:** enable `DCGM_FI_PROF_SM_ACTIVE` in the exporter's counter
list — it is absent from the default file and commented out in the others, as shown above — then
re-run the verification below and flip the `SMOccupancy` row of the table. That is a cluster-side
change; the exporter configuration is not owned by this repository. Only if the counter turns out
to be unproducible once enabled does the question become a calibration one, and only then does the
threshold need revisiting.

---

## Evidence

From the PHORVEXSEC-55 read-only AWS validation (merged as PR #5, production revision `589fa1b`):

- `VRAMFraction = 0.66`, from `9996 / (9996 + 5098)` MiB of live `FB_USED` / `FB_FREE`.
- Before PR #52, `SMSource = DCGM_FI_DEV_GPU_UTIL` exposed the historical fallback. After PR #52,
  the same absent `PROF_SM_ACTIVE` series yields `SMOccupancy=0` and `SMSource=""`.
- `LinkSource = DCGM_FI_PROF_PCIE_RX_BYTES+DCGM_FI_PROF_PCIE_TX_BYTES`. The previous NVLink-based
  template returned nothing: a T4 is PCIe-attached, so those counters do not exist here.
- The PCIe normalization ceiling is `2 x 15.754 GB/s = 31.508 GB/s`, PCIe Gen3 x16 in both
  directions, since the query sums RX and TX — `prometheus.go:294-296`.
- `gpuEnvelopeMax = 0.2925`, measured rather than assumed: the worst observed vLLM replacement
  recovery on this fleet was 117 s time-to-Ready against a 400 s documented warm-load scale.
  Configured in `phorvex/charts/phorvex/values.yaml` and
  `deploy/helm/phorvex-stack/values-eks.yaml`; the binary's unconfigured default stays at the
  conservative `1.0`.

## Verification

Point `PROM` at the in-cluster Prometheus and query the exporter directly. An empty `result`
array is the honest-absent case:

```bash
# expect data
curl -sG "$PROM/api/v1/query" --data-urlencode 'query=DCGM_FI_DEV_FB_USED'
curl -sG "$PROM/api/v1/query" --data-urlencode 'query=DCGM_FI_PROF_PCIE_RX_BYTES'

# expect an empty result on the T4 pool
curl -sG "$PROM/api/v1/query" --data-urlencode 'query=DCGM_FI_PROF_SM_ACTIVE'
curl -sG "$PROM/api/v1/query" --data-urlencode 'query=DCGM_FI_PROF_DRAM_ACTIVE'
```

The single time-sliced T4 series can move between `vllm` and `mock-rag-chatbot`, so query the
currently DCGM-labelled pod rather than assuming a fixed pod label.

To check the counter list itself rather than its output:

```bash
kubectl -n gpu-telemetry exec ds/dcgm-exporter -- \
  grep -i 'sm_active\|prof' /etc/dcgm-exporter/default-counters.csv
```

**Caveat on any historical check.** The `gpu-telemetry` Prometheus runs with
`--storage.tsdb.retention.time=2h` and has no PVC, so nothing survives a pod restart. Every
statement above is about the present state; there is no long window to appeal to.

---

**Related.** `internal/ingest/prometheus.go` (`DCGMWitnessQueries`, `PopulateGPUWitness`),
`internal/model/types.go` (`PhysicsWitness`), `internal/killchain/hazard.go` (the leakage gate),
`P-PHYSICS-DECISION.md`.

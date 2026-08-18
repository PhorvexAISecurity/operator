# P-GPU-OBSERVABILITY — what the GPU physics half can and cannot measure on our hardware

**Scope.** PHVX-3 / PHORVEXSEC-85, step 1: for every GPU-dependent term in
`model.PhysicsWitness`, state the DCGM metric it needs, whether that metric exists on the
production fleet, and what the code does when it does not.

**Fleet this describes.** The production EKS GPU node pool is **NVIDIA Tesla T4** (Turing,
`sm_75`), PCIe Gen3 x16, time-sliced, scraped by `dcgm-exporter` through Prometheus at a 5 s
interval. Everything below was observed against that exporter, not inferred from vendor
documentation.

**One-line summary.** Everything the witness needs is measurable on T4 **except true SM
occupancy**. `DCGM_FI_PROF_SM_ACTIVE` is not exposed by the live exporter, so `SMOccupancy` is
carried by the `DCGM_FI_DEV_GPU_UTIL` duty-cycle fallback and is **not** an occupancy number.

**This gap is treated as temporary.** The team intends to enable DCP profiling on the fleet, now
or later. Everything below is written for that: the formula is left alone, and the code path
already prefers `PROF_SM_ACTIVE`, so the day the series appears the witness corrects itself with
no code change. See "Decision" at the end.

---

## Term-by-term

| Witness field | DCGM metric it needs | On our T4 | What the code does |
|---|---|---|---|
| `GPUPresent` | any DCGM series answering for the node's pods | **yes** | `true` when a scan answered; `false` on kind |
| `VRAMFraction` | `DCGM_FI_DEV_FB_USED`, `DCGM_FI_DEV_FB_FREE` | **yes** | `used / (used + free)`, `prometheus.go:350-351` |
| `SMOccupancy` | `DCGM_FI_PROF_SM_ACTIVE` (true occupancy) | **NO** | falls back to `DCGM_FI_DEV_GPU_UTIL / 100`, a duty cycle, `prometheus.go:356-358` |
| `SMSource` | — | — | records which of the two above actually fed `SMOccupancy` |
| `LinkBandwidth` | `DCGM_FI_PROF_PCIE_RX_BYTES` + `DCGM_FI_PROF_PCIE_TX_BYTES` | **yes** | rate-summed and normalized by the PCIe ceiling, `prometheus.go:360-362` |
| `LinkSource` | — | — | records the exact interconnect metric pair used |
| `ModelRarity` | none — derived from served `ModelID` across the fleet | n/a | hardware-independent |
| `CoResidency` | none — derived from Kubernetes tenancy on the node | n/a | hardware-independent |
| `KVRebuildSec`, `ColdLoadSec` | none wired | n/a | still `[SP-0-PENDING]`, `0` |

### Metrics that are absent, and what they would have given us

| Absent metric | What it would measure | Consequence |
|---|---|---|
| `DCGM_FI_PROF_SM_ACTIVE` | fraction of SMs with at least one active warp — true occupancy | `SMOccupancy` is a duty cycle instead |
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

It reads `SMOccupancy` **without consulting `SMSource`**. On T4 that means a duty-cycle number is
summed into the gate as if it were occupancy — exactly the conflation `prometheus.go:75-77` flags
as load-bearing. While the fallback is in use, the gate can read high for a workload that is busy
for much of the wall clock but occupies very little of the device.

The magnitude, so the risk is on record: the observed production `VRAMFraction` is **0.66**, and
the gate fires above `0.8`. So the duty-cycle term only has to contribute `0.14` to trip it. A
small, persistent kernel — the shape a side-channel probe actually has — can supply that under
`GPU_UTIL` while occupying almost none of the SMs.

## Decision

**Leave the formula and the `0.8` threshold alone. Do not drop the SM term. Do not re-derive the
threshold.**

The threshold was set for true occupancy. Re-deriving it for the fallback would mean deriving it
twice — once now, once again when profiling is enabled — and would leave a number in the tree that
is correct for neither state. Deleting the SM term has the same problem in reverse: it would have
to be put back.

What makes this safe to defer is that the wiring is already correct. `prometheus.go:353-358` tries
`PROF_SM_ACTIVE` first and only falls back when the series is missing, and it records which one it
used in `SMSource`. **The day DCP profiling is enabled, `SMOccupancy` becomes a true occupancy
number and the gate becomes correct — with no code change and no re-calibration.**

What is consciously accepted until then: on the T4 pool the model-theft gate consumes a
duty-cycle number as occupancy, and `SMSource` records that it did. The audit therefore shows
which decisions were taken on the degraded signal, so they can be re-examined afterwards.

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
- `SMSource = DCGM_FI_DEV_GPU_UTIL` — the labelled fallback, because the live exporter exposes no
  `PROF_SM_ACTIVE` series.
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

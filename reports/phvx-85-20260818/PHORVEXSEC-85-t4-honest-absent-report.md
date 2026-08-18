# PHORVEXSEC-85 — Tesla T4 SM occupancy honest-absence

Date: 2026-08-18  
Base: `origin/main` at `7d2be46` (`v0.4.30`)  
Branch: `fix/phvx-85-t4-honest-absent`

## Scope

This completes the Tesla T4 honest-absence portion of PHORVEXSEC-85. It does not claim to provide real SM occupancy on hardware/exporters that do not expose `DCGM_FI_PROF_SM_ACTIVE`.

## Problem

The live T4 exporter does not expose `DCGM_FI_PROF_SM_ACTIVE`. The operator previously substituted `DCGM_FI_DEV_GPU_UTIL` into `PhysicsWitness.SMOccupancy`. These metrics do not mean the same thing:

- `PROF_SM_ACTIVE` is profiled SM occupancy.
- `GPU_UTIL` is coarse device duty-cycle.

The substituted value reached the model-theft leakage term (`SMOccupancy + VRAMFraction`) and could overstate the signal while appearing source-labelled.

## Fix

- Only `DCGM_FI_PROF_SM_ACTIVE` may populate `SMOccupancy`.
- If that series is absent, `SMOccupancy=0` and `SMSource=""` remain honest-absent.
- `DCGM_FI_DEV_GPU_UTIL` remains live in `Telemetry.GPUUtil`; it was not removed from general GPU telemetry.
- The redundant GPU-util query was removed from the PhysicsWitness collector.
- Documentation was corrected so it no longer recommends the duty-cycle fallback.

## Regression coverage

- The live T4-shaped test now proves missing `PROF_SM_ACTIVE` leaves SM occupancy absent.
- The test also proves the PhysicsWitness collector does not query `GPU_UTIL` as an occupancy fallback.
- A positive test proves a real `PROF_SM_ACTIVE` sample is preserved with the correct source.
- The existing telemetry test proves `GPU_UTIL` still reaches `Telemetry.GPUUtil`.

## Verification

| Check | Result |
|---|---|
| `go test ./internal/ingest ./internal/platform ./internal/killchain` | Pass |
| `go test ./...` | Pass |
| `go vet ./internal/ingest ./internal/platform ./internal/killchain` | Pass |
| `git diff --check` | Pass |

## Live AWS evidence (read-only)

Cluster observations on 2026-08-18:

- GPU model: Tesla T4.
- `count(DCGM_FI_PROF_SM_ACTIVE)` returned no series.
- `count(DCGM_FI_DEV_GPU_UTIL)` returned one series.
- The current T4 `GPU_UTIL` series remained available under the `vllm` pod.

No Kubernetes resource was changed during this validation.

## Remaining PHORVEXSEC-85 work

Real SM occupancy still requires an Ampere-or-newer/DCP-capable environment (or another exporter configuration that genuinely exposes `PROF_SM_ACTIVE`). Until that infrastructure is available, T4 reports the signal as absent instead of fabricating a proxy.

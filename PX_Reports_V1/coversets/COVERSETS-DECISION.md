# Cover-set decisions

This repository did not previously carry the coversets decision referenced by
PHORVEXSEC-117/121. It is now versioned with the implementation so the hardware
conditions and superseded model cannot drift out of band.

## 3.2 GPU contention is not GPU co-residency

PHORVEXSEC-121 supersedes the former `sideChannel` merge:

- `gpuCoresidency` is the attacker's durable knowledge of which workloads share
  the physical device.
- `gpuContentionChannel` is the memory-bandwidth, cache, and SM contention path
  through which a co-tenant can be observed.

The contention fact does **not** claim power or thermal isolation. MIG's treatment
of those paths is a vendor claim and remains contested; no cover credit is issued
for them.

`mig-rebind` may invalidate `gpuContentionChannel` only on a pod with live MIG
capability and only after a successful repartition. It never invalidates
`gpuCoresidency`, because repartitioning does not move the workload.

## 4.1 Capability-conditional Tier-1 status

`gpuCoresidency` is Tier-1 only where at least one deterministic eraser is
available. On T4-class, single-GPU-node, or otherwise incapable fleets its eraser
set is empty and the fact is audit-only (`CANNOT-HELP`).

`warm-swap` currently receives neither GPU fact. Clearing `NodeName` delegates
placement to the scheduler and permits a successful same-node result; a possible
relocation cannot back deterministic binary cover. Restoring the grants requires
all of the following:

1. required pod anti-affinity against the old leader on
   `kubernetes.io/hostname`;
2. at least one alternative GPU node schedulable for the complete shadow pod;
3. three consecutive complete positive inventory observations before activation;
4. immediate withdrawal on the first negative or incomplete observation; and
5. zero credit for failed or non-relocating outcomes.

Until those conditions are implemented, `warm-swap` remains valuable only as a
cold-load-free cutover and makes no co-residency claim.

Cross-references: PHORVEXSEC-117 (PHVX-25a) and PHORVEXSEC-121 (PHVX-26a).

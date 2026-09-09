# B4/B5 — warm or shard cutover

Use an approved same-model, attested-clean warm pool and the real role/service
contract. Establish independent readiness, output/integrity and request probes.
For B4 distributed claims, require the actual tensor/pipeline-parallel topology;
otherwise explicitly limit scope to a single shard. For B5 isolation claims,
verify destination placement and isolation, not just a new pod name.

Trigger the declared stimulus; observe selection, promotion, traffic cutover,
old-worker drain/retirement, pool replenishment and competing controllers. Verify
output/model identity and ongoing attacker access independently. Count interrupted
streams as impact even if some service remains available.

PASS means the pre-registered cutover and service budget hold. A smaller CPU
stand-in is a degraded-failover experiment, not same-model/GPU security coverage.
Abort on double leaders or uncontrolled recreation. Restore roles/owners in the
planned order and watch long enough to detect renewed churn.
Historical references: T46/T48; those used a 0.5B CPU stand-in and found F18.

# K1/K2 — cache-state eviction

Use a controlled serving target with observable prefix-cache metrics and a real
reset endpoint. Plant a unique harmless prefix, repeat it and establish HIT as
positive control. Pre-register the latency/metric threshold and ambient load.

K1 may use a declared synthetic signal to isolate the reset integration. Keep
policy configuration recorded. K2 additionally keeps supported competitors
available and records why each passes/fails feasibility; a pruned rotate is not
an optimizer preference. Observe the chosen action and an independently measured
HIT→MISS after reset, while recording request failures/latency and pod UID.

PASS means cache state was evicted under the declared conditions. It does not
mean prompt injection was cured: content can recreate the same KV. A cache-hit
canary measures cache residency, not malicious intent. Retire the nonce probe
and its owned signal after measurement to avoid self-sustaining churn.

Abort at the agreed service-impact budget. Cleanup verifies owned signals are
gone and no repeat reset remains. Historical references: K1/K2, T12/T18–T20,
runtime validation §1.2.

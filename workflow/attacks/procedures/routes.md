# S2/B3 — route invalidation

Require the actual route-service/selector contract and enough Ready capacity.
Capture the attacker's exact reference (pod address, route key, Service DNS or
existing connection), and demonstrate successful replay before intervention.

Trigger the declared action, then replay the SAME captured reference independently.
Also test legitimate discovery through the intended stable service. Record selector
writes, endpoints and UID, but score the invalidated reference from actual replay.
A changed label with the same reachable endpoint is not security invalidation.

PASS requires the pre-registered stale-reference behavior and legitimate traffic
budget, plus conflict/recovery evidence if that branch was in scope. Bound the
claim to the reference tested. Restore exact selectors/labels using observed
resource versions, verify endpoints, and abort if the legitimate path disappears.
Historical references: S2/B3, T11/T17; revalidate against today's route handler.

# B2 — request drain

Use bounded synthetic requests, an approved concurrency/token/time ceiling, and
engine-side queued/running work metrics. Establish successful baseline requests;
record the declared signal source. Never use an unbounded vendor-spend workload.

Start the bounded load, trigger drain, and observe candidate/dispatch records,
client outcomes AND engine completion/cancellation. Measure whether new requests
are admitted and whether retries restore load. Proxy HTTP 500s alone do not prove
GPU work or spend stopped. Separate malicious load from benign control traffic.

PASS of the integration claim requires the declared drain effect and service
budget. A denial-of-wallet defense claim additionally requires sustained admission
and work/spend bounds; record it only in a separately pre-registered defense case.
Abort at ceilings. Restore admission/labels and verify no queued work remains.
Historical reference: T47 (client aborts measured; stop-admit not enforced there).

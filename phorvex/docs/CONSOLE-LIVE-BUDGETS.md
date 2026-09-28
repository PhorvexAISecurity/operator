# Console live audit budgets

With a remote audit source, `/api/live` admits at most 16 subscriptions per
Console handler. The initial source probe, initial replay and every complete
poll/rotation/read/emit/verify operation share two expensive-read permits per
Server. Idle subscriptions hold no read permit. Each operation, including its
queue wait, has a 30-second budget; the admission probe retains its tighter
five-second budget. Paged and derived requests retain four separate slots and
their existing 30-second request budget.

A write or flush has a five-second deadline, shortened to the remaining read
budget where applicable. Successful writes clear that deadline before idle or
source waits. Failed, stalled or unsupported writes cancel the subscription;
request cancellation also releases queued or active read work. Wrapped HTTP
writers can expose their underlying writer through `Unwrap`.

This separates idle connection capacity from costly replay capacity without
sharing records between tenants. Per-grant owner projection, provider scope,
scan and record bounds, same-handle append anchors, retained-generation drain
and source verification remain in the live reader. A replay can still retain
records from its existing 32 MiB scan; at most two stream read operations do
that concurrently. The four derived-reader slots can still allocate their
existing 16 MiB audit windows. These bounds do not promise unlimited users or
eliminate genuine source overload.

The existing outer audit health/admission gate still precedes the route's
identity middleware. This repair bounds its stream probes with the same read
pool; it does not move the authentication boundary or change grants.

Regression tests use real local HTTP subscriptions, signed identities, an mTLS
audit source and actual committed audit files. Five simultaneous clients cover
owner projection, usable durable history, append/rotation continuity, repeated
disconnect/reconnect and real slow-reader backpressure. Separate controls cover
subscriber exhaustion, cancellation while queued, cached-reader cancellation,
expired work during cached emission, unsupported writers and successful writes
after idle periods longer than their injected write deadline.

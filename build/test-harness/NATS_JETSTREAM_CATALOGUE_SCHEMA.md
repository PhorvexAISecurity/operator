# NATS JetStream catalogue source contract

Suite entry: `c2-nats-jetstream-durability`. The entry is executable only with
an explicit `natsJetStreamFixture` authority, one trial, and `d-nomtd`. Each run
chooses one mode. `no-action` measures the genuine protocol without disruption;
`member-restart` restarts one child server inside an unchanged fixture Pod and
volume. `quorum-pause` keeps the member-0 client transport fixed, pauses the
exact member-1 and member-2 child processes for at most ten seconds under an
automatic-resume supervisor, retains one X publication attempt and a basic NATS
ping, then reconciles only X's same message ID after exact recovery. Direct-native and installed-dispatch are separate later entries and can
never be inferred from either mode.

Invoke the harness with both `-negative-control=false` and `-adaptive=false`.
Their CLI defaults are `true`, but either extra arm would reuse the same external
PV authority after its single owned trial. The command refuses this combination
before it builds Kubernetes clients; it does not silently disable an arm.

The authority binds one reviewed node and holder UID, the exact UID of a
no-provisioner Immediate/Retain StorageClass, three unique Available local PV
names/UIDs/slots/path hashes, and a nonce. Each PV must carry the exact holder,
node, nonce, slot and path-hash provenance. The scenario creates only three prebound PVCs, an owned three-member
NATS 2.10.29 StatefulSet, and owned Services. It refuses existing claims or
workload objects and never discovers, reads, publishes to, restarts, or adopts
the installed NATS workload.

The probe connects through an exact port-forward to member 0 with reconnects
disabled. `member-restart` targets only member 2. `quorum-pause` targets members
1 and 2 after binding each server ID, Pod/PVC/PV/store identity, child PID, Linux
process start time, and supervisor generation. Both process authorities are bound before either pause, the two pause requests
and confirmations are bounded concurrently, and both explicit resume requests
are sent before post-resume identity reads. The independently armed in-Pod
watcher resumes each same child within ten seconds even if the harness disappears;
an automatic-only resume invalidates a positive quorum result while still making
cleanup safe. Member-restart remains a non-client restart control, and the quorum
profile retains the connected member throughout. Client-member and leader
failover remain unmeasured.
After each explicit consumer ACK, the same-consumer negative observation window
is 500 ms while the configured consumer `AckWait` is 2 seconds. The receipt only
claims that no same-consumer delivery was observed during that completed 500 ms
window (including a final queued-message drain); it does not claim a full-AckWait
or indefinite absence of redelivery.
Every successful restart result records the suite version, mode, source and
image identities, stream/subject/consumer/nonce, exact Pod/PVC/PV/server member
identities, A and B PubAcks, delivery ACKs, independent stored-message reads,
replica state, one action attempt/completion, old/new child process identity,
unchanged storage identity and recovery duration. Availability during the
restart is explicitly unobserved; the result proves protocol restoration after
the boundary. A quorum-loss publication timeout is retained as unknown commit status. Both
the initial X publication and its same-ID reconciliation explicitly disable the
nats.go no-responder retry loop, so each receipt attempt is one wire publication.
After recovery the probe permits one same-ID publication only when its full request
timeout still fits before the configured two-minute deduplication window expires,
measured from the first attempt's earliest start. It validates the real PubAck
and stored bytes and requires exactly A/X/Y contiguous stream state. It never
retries X with a new ID. The basic
ping only proves that the existing member-0 NATS transport remained reachable;
it is not JetStream availability or failover evidence. Security and CVE outcomes
are `not-measured` for all three modes. NATS 2.10.29 is newer than the vendor-fixed 2.10.27 release for
CVE-2025-30215; CVE-2026-33248 configuration applicability remains unknown.
This durability entry receives no CVE-defense credit. Kubernetes Ready alone
earns no durability or availability credit.

The opt-in `benchmarkEvidence` metric field carries bounded non-sensitive
identity and receipt data (at most 64 fields and 32 KiB total). A failed oracle
retains its completed stages and partial receipt while the trial remains
invalid and unscored. Legacy free-form `AttackResult.Notes` is not copied into
this field. Teardown UID-preconditions every owned deletion, proves the exact
Pods and PVCs are absent, and requires each external Retain PV to reach Released
with its original claim UID before cleanup is complete.

The approved direct-native command will live in the Phorvex module and expose a
fixed quarantine-only request schema: exact namespace, fixture nonce, Pod UID,
policy owner UID, storage identities, and one action. It will call the genuine
internal native handler, persist a one-send result, and bind rollback to the
returned reference and exact post-effect identities. The harness must invoke an
explicitly configured executable whose source and binary digest are pinned. It
will not export actuator internals, download a binary, use a shared target, or
claim installed-brain dispatch. Installed dispatch requires its own trusted
event, audit decision, hybrid route, operation, effect, rollback, and protocol
receipts.

On the current development node the CNI runs with network policy disabled.
Creating a NetworkPolicy is not packet isolation, so a direct quarantine arm
must report backend-unavailable or incomplete when continued positive traffic
is observed. It must not mutate shared CNI configuration or convert that
continued traffic into a successful isolation claim.

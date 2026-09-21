# NATS JetStream catalogue source contract

Suite entry: `c2-nats-jetstream-durability`. The entry is executable only with
an explicit `natsJetStreamFixture` authority, one trial, and `d-nomtd`. Each run
chooses one mode. `no-action` measures the genuine protocol without disruption;
`member-restart` restarts one child server inside an unchanged fixture Pod and
volume. Direct-native and installed-dispatch are separate later entries and can
never be inferred from either mode.

The authority binds one reviewed node and holder UID, the exact UID of a
no-provisioner Immediate/Retain StorageClass, three unique Available local PV
names/UIDs/slots/path hashes, and a nonce. Each PV must carry the exact holder,
node, nonce, slot and path-hash provenance. The scenario creates only three prebound PVCs, an owned three-member
NATS 2.10.29 StatefulSet, and owned Services. It refuses existing claims or
workload objects and never discovers, reads, publishes to, restarts, or adopts
the installed NATS workload.

The probe connects through an exact port-forward to member 0 with reconnects
disabled. `member-restart` targets only member 2. It therefore measures a
non-client member restart; client-member and leader failover remain unmeasured.
Every successful restart result records the suite version, mode, source and
image identities, stream/subject/consumer/nonce, exact Pod/PVC/PV/server member
identities, A and B PubAcks, delivery ACKs, independent stored-message reads,
replica state, one action attempt/completion, old/new child process identity,
unchanged storage identity and recovery duration. Availability during the
restart is explicitly unobserved; the result proves protocol restoration after
the boundary. Security and CVE outcomes are `not-measured` for no-action and
member-restart. NATS 2.10.29 is newer than the vendor-fixed 2.10.27 release for
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

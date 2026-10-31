# Split brain snapshot capture

The brain owns its Math Lab store. The manager relays read-only snapshot queries
over its existing authenticated brain connection and exposes them through the
existing audit listener and Console authorization path. No new listener, service
account, or write operation is introduced.

Enable the brain chart's `mathLab.capturePolicies` with explicit
`namespace/policy` entries and configure its bounded persistent store. Capture is
disabled when this allowlist is empty. The capture-enabled pod uses group 65532
for volume access. Manager `mathLab.captureCostEvidence: true` adds the existing
bounded observational evidence to remote requests; it does not make endpoint
interval history complete or change decisions.

Both manager and brain must contain the additive snapshot RPCs. A new manager can
start before an older or capture-disabled brain: reads fail closed until a
capture-enabled brain is available, then the same connection and relay recover
without a manager restart. The startup Hello capability is informational, not a
permanent enablement decision. An older manager still needs its own upgrade to
relay snapshots. Enabling capture never backfills ticks missed before rollout.

The relay validates policy filters and time bounds, defaults to 500 index entries
and permits at most 5000. An index is at most 32 MiB. Snapshot reads accept only a
lowercase SHA-256 digest, stream chunks of at most 1 MiB, and enforce the existing
64 MiB snapshot bound and manager brain-call deadline. Both ends verify the
content address. Old, disabled, missing, malformed, oversized, corrupt, or timed
out responses remain errors; they are never reported as successful empty history.

Split-brain recording binds `header.gitSHA` to the brain executable's embedded
source revision and `header.brainImage` to its chart's exact container image.
`header.captureIdentitySource` is `recorder-process`. The chart injects the same
full image string, including an immutable digest when configured, into
`PHORVEX_BRAIN_IMAGE`. The recorded decision policy retains the manager's original
fields, so capture identity does not alter decision inputs or replay semantics.
Study cohort admission additionally requires the exact installed immutable brain
image and source. Legacy snapshots without this marker retain their original
identity and are not relabeled as process-bound recordings.

The brain OCI build includes `/brain-replay`, compiled from the same source and
linked with the same build identity as `/service`. This companion reproduces
recorded decisions offline; its presence does not enable any live experimental
selection policy. A separately built candidate must retain its own actual source
identity and use explicit cross-version replay where authorized.

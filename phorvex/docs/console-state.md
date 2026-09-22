# Console state storage

The console writes its own mutation intents and outcomes, attack results, uptime samples, and
three-arm experiment records under `-state-dir`. This directory is independent of the manager's
decision audit. Remote audit transport is read-only and never supplies a writable state path.

The Helm chart creates a dedicated `console-state` PVC by default. Set
`phorvex.console.state.persistence.existingClaim` to use a separately provisioned claim, or set its
`storageClass`, `size`, and `accessModes` values for a chart-managed claim. The console Pod mounts
only that claim writable. Its audit client certificate, grant table, and root filesystem remain
read-only; the manager audit PVC is mounted only by the manager Pod.

The console Deployment is a singleton with the `Recreate` update strategy. An ordinary Helm or
Deployment upgrade stops the old console Pod before starting the new one, so only one console
process writes these ledgers during that upgrade. This causes a brief period when the console is
unavailable. `Recreate` governs Deployment upgrades only: it does not fence a force-deleted Pod
that is still running on a partitioned node, nor independently created or manually replaced Pods.
Operators must avoid manual overlap and resolve uncertain termination before starting another
console writer against the same claim.

The storage operator owns StorageClass and claim provisioning, capacity alerts, snapshots,
restore tests, and retention across upgrades. The chart-managed claim is retained on Helm delete
by default; after uninstall it must be reattached deliberately or deleted by the storage owner.
Set `retainOnDelete=false` only when the release lifecycle intentionally owns deletion, and still
observe the StorageClass reclaim policy. Back up the claim before replacing it. The
console bounds each JSONL ledger and retains the preceding segment as `<name>.1`; external backup
retention should cover both files.

The durable decision archive (`audit-history.db`) is append-only: source rotation does not remove
imported decisions. To keep that archive from consuming the entire state filesystem, imports pause
before either the database reaches `-history-max-bytes` or the filesystem would fall below
`-history-min-free-bytes`. The chart defaults are 2 GiB and 512 MiB. Each guarded transaction also
reserves 64 MiB for one 4 MiB source batch, bbolt copy-on-write pages, its 16 MiB allocation step,
indexes, offsets, and filesystem metadata. Existing archive rows remain readable while paused;
the history response is marked partial, and its durable source offset does not advance. Import
retries automatically after capacity is restored.

These guards do not prune, compact, resize, or delete the archive. Operators must monitor the PVC
and either expand it or, while the console is stopped, snapshot and deliberately archive/replace
the database according to their retention policy. Raise the archive ceiling only after sizing the
claim for the archive, the free-space reserve, the transaction reserve, and the other console
ledgers. An archive already above the configured ceiling stays readable and remains paused.

For local development, `DefaultConfig` keeps the historical `build/test-harness` location unless
`-state-dir` is supplied. In Helm, durable storage can be disabled only by also setting
`phorvex.console.state.allowEphemeral=true`. That mounts an `emptyDir`; every console-owned record
is lost when the Pod is replaced.

At startup the console creates a bounded probe, writes and syncs it, renames it, reads it back, and
syncs the directory. Startup fails if any operation fails. A policy edit or experiment is refused
before its external effect unless its intent is durable. If the external effect succeeds but its
outcome cannot be synced, the API reports an applied partial outcome and `unsafeToRetry`; callers
must inspect the cluster rather than repeat the request.

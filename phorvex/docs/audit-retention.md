# Audit retention and evidence export

Audit rotation is opt-in. The default target segment size is 512 MiB and the
default is four rotated segments, so the nominal budget across the live segment
and four archives is 2.5 GiB. The chart's persistent volume default remains
5 GiB. The remaining capacity is headroom for other files, filesystem metadata,
and whole-record overshoot; increasing a rotation threshold does not resize a
volume.

`maxBytes` is a segment target rather than a hard disk ceiling. The writer never
splits one JSONL record. A record that does not fit causes the existing live
segment to rotate, then the complete record is written; a record larger than the
target therefore creates an oversized segment. Pre-existing files also count,
and the contract assumes exactly one writer for the path. With largest accepted
record size `R`, a planning estimate for newly written segments is at most
`(maxBytes + R) * (maxBackups + 1)`, plus pre-existing files and filesystem
overhead. Measure real record sizes before selecting a budget.

Retention is capacity-based, not a time guarantee. For a measured sustained
write rate of `B` bytes/second, estimate the nominal window as
`maxBytes * (maxBackups + 1) / B` seconds. Bursts, oversized records, existing
files, and rotation timing change the observed window. For example, 512 MiB and
four archives on a 5 GiB claim reserve 2.5 GiB nominally; operators must verify
that the other contents and overhead fit the remaining capacity. Compression is
not enabled and no minimum number of hours is promised.

## Export selected segments

Use a unique local directory outside the rotating live volume. The following is
a read-only example; choose the namespace, Pod, container, and segment names from
the deployment under review:

```sh
export_dir=$(mktemp -d ./audit-evidence.XXXXXX)
chmod 700 "$export_dir"
kubectl -n "$namespace" get pod "$pod" -o json > "$export_dir/pod.json"
kubectl -n "$namespace" get pod "$pod" -o jsonpath='{.spec.containers[?(@.name=="phorvex")].image}{"\n"}' > "$export_dir/image.txt"
date -u +%FT%TZ > "$export_dir/observed-at.txt"
for segment in live.jsonl live.jsonl.1 live.jsonl.2; do
  if ! kubectl -n "$namespace" cp "$pod:/audit/$segment" "$export_dir/$segment" -c phorvex; then
    printf '%s\n' "$segment missing or changed during export" >> "$export_dir/export-gaps.txt"
  fi
done
sha256sum "$export_dir"/live.jsonl* > "$export_dir/SHA256SUMS"
```

Record the deployed image digest, embedded source revision when available, UTC
observation time, exact selected names, and hashes with the review. Each copy is
independent: rotation can occur between copies, so this is not an atomic snapshot
and cannot prove gap-free history. Record missing or concurrently changing
segments explicitly. Do not retain secret-bearing payloads in tracked evidence;
apply the review's data-handling rules to the private export. Keep the exported
directory until review completes instead of relying on files that continue to
rotate in place.

## Parameter material permissions across restarts

The manager stores decision parameter manifests and policy overrides in the
process-owned sibling directory `<audit path>.parameters`. Its steady-state
contract is mode `0700` for that root and its two known kind directories, and
mode `0600` for retained documents and crash-left temporary files.

Kubernetes can widen existing volume contents to group mode while applying a
Pod `fsGroup`. On startup the manager accepts only the exact process-owned
`02770`/`0660` shape produced by that operation, `02700` on a newly created
directory that inherited setgid from the audit volume, or the already-private
modes. It validates the fixed hierarchy, names, object types, link counts, size
bounds, JSON, and content-addressed document digests through no-follow
descriptors, then restores `0700`/`0600` on those same descriptors. It does not
chmod the audit volume or any unrelated path. Unexpected content makes the
parameter store unavailable and decision rows report that retention failure; it
is never silently deleted or regenerated.

The chart sets `fsGroupChangePolicy: OnRootMismatch` on the manager Pod as a
preventive best effort. Its effect depends on the volume root mode and whether
the CSI driver delegates ownership changes, so startup descriptor validation and
recovery remain the correctness boundary. After an upgrade, verify the manager
starts without a parameter-store initialization error, all three directories
and all retained files have the steady-state modes and manager UID/GID, existing
material remains readable at its original digest, and a newly written decision
can retain and read a new parameter set. Treat any missing, altered, or
unavailable material as a failed verification rather than repairing the live
volume manually.

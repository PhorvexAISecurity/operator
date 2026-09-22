# Installed audit observer v1

`installed-audit-observer` reads the existing mTLS audit transport and produces
a bounded projection for an installed-manager benchmark. It is read-only. It
does not use Kubernetes, start a manager, mutate a policy, confirm application
effect, or turn a missing decision into a no-action result.

The caller first captures a cursor before the observation window:

```text
installed-audit-observer \
  --mode=cursor \
  --url=https://audit-reader.example:8443 \
  --server-name=audit-reader.example \
  --ca-file=/mounted/ca.crt \
  --client-cert-file=/mounted/tls.crt \
  --client-key-file=/mounted/tls.key \
  --output=/receipts/cursor.json
```

Credential file contents never enter the cursor or receipt. After the window
has ended, the caller runs `--mode=observe` with that cursor and the exact
policy, target, manager source, parameter epoch, and time window. Required
observe flags are:

- `--policy-namespace`, `--policy-name`, `--policy-uid`, and
  `--policy-generation`;
- `--target-namespace`, `--target-name`, and `--target-uid`;
- `--trace-schema`, `--brain-image`, and `--git-sha`;
- `--parameter-manifest-id` and `--parameter-manifest-hash`;
- `--not-before`, `--not-after`, and `--cursor-file`.

The optional `--policy-overrides-hash` may pin a hash already known after policy
creation. When omitted, the observer still requires the exact
`policyOverridesId` derived from the fresh policy UID and generation, fetches
the row's referenced material by its validated hash, verifies the complete
parameter set, and returns that verified hash. For an expected emitted native rotate, also pass the exact
`--target-resource-version`, `--expected-grace-seconds`, and one
`--allowed-object=Pod/<namespace>/<name>`. The command validates the full
`policyOverridesId` as `<namespace>/<name>@<UID>:<generation>` and retrieves
both immutable parameter documents through the authenticated transport. It
never writes those documents to the receipt.

The output is JSON Lines. Zero or more
`phorvex.installed-audit-receipt.v1` rows are followed by exactly one
`phorvex.installed-audit-summary.v1` row. The receipt contains only policy and
target identities, source hashes, parameter references, decision/dispatch
dispositions, exact allowlisted touched objects, a bounded graceful-termination
projection, raw row hash, and pinned source ranges. It excludes raw reasons,
rationale, model inputs, parameter bodies, credentials, and application data.
For the rotate disposition only, an exact producer reason of
`availability: ready=N-1 < minAvailable=M` is projected to the optional typed
`availabilityRefusal` object with integer `ready`, `removed`, and
`minAvailable` fields after checking `N-1 < M`. Other feasibility reasons and
malformed or contradictory numeric reasons do not populate that field; the raw
reason is never copied.

`status=complete, attribution=unavailable` means the exact range was read but
no matching decision was found and no exact-target row lacked attribution. It
is not evidence of no action. An exact-target row without a rich decision trace
invalidates the observation even when an earlier matching receipt was valid. An invalid or
canceled read exits nonzero after preserving any earlier receipt rows and an
invalid summary. A decision may span several `sourceRanges` when a retained
rotation occurs; consumers must retain the complete array or its canonical
digest. Each source range includes its own SHA-256 in addition to the complete
raw-row hash. A receipt proves only decision and dispatch observation. In particular,
`terminationStatus=unconfirmed` requires a separate application and Pod
lifecycle observer before effect or availability credit.

The defaults cap one read at 8 MiB and 512 records. Hard limits are 64 MiB,
4,096 records, 512 KiB per record, eight exact touched objects, a two-minute
window, and a 30-second client deadline. A lost generation, history gap,
partial row, duplicate JSON field, reused decision ID with different bytes,
wrong UID/source/epoch, unavailable parameter material, or exceeded bound
invalidates attribution.

The reviewed live audit recently grew at roughly 0.5 MiB/s, so the 8 MiB
default can cover only a short window. The consumer must freeze a short window
and an explicit byte/row bound suitable for that window. A bound failure is an
invalid observation and must never cause an automatic retry of a policy
mutation or targeted action.

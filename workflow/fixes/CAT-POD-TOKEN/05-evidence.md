# CAT-POD-TOKEN — implementation evidence handoff

## Version anchors and limits

- Reviewed baseline: `a50d796af128cd4109875e03eaf429d460126740`.
- The current implementation is an **uncommitted worktree snapshot**. Its exact relevant file hashes and aggregate digest are in [`evidence/implementation-source.json`](evidence/implementation-source.json). The aggregate digest is `f8475dfd92e864ca8b54bc6c27448a3a75f06732810cbbad6a073fbf3729544e`; it is not a Git commit or an `implementation.head_sha` pin. Recalculate it after any source edit.
- Lead's independent final run used Go 1.26.3 with bounded `GOMAXPROCS=2`, `GOFLAGS=-p=1` and disk temporary storage. Exact commands, test-file hash and log hashes are retained in [`evidence/LEAD-FINAL-TESTS.json`](evidence/LEAD-FINAL-TESTS.json), with the [baseline](evidence/baseline-final.log) and [head](evidence/head-final.log) raw outputs.
- Deployed image and installed implementation SHA are **not established by this handoff**. L3 and installed-defense outcome remain pending.

## Source change and behavioral boundary

The real `CollectSnapshot` producer derives a typed potential Pod-bound Kubernetes API authentication witness only from an admitted Running Pod, a started container with an unshadowed mounted default-audience projected token, and an exact current ServiceAccount identity created before the Pod. The optional ServiceAccount inventory uses the existing direct API boundary reader, with at most 250 ms and one quarter of the remaining parent deadline. Nil, denied, blocked, or partial inventory grants no witness and does not start a cached informer. Chart RBAC adds only `serviceaccounts` `list`.

Recon emits a separately named potential-capability fact with **planned rotate-only cover**. Generic copied-knowledge `FactCredential` remains coverless. This is neither a token-theft detector nor an observed API-authentication effect. Selection or Eviction acceptance does not imply same-bearer rejection, Pod retirement, or attack mitigation. The existing native rotate execution reports termination unconfirmed; no new effect receipt was added.

## RED, controls, and L0–L2 evidence

The lead ran the independent real-producer regression on baseline: its ordinary no-token control passed, while the explicit mounted default-audience token with `automountServiceAccountToken=false` failed the expected assertion because baseline produced zero narrow facts. The same test passed at the uncommitted head. This distinguishes the fix from a manually populated final model flag.

The final head command passed `./internal/ingest`, `./internal/model`, `./internal/recon`, `./internal/decision`, `./internal/actionset`, `./internal/actuator`, `./internal/runner`, and `./internal/console` with `-count=1`. Producer tests cover wrong or missing audience, legacy Secret, missing mount, SubPath/SubPathExpr, token-path and parent-path shadowing, unrelated sibling mount, Pending or unstarted container, recreated/deleting ServiceAccount, stale Pod UID/resourceVersion, duplicate identity, forbidden list, and blocked direct list under both normal and short parent deadlines. The blocked cases require core Pod, namespace, and event collection to finish under a live parent context. The qualified-versus-unqualified fixture adds exactly 10 to planned rotate cover under the test's neutral physics and leaves other actions without token cover.

The owned round-3 [direct mechanism control](../../campaigns/2026-09-23-catalogue-coverage/rounds/round-3/) observed the same captured Pod-bound bearer accepted before exact Pod UID eviction and rejected with HTTP 401 after observed UID absence, while a legitimate bearer remained accepted. It did not exercise this new installed source, demonstrate token theft, or verify defense selection. The independent lead's final source review passed; formal P3 and incident workflow signatures still require a pinned implementation commit and handoff.

## Remaining workflow actions

The implementation source and this record must be committed before a final preflight receipt or `submit-review` can pin the implementation head. The current `preflight CAT-POD-TOKEN` plan resolves the older committed worktree head and therefore cannot attest this uncommitted implementation. After the lead coordinates the exact fix commit, the implementer configures only branch/base/head, runs the selected local preflight with matching Go/Helm/Python tools, signs the expected baseline RED and source-bound L0–L2/positive-control evidence, then calls `submit-review` at the expected revision. The lead independently signs incident/P3 and continues PR delivery. L3 requires later deployed-source pin and installed owned-fixture verification; it is not a prerequisite for an honest PR-stage handoff.

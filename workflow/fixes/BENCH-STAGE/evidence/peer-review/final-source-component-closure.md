# Independent final source component closure

Reviewer: stage-review. Source: `ec310e276e45e6a218f7520880e22c6c1c687817`. Recorded: 2026-11-01T01:26:12.550277+00:00.

All reviewed runtime component findings R1–R9 are resolved. This is component acceptance, conditional on the complete coherent ec310 required preflight and final operational handover. It is not a claim that previous failed checks or attempts passed. No source was authored or changed by this reviewer.

## R1

Resolved: missing price bounds on otherwise eligible candidates can no longer be called a complete comparison. Known non-cost vetoes, worth rejection and a known exhausted budget remain legitimate NOOP results. Concrete before/after kernel counterexamples and positive controls are retained.

- `workflow/fixes/BENCH-STAGE/evidence/peer-review/r1-component-review.json` — SHA256 `51c087475985d87b46f9e760e3c6ec6583efeec717a3267ad3ab1fca3a9aab50`.
- `workflow/fixes/BENCH-STAGE/evidence/peer-review/dynamic-study-scope-review.json` — SHA256 `6317d2ff6e10c628038b2f528c75a22492f09291bcb782a578f8b3a601904757`.

## R2

Resolved: removing or nulling a frozen stage pin cannot fall back to legacy execution. Existing stage provenance forces strict stage validation.

- `workflow/fixes/BENCH-STAGE/evidence/peer-review/missing-stage-pin-control-after.json` — SHA256 `903a8d95955a11f6f16b3bdc1ac03ae7d6e9040f4bb1df89f56c78e217131344`.
- `workflow/fixes/BENCH-STAGE/evidence/peer-review/dynamic-study-scope-review.json` — SHA256 `6317d2ff6e10c628038b2f528c75a22492f09291bcb782a578f8b3a601904757`.

## R3

Resolved: capture provenance comes from the actual recorder process (embedded source, immutable image and recorder-process marker). Consumer scope checks reject foreign source/image/UID/namespace. All independently inspected live 600-second and code cohorts match those actual producer identities.

- `workflow/fixes/BENCH-STAGE/evidence/peer-review/dynamic-study-scope-review.json` — SHA256 `6317d2ff6e10c628038b2f528c75a22492f09291bcb782a578f8b3a601904757`.
- `workflow/fixes/BENCH-STAGE/evidence/peer-review/relay-oci-review.json` — SHA256 `265e952f828ff1453e7b775be63b7c19270195ebccb41403a1713c3ae6a1d3d0`.
- `workflow/fixes/BENCH-STAGE/evidence/peer-review/refresh-600/component-review.json` — SHA256 `69ae78c351b1b81fd17743924489139d29477aaa1bc361cc6afe4d220e0a1372`.
- `workflow/fixes/BENCH-STAGE/evidence/peer-review/code-retry/actual-cohort-binary-control.json` — SHA256 `7ee5f6729d6bea7393b7ae815a1d6a53dc827e9b25e39b750dc97b874908dd34`.

## R4

Resolved: the remote snapshot source is lazy and each request fails closed for old/disabled servers. Enabling capture after reconnect does not require manager restart. The non-author lead reviewed and tested the actual Recorder/store/RPC/HTTP path and old-to-enabled TCP lifecycle; this reviewer separately verified compiled OCI artifacts and live identity.

- `workflow/fixes/BENCH-STAGE/evidence/peer-review/../relay-component-review.json` — SHA256 `2ec509b8f13fb2bdb871bb1aa99a5b1772e3918969496dec18a05b7d770df416`.
- `workflow/fixes/BENCH-STAGE/evidence/peer-review/relay-compiled-artifacts-review.json` — SHA256 `e40fdd76932a947d65249b07676fb8a72d4ebaf17d408890c415720de8224046`.
- `workflow/fixes/BENCH-STAGE/evidence/peer-review/relay-oci-review.json` — SHA256 `265e952f828ff1453e7b775be63b7c19270195ebccb41403a1713c3ae6a1d3d0`.

## R5

Resolved: obsolete remote pages cannot permanently starve the new source cohort. Bounded inclusive pagination, scope-bound continuation and explicit untraversable equal-time refusal were independently exercised with real snapshot bytes.

- `workflow/fixes/BENCH-STAGE/evidence/peer-review/r5-pagination-review.json` — SHA256 `807ed0ed13db21bd3aefc287c69ce551f815a6717512021a7805665f605d9cb0`.
- `workflow/fixes/BENCH-STAGE/evidence/peer-review/sync-old-image-page-control-after.json` — SHA256 `86e1d80ea9a2b88c9e5473ba444ad27939384b80432ba69b229c096333fbd1ec`.

## R6

Resolved: stage writers serialize the complete download-to-registration interval. Shared consumer freeze locks and exclusive owned pruning prevent deleting inputs or exposing an ownership gap to another stage sync. The exact concurrency counterexample passes.

- `workflow/fixes/BENCH-STAGE/evidence/peer-review/r6-sync-review.json` — SHA256 `f069d36d7f5cfcdd2683c3d23a074f698e1583062319d39776e55bec7e4e4964`.
- `workflow/fixes/BENCH-STAGE/evidence/peer-review/refresh-component-review.json` — SHA256 `fc330c6ebecdb50a51736248bcd49d782e1419030e35b6944b6e0630077c092d`.

## R7

Resolved: English/Persian guides and generated PDFs explain independent W/L values, evidence coverage and unvalidated long windows. Actual PDF delivery and extracted text were checked.

- `workflow/fixes/BENCH-STAGE/evidence/peer-review/r7-r8-component-review.json` — SHA256 `4eac6f9cb8c76836f52d818fc3c5c05152a9e0ef092e1791bfc6ed1517236eb4`.
- `workflow/fixes/BENCH-STAGE/evidence/peer-review/r7-r8-pdf-text-review.json` — SHA256 `33c72ff76b05eb2fbb1a71175312a696c1524ef89dbc4b51979cc98146bc7d2e`.

## R8

Resolved: recipe-2 current-CI attestation schedules chart checks for benchmark-only changes. Historical recipe/source behavior stays unchanged; real temporary Git counterexamples and 16 adapter tests pass.

- `workflow/fixes/BENCH-STAGE/evidence/peer-review/r7-r8-component-review.json` — SHA256 `4eac6f9cb8c76836f52d818fc3c5c05152a9e0ef092e1791bfc6ed1517236eb4`.
- `workflow/fixes/BENCH-STAGE/evidence/peer-review/final-ci-benchmark-path-control-after.json` — SHA256 `d2bc4bad1263cb5c9d27093c34a8ead41a95f8adbefb4622fdbd9e83254f8f84`.

## R9

Resolved: refresh uses strict ASCII RFC3339Nano parsing to integer UTC nanoseconds, then the same float64(ns)/1e9 conversion as the real Go exporter. Strict equality remains enforced. The original failed-cohort export reproduces before repair and matches after repair; independent 18-test and real Go bitwise controls pass.

- `workflow/fixes/BENCH-STAGE/evidence/peer-review/r9-clock/component-review.json` — SHA256 `f069ec637b0a316f67182eab31bdd05d627b749d34377eef4b6b994072d24d56`.
- `workflow/fixes/BENCH-STAGE/evidence/peer-review/r9-clock/actual-failed-cohort-before-after.json` — SHA256 `698152a2a75ff9469ddd5cd4fecc799696b48690e1420594f10ce2c881c30af5`.

## Refresh and storage

Accepted components: frozen sealed journal prefix and as-of normalization; exact same-source control and local-base replay before cross-version candidate export; immutable generations with atomic manifest and last-good preservation; bounded owned cache pruning and reader locks. New explicitly compressed journals preserve decoded hash chains with bounded lossless decoding, transactional counters and quotas. Existing plain journals remain unchanged. Actual backup parity and 52 refresh / 59 storage component controls passed. Capacity and long-history scan estimates are not a 30-day guarantee.

- `workflow/fixes/BENCH-STAGE/evidence/peer-review/refresh-component-review.json` — SHA256 `fc330c6ebecdb50a51736248bcd49d782e1419030e35b6944b6e0630077c092d`.
- `workflow/fixes/BENCH-STAGE/evidence/peer-review/storage-component-review.json` — SHA256 `4d1f78b1d4047b13811a1da05697545732d01c0e7bb2dc2c66dea5c5c9ae6ff7`.
- `workflow/fixes/BENCH-STAGE/evidence/peer-review/storage-real-backup-independent.json` — SHA256 `e31a87e8b19585d57d47e8d0384866106f44d75660071321528afc22489a1640`.

## Final packaging

Accepted archive-only ec310 delta: 76 member names unchanged, 74 payloads identical; two payloads match already reviewed source capture flags/example. Pinned GNU tar 1.35 deterministic regeneration and full umbrella default/enabled renders pass. The previous stale-archive failures are preserved.

- `workflow/fixes/BENCH-STAGE/evidence/peer-review/packaging/component-review.json` — SHA256 `67a8fb3e9db59b3503c54d1e094d7b00dd8351907b8a0b0d3e704992ece7e4e8`.

## Remaining acceptance conditions

- Finish and independently bind all required ec310 preflight checks. Prior full Go/build success does not replace a coherent final-source receipt.
- Reconcile final task-owned mutation ledger, retained service/storage configuration, rollback instructions and transient/auth cleanup; verify post-retry refresh recovery independently.
- Preserve the distinction between the live ef94 capture deployment, d552 offline candidate engine, 4b016 generated pure helper candidate and ec310 bot/documentation source. No experimental picker is activated in the live stage brain.

The later successful measurements establish real short-window operation. They do not establish arbitrary unsupported parameter support, future error-free operation, 30-day continuous history, application availability, realized counterfactual security effects, or V3 ranking advantage.

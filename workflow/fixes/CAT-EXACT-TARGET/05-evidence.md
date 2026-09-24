# CAT-EXACT-TARGET — implementation evidence handoff

## Source and limits

The reviewed baseline is `a50d796af128cd4109875e03eaf429d460126740`. The exact-target implementation was committed as `eaab76cc016521092c21c321d322c427e8a7b137` and incorporated without source conflicts into integration head `eec96867ab16a1d516a4352aa34256050ebf7e1b`. [The source manifest](evidence/implementation-source.json) lists all 17 changed product, test and generated-document files with full SHA-256 hashes. `docs/recon-cover-map.generated.md` changed because its declared source inputs include the edited `internal/model/types.go`; `go run ./tools/covermap --check` passed with input digest `c46eaf74ddcc71f69b5e8a8206aa53bca077006e9c74ab3d916019b7ffff9d96`.

This handoff concerns source behavior. Neither the manager nor console exact-target implementation is established as deployed; no fresh console case, attack, actuation, or independent service outcome has been performed for this fix. L3 remains pending.

## Incident and RED

The isolated a50 baseline archive runs the current portable actual-handler fixture. A request names an owned `voice/owned-0` Pod and its UID while one business-like Voice Pod is also available. Baseline ignores those optional fields and serializes a SecurityEvent targeting `voice/voice-bot-0` without a target-UID annotation. The assertion fails after the event is created; the 502 response records that target identity changed. The expected baseline RED output is [implementer-baseline-red.log](evidence/implementer-baseline-red.log), SHA-256 `2f8be0e236020169b59c743c9cab2a660f8db3efcb1cad0adc2ae92a4f5fc73a`. `red=PASS` means this intended baseline failure was reproduced, not that baseline behavior was safe.

The fixture uses a real console handler and serializes its event manifest. Its Kubernetes client is a finite fake executor; it does not mutate a cluster. The baseline archive is `/home/mehrdad/.cache/phorvex-exact-baseline.IXvQ2S`, derived from `git archive a50d796af128cd4109875e03eaf429d460126740 phorvex` with only the portable regression test copied from this commit. The test overlay is precisely the committed `scenario_exact_target_test.go` truncated immediately before `func TestExactBoundUptimeRejectsReplacedDeploymentInSingleRead`, since that head-only test invokes the new `workloadUptimeBound` method. Its exact Go invocation is recorded with the RED check in `STATUS.yaml`. The separate incident and independent reviewer P3 records are the lead's responsibility.

## Head behavior and controls

The head requires paired canonical `targetPod` and `targetUid` fields, resolves the current Pod, binds its UID and exact Deployment owner, and rejects missing or changed target, owner or unique active policy before signal intent. It still permits a policy with a disabled catalogue action hint so that a diagnostic NOOP can be observed. Every newly emitted catalogue SecurityEvent, including legacy-selected cases, includes a dedicated target-UID annotation. The create reply must preserve that identity.

The manager's real `CollectSnapshot` producer checks the annotation against the UID in the same Pod list used for its decision snapshot. Stale, malformed or multitarget bound events remain in diagnostic inventory with an explicit rejection reason, but cannot enter `EventByPod`, neighbor evidence, existential outcome or current-inventory effects. Current bound, legacy unbound and untrusted controls are included. The steering trace retains the original event target UID; a same-name replacement is never relabeled. Exact-mode uptime reads UID and replicas from one Deployment GET and returns unknown when the owner changed. Signal execution stays synthetic and no response/mitigation success is inferred.

The [focused head log](evidence/implementer-head-focused.log), SHA-256 `2a110627ef3697f3c7d85a1d72fbfca751bac19caac4668934cda658594a3063`, passes the exact handler, snapshot, runner rejection and generated-document checks. An earlier full affected-package run also passed `./internal/console ./internal/ingest ./internal/decision ./internal/runner ./tools/covermap -count=1`. The lead's frozen eec CI-matched preflight now passes all 11 selected jobs; its [Go log](evidence/l0-go-phorvex.log), SHA-256 `5841a13419b313167856c8e8845a6b4739072ce99d166fab6d471ecd8d202ddd`, includes `go build ./...`, `go test ./...` and `go vet ./...`. The complete receipt and raw jobs are copied under `evidence/preflight/` with unchanged hashes for validation in this fix's own directory.

## Remaining handoff

The implementer handoff pins the integrated head and passing preflight receipt in `submit.yaml` with source-bound L0–L2 and positive-control artifacts. The lead independently signs incident/P3, then manages PR and installed L3. No local PASS here asserts an installed defense or security outcome.

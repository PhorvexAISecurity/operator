# Console terminal-observation diagnosis

Baseline: `bb92355cf7b6c4a696f44caf52bd5fa1268e7303`; proposed source at diagnosis: `0435b7f57017dbb5768adf92a80d2accc87e5a33`.

The current source idle control failed only the 1-second poison assertion after all seven module test binaries were prepared and independent Go checks ended. The unchanged baseline control reproduced the same assertion with exit 1. All five setup-failure cases, including the 2-second event-create-ack-lost case, passed. This establishes an existing test timing assumption, not a capture-code regression.

A separate baseline Go overlay adds only deferred post-Wait logging. Original polling deadlines, assertions and failures are retained; it also exited 1. `console-postwait-test-delta.patch` is the entire logging-only change; the baseline archive was not edited. The poison record was RUNNING when its unchanged 1-second assertion fired, then the already-registered watcher completed at 1.370 seconds after the response: status=done, outcome=LANDED, cleanup=completed, observation/cleanup/persistence errors empty. The event-create-ack-lost positive control reached the same terminal fields at 1.522 seconds. Other modes retained their intended typed nonbehavioral outcomes.

Both tests already register `t.Cleanup(s.attackWatchers.Wait)`, so those 1/2-second sampling loops do not bound test duration: cleanup waits for the watcher regardless. A proposed synchronization repair is to call that existing Wait before reading terminal fields, keeping every outcome, route, command, load and cleanup assertion plus the CI command's 15-minute deadline. It does not change runtime code or increase a test threshold. The lead signed this exact amendment at revision 15. Commit 00eac153f3f27929907f91d4231362051664364c implements only those two loop replacements; final acceptance is recorded separately.

Actual execution pins: Go 1.26.3 with GOTOOLCHAIN=local, Helm 3.16.4 and the declared non-cluster environment. Local Python is 3.12.15; the Go CI job itself does not pin Python (the chart jobs do). Available-interpreter startup samples do not establish Python choice as the cause, and no such claim is made. Neither the unchanged failed test nor the diagnostic failed test is counted as passing acceptance evidence.

See `console-idle-control-status.json` and `console-idle-control.txt`, `console-baseline-{status,config}.json` and `.txt`, and `console-postwait-{status,config}.json` and `.txt`. Build-only preparation (-run ^$) is separately retained and is not a test pass.

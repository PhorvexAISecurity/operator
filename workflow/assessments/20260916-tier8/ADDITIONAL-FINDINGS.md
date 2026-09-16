# Additional observation during Tier8 validation

## M168 diagnostic residual: partial observation is called persistence failure

At source `38f1f18c6211e059217320af9168427a111de8b3` (unchanged console product code in the Tier8 issue branches), `phorvex/internal/console/arms_runner.go`'s `observe` closure labels every `attackRecord.Status == "partial"` as `attack observation persistence partial`. `attack_results.go` can also produce that status when a target-UID read completes outside the registered observation window, with the real cause in `ObservationError`.

The first M124 full preflight hit this path in `TestM168ArmsWorkerRejectsDeploymentReplacementBetweenArms`: the experiment remained incomplete/restored before the intended fourth target read. Source analysis identifies the 20 ms watcher deadline as the likely timing cause; the captured outer error alone cannot distinguish an observation deadline from persistence failure. The Deployment guard was not bypassed. The fixture repair gives the observation a realistic scheduling window while retaining the exact between-arm read count and identity-error assertion.

The runtime diagnostic remains unresolved: distinguish observation-window/read uncertainty from persistence errors when explaining a partial result. Preserve fail-closed incompleteness, the retained inner observation cause and absence of comparative/mitigation claims. This is recorded against the existing M168 entry; it is not a new safety bypass or a claim that storage failed. Live M168 acceptance remains pending in the central backlog.

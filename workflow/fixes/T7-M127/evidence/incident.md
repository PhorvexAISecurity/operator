# M127 independent incident review

Reviewer: codex-lead. Baseline `669197bf025a446a87ed2923c04dbaa2237ca077`; implementation `f2d56318701b532f0a6c4e1b1363a7e58e5120d6`. Final rerun checkout `b697b1aff8f626a3607941df7cb3d552c00a57c4` differs only in workflow metadata.

The lead overlay runs the actual CoverageEngine-selected decision through the runner and an observable local HTTP actuator. Its route preparation updates the actual ConfigMap object after the initial sample. This exercises the time window rather than supplying a final kill-switch boolean. The existing real-API test additionally pauses a real informer watch to distinguish cached and direct reads.

| Control | Baseline | Implementation |
| --- | --- | --- |
| Sentinel off | One HTTP request, actuated | One HTTP request, actuated |
| Sentinel flips during route preparation | One HTTP request despite engagement; expected-fixed assertion fails | Zero HTTP requests and zero actuations |
| Real API update with paused informer | Baseline defect separately reproduced above | Direct-reader boundary blocks while stale-cache negative control dispatches |
| Engage then disengage | Existing control | Actual tenant actuation suppressed then resumes |

Baseline command and expected failure are retained in `lead/red.md` and `lead/baseline-red.log`. Final independent command and complete output: `lead/final-head.log`. Command: source the retained heavy/local API environments, then `M127_EXPECT_FIXED=1 $GO_BIN -C phorvex test -overlay /home/mehrdad/operator/.git/phorvex-workflow/tier7-20260916/m127-head-overlay.json ./internal/runner -run '^(TestM127LeadSentinelChangesAfterDecision|TestM127RealAPIDirectReaderClosesCachedDispatchWindow|TestKillSwitchEngageDisengageSuppressesAndResumesActuation)$' -count=1 -v`.

All final controls PASS with no skips. The independent overlay source is `lead/m127-lead-probe.go`; the local overlay changes only test source, not product code. Isolated API and local HTTP are not a deployed-cluster test. L3 is pending under the Tier7 live plan and central backlog LV-11.

Verdict: PASS for the scoped source repair; no live or production approval.

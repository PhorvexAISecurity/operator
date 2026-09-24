# Verification

Independent lead baseline: `bbce251b565429939cb945e3fd6f36e65147c0f9`; actual console constructor and fixed-suite launcher. The private overlay adds only the test retained in evidence/worker-functional_load_error_test.go.

Command from phorvex: Go1.26.1 `test -overlay /home/mehrdad/operator/.git/phorvex-workflow/catalogue-coverage-20260923/reconciliation/lead-load-error/overlay.json ./internal/console -run '^TestFunctionalLaunchRefusesUnknownRetainedRunState$' -count=1`. Exit1 at the intended assertion: nonempty runID, nil error, sequence1, one run and modified malformed ledger. Worker baseline independently matches.

No external mutation. The inert executable exits immediately. Healthy retained-state and actual persisted unsafe-state controls are required alongside the repaired test before acceptance; they are not claimed yet.

Positive controls executed by campaign-cleanup-audit on unchanged producer cbccea9b43d3d8417a5e5f97c2fdcf50d7bfce6e73f1dbc345cd471aea3560dc: actual safe persisted run -> constructor -> healthy admission PASS, and actual unsafe persisted Voice run -> constructor -> refusal PASS. Go1.26.1 `test ./internal/console -run "^(TestFixedSuiteStartAdmitsHealthyRetainedLedger|TestFixedSuiteRetainedUnsafeRunBlocksAfterRestart)$" -count=1`. Raw evidence/positive.log SHA256 7e3298c5ba7ced7cd286effd8d8fbcd621c8c785b8967adf03cfa268a3fa2390. Verification PASS for the defect, not the yet-unimplemented repair.

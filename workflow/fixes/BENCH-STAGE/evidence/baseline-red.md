# Independently executed baseline RED

Executed and reviewed by bench-v3-lead on 2026-10-31. Baseline source9b5a3eb0e9b1b5a033290cee1302aa6b5059cf40 is the real mergedPR181 image; no guard was disabled.

The original live producer had a different stage source and no capture configuration; the bot still selected legacy operator/vllm data and lacked an endpoint trace. After deploying exact mergedmain manager/brain/sensor and enabling bounded stage capture with a separately scoped read-only Console identity, authenticated snapshot index still returns502. Source confirms manager remote-brain branch leaves audittransport.MathLab nil and brain RPC has no snapshot relay. This is a real producer failure, not a mocked result.

Positive controls: all3 running binaries report exact9b5 source with exit0; image-extracted manager /brain-replay -version returns valid replay identity. Requesting /brain-replay --export-study-candidates from this same baseline fails with exit2 and the expected unsupported flag. These demonstrate both live data-path gap and absence of the requested engine export. Source capability alone does not satisfy completed benchmarking.

Commands executed through the existing authenticated stage jump host with explicit EKS context: kubectl -n phorvex-staging exec deploy/staging-brain -- /service --version; analogous sensor/manager versions; kubectl exec deploy/staging-phorvex -- /brain-replay -version; then --export-study-candidates. Snapshot index: GET /api/math-lab/snapshots?namespace=phorvex-staging-demo&policy=stage-bench-defense&limit=3 through owned localhost port-forward, short10m benchmark-SA token (not retained).

This RED establishes a necessary baseline failure. Final incident/P3 must additionally cover repaired relay, exact replay, stage pin deletion, missing pricing and real bot runs. No final acceptance is claimed here.

Immutable raw evidence:
- baseline-real-producer.json SHA256 21fceb9f0ac654060bb676d3ce7068705d67dabc145aa9413b13d18aede29fa2
- live/deployed-source-and-capture.json SHA256 7feea8e1a0fc1b9795f87fa0243220abfef31760129b27c0933e659cd35dcb61

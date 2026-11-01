# Vendored umbrella subchart lagged the reviewed source chart

The coherent3e11 preflight found that deploy/helm/phorvex-stack/charts/phorvex-0.1.4.tgz omitted reviewed source deployment/value changes for captureCostEvidence. Two gates independently rejected the same mismatch. The active stage deployment used the correctly rendered direct source chart, so this finding concerns packaged installation consistency.

Deterministic GNUtar1.35/Helm3.16.4 regeneration changes exactly two archive members, keeps76membernames/74memberbytes and passes source consistency plus default/optin renders. Archive SHA012cdcc459fa585f63768227b5d418c2c428e53ff2fc210076c657d19bbab036 independently reviewed at fixes/BENCH-STAGE/evidence/peer-review/packaging/component-review.json. Final coherent rerun remains required. Covered by active BENCH-STAGE, no separate product change inferred.

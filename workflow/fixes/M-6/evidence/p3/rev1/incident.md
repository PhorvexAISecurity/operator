# M6 independent incident evidence — UNAVAILABLE

Reviewer: codex-m006. Implementation head `8da845ab8f38b06cab120cfe30239b3722c03c25`;
original analysis baseline `79c0370dd460a1d6400bc62346638655f64ae709`;
reviewed integration base `5a0fd3fa6f00ae93da442d84ac2b651b6a2573f9`.

The author handed off an unfilled incident template and baseline source excerpts,
plus mutation controls on modified head. These do not reproduce the admission gap
through the manager principal and real ephemeralcontainers API with baseline/head
outcomes and a legitimate positive control, as required by the signed decision.

Independent production-reader/verifier counterexamples are recorded in
`p3/verdict.md` and `p3/rev1/adversarial.log`. They use a fake transport and are
explicitly not the required real API incident acceptance proof.

Implementation review failed. No incident PASS, real-cluster verification, waiver
or live mutation authorization is asserted. Complete the real API incident matrix
in an appropriately authorized isolated environment after corrections; retain
explicit baseline, source/deployment pins and attributable controls.

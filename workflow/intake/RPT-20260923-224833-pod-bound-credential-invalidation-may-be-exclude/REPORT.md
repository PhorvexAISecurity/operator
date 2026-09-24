# Report

## Claim
The recon model's blanket credential rationale incorrectly says a Pod-scoped action cannot invalidate a Pod-bound Kubernetes API token before TTL. It also lacks a separate structural representation of the continuing API-authentication capability for this narrowly defined token class.

## Expected behavior
Keep copied credential knowledge and general/offline credentials coverless. Represent conditional default-API-audience Pod-bound exposure only from current admitted Pod/SA evidence; exact Pod retirement can remove that online capability. Planned coverage must not become an observed security-success claim.

## Observed behavior
Source comments deny the mechanism; the independent owned round3 control measured same-token HTTP200 without action and HTTP401 after binding Pod absence, with legitimate200 and natural-expiry margin. No installed Phorvex response was tested.

## Reproduction and scope
One isolated two-Pod namespace on the existing dev node; no business credentials or shared configuration change. Actual result and cleanup are retained under the campaign round3 manifest. Coverage change requires conservative production ingestion and all existing feasibility gates.

## Initial evidence
See VERIFICATION.md, the campaign round3 spec/result/review, and private token-model/FIX-PLAN.md. Treat the broader objective-weight effect as a source change needing independent review and tests, not a conclusion from one live effect.

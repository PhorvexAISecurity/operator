# Independent callback repair review

Accepted the narrow source change at runner `37865214e87e3566ba9822a31c36f98cbba56b4b0d498c2c0fcd8881e0612861` and regression tests `42c3fd4e2c09e3bb80e2147c8b6a6561381bea2b8f4b46dbd78b72bdb72ed2c7`.

Physical2 exposed a concrete evidence defect: Resident retained the response dictionary by reference, then the actual Episode.record_probe callback enriched and normalized that dictionary. Comparison with the original terminal consequently rejected conserved raw responses. Copying the raw response before that callback preserves the original evidence. Six affected tests pass independently. Replacing only that copy with the old alias in memory makes the actual mutating-callback regression fail at the original conservation predicate. This sensitivity check is a local test, not a historical execution.

The real HTTP500 responses still cause an adverse outcome. The change permits honest conserved failed-drain acknowledgement and does not repair availability, change an oracle, or reclassify either original physical failure. Physical2 remains INCOMPLETE with its original transport acknowledgement flag unchanged. Its separately verified safe state permits lease release without defense credit.

This review grants no physical authority, extends no deadline, and consumes no new episode. Any next attempt requires its own prospective source/profile admission, fresh protected native readback and root lease. The fixed20:03UTC deadline, lifetime ceiling9 and strict behavior gates remain. Full original DOCX/worksheet acceptance is not established. Exact raw input, checker, test logs and sensitivity bindings are in REVIEW-HARNESS-REPAIR-2.json.

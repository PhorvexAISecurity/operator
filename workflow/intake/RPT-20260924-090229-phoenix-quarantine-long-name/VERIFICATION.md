# Independent Phoenix label reproduction

Lead codex-lead independently executed the real SecurityEvent reconciler with Kubernetes label validation at its NetworkPolicy CREATE and Pod UPDATE boundaries. This is a source-level producer test using the API validation library, not a claim that a live API server was used.

Baseline source: `e2ee94315828a180a83902f6eb61e37a66bce22d`. Reviewed worker source: `b3adc904bbda0a1e503065c840a71f40ca57c95d`; integration equivalent: `8c665d39`. The baseline overlay restores the complete original controller file while retaining the newly added regression and helper, so the producer wiring itself must change for the test to pass.

The baseline fails at the intended CREATE boundary: `API NetworkPolicy selector label rejected: [must be no more than 63 characters]`. The existing short-name quarantine/replacement control passes on that same baseline. Repaired producer, short-name compatibility, maximum valid namespace/Pod lengths, stable distinct tuple mapping, target UID fencing, recreated namespace rejection and immediate pre-effect revalidation all pass. Package vet also passes. Exact commands, source hashes and log hashes are in [lead result](../../fixes/CAT-PHOENIX-LABEL/evidence/lead/RESULT.json).

The repair keeps the historical name where it is a legal label, and otherwise uses a domain-separated 192-bit hash of the unambiguous namespace/Pod tuple. The fixture keeps realistic full nonce and controller-generated Pod names; it is not shortened to evade the actuator defect.

No live resources were changed. The Phoenix controller itself must be rebuilt/deployed before the repaired long-name behavior can be live verified. Manager/console deployment alone is insufficient. A created deny policy is still not packet mitigation; the independent CNI and attacker/legitimate-client controls remain required.

Result: PASS for the reported source defect and its positive control.

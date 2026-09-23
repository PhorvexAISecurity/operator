# Verification

## Revised pre-registered test

Console source main 3f4e2cc0c9415ce93ec525a957bfd96029f8dc0a. Exercise the actual RunEvidence reader using retained metric rows, without cluster requests.

Claim: per-run evidence loses validity, functional-control identity and reason. The actual legacy benign round57 result is counted as a security trial and the current UI expression labels its functional success attack landed; the actual valid round69 functional result becomes merely skipped.

Falsifier: the reader preserves the semantic fields and separates functional/invalid rows from scored security arms. Positive control: separately labelled valid adversarial input reaches the same reader.

Important corrected hypothesis: actual GPU v11 is skipped=true and is excluded from aggregation, so it does not reproduce a false defended verdict. Its invalid reason is lost. A first local reproduction used multiline JSON instead of JSONL and was non-discriminating; after correcting framing, the test disproved the original v11 false-defended hypothesis. Both failed attempts are retained in this account.

Inputs: original-source-hash-bound field projection for v11; existing tracked round57-restart and round69-quorum metrics, unchanged. No new NATS execution. Temporary test source removed after execution; input and test program retained.

## Result

PASS: the revised test exercised actual RunEvidence on all three retained inputs and the valid adversarial positive control. Go1.26.3 returned exit0; source test removed after execution. See evidence/reproduction-result.json.

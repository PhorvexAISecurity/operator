# Root-cause deduplication

## Search and source

Used workflow dedup-intake and read M-167, M-168 and M-169. Trigger is a fixed-suite validated non-pass terminal artifact with process error: finishFunctional records partial, then FunctionalResult rejects partial before reading the retained artifacts.

## Candidate comparison

- M-167 concerns failed durable storage configuration. Here the exact retained job/result/metrics are valid and durable; an API state gate hides them.
- M-168 concerns a different three-arm stimulus/unsafe restore implementation, including misleading generic diagnostics. Its fix does not change this new fixed-suite FunctionalResult state gate. No attack verdict is being credited here.
- M-169 concerns unsynchronized shared outcome pointers. This failure reproduces sequentially with locked status copying; no race is needed.
- M-136 authentication and M-146 numeric zero serialization are unrelated to this terminal-state predicate. Authentication and numeric telemetry do not change in this repair.

## Determination

NEW. Required correction is validated non-pass evidence projection for partial fixed-suite runs, retaining authoritative unsafe status and excluding partial metric credit. Separate underlying Voice cleanup failure is tracked independently.

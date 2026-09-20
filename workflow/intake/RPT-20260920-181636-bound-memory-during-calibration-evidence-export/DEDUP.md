# Deduplication ruling

NEW bounded source defect: calibration evidence export materializes complete retained comparison JSON and CSV multiple times, causing a large peak above the retained Runtime history. Fix is bounded streaming serialization with unchanged complete data, output semantics and atomic per-file replacement.

M137 concerns full-manager tick/API/cache scale and later audit/trace costs; its source boundaries do not repair internal/calib.Export. This finding has its own direct public-producer counterexample and exporter-specific correction; overall capacity remains M137.

M179 is expired references retained beyond compacted slice length. It is already repaired; this experiment is inside7.5h of the configured7day window and exercises nonexpired data. No expiry cleanup fixes this export buffering.

M98 is value/cost dimensional consistency, not evidence serialization. No ambiguous shared root cause remains among these candidates. Retention count/byte policy and actual OOM cause remain separate; this issue must not claim either is solved.

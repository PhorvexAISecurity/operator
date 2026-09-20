# Bounded calibration export verification

The exploratory actual Runtime/Export differential and exact source/test/binary hashes are retained in the campaign capacity/calibration-export-probe directory. This verifies a source allocation spike at the explicitly synthetic cardinality; it does not establish live OOM causality.

Independent worker confirmation is requested before fix implementation. Rebuild or verify the exact compiled experiment against unchanged calib production bytes. Run disabled/enabled in fresh processes with identical Runtime history; compare actual generated evidence counts/schema and peak/allocated memory. Positive: every comparison remains in generated JSON/CSV. Negative: no export performs no export I/O, with same retained history. Falsifier: discrepancy depends on different history/source or only on a fabricated final flag. No cluster changes or deadlines/coverage waivers.

## Verified source finding

The investigator reproduced the actual public Runtime/Export differential locally with a source-bound test binary. Both runs pass the exact24300-comparison history assertion. Disabled export:147332KiB maxRSS/zerooutputfiles. Enabled export:547684KiB maxRSS/13files189252291bytes. The complete raw commands/testsource/binaryhash and results are retained in the linked campaign report. Calib production files are byte-identical to deployed7460fe5a and currentmain92f961bd. Positive control: actual exporter emits all expected files; no serialization occurs in disabled contrast. This proves the allocation defect only. Worker independent confirmation and output-row parity are required before accepting a repair.

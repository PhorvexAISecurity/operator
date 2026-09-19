# Initial root-cause comparison

M137 concerns the controller-runtime informer cache and its O(cluster) scale envelope; this candidate concerns internal/calib.Runtime.samples compaction retaining expired object references. The sources and ownership differ. The live OOM incident is related investigation context, not proof that either causes it. M98/M108 calibration design concerns do not establish this concrete memory-release repair. Formal dedup/promotion remains pending.

## Lead root-cause comparison — NEW

M137 concerns missing measured full-tick capacity and cached cluster inventory/status-write cost. This finding instead occurs after the calibration Runtime has already logically expired history: in-place slice compaction retains nested comparison/score and snapshot references in unused backing-array slots. M129/M140 concern policy-owner retirement and recreation state, not time-based pruning inside the independent calibration history. M144 concerns lambda learning/floor dynamics, with no samples compaction mechanism. M106 epistemic calibration and M109 GPU uncertainty do not govern history ownership/release. Other ranked rows matched generic report vocabulary and name unrelated auth, audit, telemetry, CRD or campaign mechanisms. Register source search found no existing expired calibration backing-array issue.

The observed6–8-hour manager OOM and the legitimate seven-day comparison memory budget remain distinct unproven/design questions. Neither is conflated with this verified expired-reference defect. A bounded unused-slot clear can preserve every retained observation and published scientific result. No human dedup ruling is needed because the mechanisms and reproductions are distinct.

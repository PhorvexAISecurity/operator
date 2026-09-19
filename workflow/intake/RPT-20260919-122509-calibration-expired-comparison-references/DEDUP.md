# Initial root-cause comparison

M137 concerns the controller-runtime informer cache and its O(cluster) scale envelope; this candidate concerns internal/calib.Runtime.samples compaction retaining expired object references. The sources and ownership differ. The live OOM incident is related investigation context, not proof that either causes it. M98/M108 calibration design concerns do not establish this concrete memory-release repair. Formal dedup/promotion remains pending.

# Calibration export allocation counterexample

At the same actual Runtime history (112 synthetic assets,10 nodes,9 policy comparisons/10s,12 scores on each side,7.5 simulated hours =24,300 comparisons), final public Export materially increases memory. Separate fresh processes ran the identical history construction; only the final Export call differs. This is a source-specific differential, not a full manager or production-cardinality reproduction.

Disabled: max RSS147,332KiB, retained heap69,294,504bytes before final step. Enabled: max RSS547,684KiB; sampled heap455,870,504bytes;732,692,624bytes cumulatively allocated by Export. It produced13files/189,252,291bytes. The sampling is not a guaranteed instantaneous peak. Output files were temporary and automatically cleaned by the test.

Actual Export materializes the full indented comparison JSON, full CSV rows, serialized score-cell strings and an additional CSV byte buffer. Stream rows into temporary files while preserving the exact schema, ordering, bytes for valid inputs and atomic replacement/error cleanup. Do not disable exports, shorten the seven-day history, discard comparison evidence or claim to solve full retention/capacity/OOM. Scalar/small distributions can use the same writer abstraction; whole-slice json.Encoder alone still buffers the entire payload.

Live manager OOM18:03:53 occurred after calibration-refresh log18:03:52.649 and under256Mi. That correlation plus this allocation counterexample warrants a focused source repair but does not identify live causality. Informer retention, real score cardinality, GC/cgroup memory and repaired-source lifetime remain separate.

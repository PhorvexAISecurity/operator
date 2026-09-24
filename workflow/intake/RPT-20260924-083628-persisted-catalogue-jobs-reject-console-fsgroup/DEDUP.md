# Root-cause comparison

Determination: NEW.

M-189 exposes validated non-pass evidence from partial runs; this incident occurs earlier when LoadJob/LoadRuntimeConfig reject a same-owner fsGroup-adjusted record before the result can be validated. PR323 includes M-189 and still reproduces this distinct permission predicate failure. M-168 concerns unsupported stimulus, outcome inference and unsafe experiment restart restoration, not the mode required for persisted fixed-suite records. M-136 concerns authentication/default mutation authorization, not filesystem compatibility. Ranked lexical matches M-140, M-144, M-2 and M-142 concern unrelated tenant state, economics, CRD enums and telemetry.

The new repair changes only the private-file readers, preserves the earlier partial/unsafe outcome, and does not implement the separate Voice reconciliation endpoint. A common console symptom is insufficient to merge different root causes.

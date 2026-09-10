# PHORVEXSEC-226 / M-32 raw selection coverage

Base 345c0ade12ac5b0d6ec71fe96c70cb9bc1d9cbac. RECORD representation correction, no optimizer/math/security response changes.

Source trace: decision/coverage.go covValue sums set.FactWeights over the chosen candidate's CoverKeys. This is full standalone selection-time recon fact weight, not marginal gain, achieved containment, dollars or a calibrated probability. CoverageValue is assigned that sum. The old runner clamps DecisionValue to 1 and passes it as Request.Score; Phoenix writes that to spec.anomalyScore. This is a current static reproduction of the mapping, distinct from the register's historical live sample.

## Wire contract
P1 requests carry optional CoverageValue separately from genuine Score. Phoenix emits the raw finite nonnegative value in the existing spec.metrics.coverageValue decimal-string field, with shortest round-trip float64 precision, including valid zero and distinct values above one. metadata.annotations[phorvex.ai/coverage-contract]=selection-fact-weight-v1 and coverage-status=present describe it. Presence of coverage always suppresses anomalyScore, even if invalid. Invalid nonfinite/negative input omits coverage and writes coverage-status=invalid-source-value, without changing whether the event is dispatched. Omitted coverage and genuine-score requests retain their pre-existing anomaly contract. Deprecated P0 ThreatRisk mapping is unchanged and is outside the coverage correction.

No new structural field is needed: the existing SecurityEvent v1beta1 schema already admits metrics as map[string]string and optional anomalyScore. Both existing CRD copies support it. The existing typed API/deepcopy handles the map. No unknown-field bypass or schema widening.

## Consumers / compatibility
Generated AMTD strategies use exact Type/Source/ThreatLevel rules with no anomaly threshold. Tests execute the real MatchStrategy predicate on the emitted event. Self-produced events are excluded by ingest/events.go before anomaly evidence handling. Audit/console already use explicit coverageValue from the decision and do not derive it from SecurityEvent.anomalyScore. No event-based percentage display in this declared consumer path needs conversion. Genuine detector fields are unchanged.

Phoenix supports customer-configured anomaly thresholds and weighted metrics scoring. Before deployment, Hami must inventory those configurations for PhorvexController events. Do not repoint a score threshold or scorer weight to raw coverage. If such a custom integration exists, link its migration and get the product/security ruling before changing that response behavior. Source tests establish the generated default rule only, not arbitrary deployed rules. Old saturated controller events are legacy invalid anomaly evidence with unknown original coverage, not values to backfill or rewrite. Downgrading the producer reintroduces the old false mapping, so retain new evidence and do not treat downgrade as a semantic fix.

## Validation and limits
Focused actuator/runner/ingest/audit tests verify raw >1 values, zero, fractional precision, invalid inputs, no anomaly alias, unchanged genuine scores, and actual runner request mapping. A Kubernetes 1.33 envtest API server installs the existing CRD and reads back 12.3456789012345 without pruning and without anomalyScore. Raw outputs attached. The indirect semver dependency supports envtest only.

No live image/digest/installed CRD/customer configuration is certified. Independent DEV/security review and Hami deployed readback/consumer verification remain required. Schema support is already in source, but existing deployed schema/readers must be verified before producer rollout. No normalization, threshold, new grant or mathematical approval is needed for this representation change.

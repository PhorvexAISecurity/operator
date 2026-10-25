package cost

// ProductionParameters exposes the exact numeric sources consumed by the cost
// model. It is read-only provenance for the decision parameter manifest.
// Production scoring continues to read the same constants and phase table.
func ProductionParameters() map[string]float64 {
	values := map[string]float64{
		"cost.lambda.seed":                         DefaultLambdaSeed,
		"cost.lambda.step":                         LambdaStep,
		"cost.lambda.minimum":                      LambdaMinimum,
		"cost.lambda.maximum":                      LambdaMaximum,
		"cost.lambda.maximum-excess-per-tick":      LambdaMaxExcess,
		"cost.rls.feature-count":                   featureDim,
		"cost.rls.forgetting-factor":               RLSForgettingFactor,
		"cost.rls.initial-covariance":              RLSInitialCovariance,
		"cost.rls.maximum-theta-step":              maxThetaStep,
		"cost.rls.prediction-maximum":              RLSPredictionMaximum,
		"cost.rls.request-rate-normalizer":         RLSRequestRateNormalizer,
		"cost.conformal.window":                    ConformalWindow,
		"cost.conformal.alpha":                     ConformalAlpha,
		"cost.conformal.cold-start-slack":          ColdStartSlack,
		"cost.conformal.calibrated-observations":   ConformalMinimumSamples,
		"cost.gpu-envelope.configured":             GPUEnvelopeMax(),
		"cost.ready-delay-reference-seconds":       ReadyDelayReference.Seconds(),
		"cost.default-ceiling":                     DefaultCostCeiling,
		"cost.flow.bias-prior":                     biasPrior,
		"cost.flow.gpu-prior":                      gpuPrior,
		"cost.flow.load-prior":                     loadPrior,
		"cost.flow.cutover-base":                   estimatedCutoverBase,
		"cost.flow.cutover-load-span":              estimatedCutoverLoadSpan,
		"cost.flow.serving-state-base":             estimatedServingStateBase,
		"cost.flow.serving-state-load-span":        estimatedServingLoadSpan,
		"cost.flow.lightweight":                    estimatedLightweightFlow,
		"cost.flow.unknown-maximum":                unknownActionFlowMax,
		"cost.flow.kv-reset-ttft-penalty-fraction": measuredKVResetTTFTPenaltyFraction,
		"cost.flow.request-rate-normalizer":        requestRateNormalizer,
		"cost.flow.connection-count-normalizer":    connectionCountNormalizer,
		"cost.flow.quarantine-base":                quarantineBase,
		"cost.flow.quarantine-connection-span":     quarantineConnectionSpan,
	}
	for phase, enc := range phaseFlowEncoding {
		values["cost.phase."+string(phase)+".rls-prior"] = enc.priorWeight
	}
	return values
}

// ProductionNormActionPriors returns the normalized structural costs read by
// normCostP1. Names match model.Action values for deterministic manifest keys.
func ProductionNormActionPriors() map[string]float64 {
	return map[string]float64{
		"cost.norm.action.rotate":                       NormCostWorkloadReplacement,
		"cost.norm.action.warm-swap":                    NormCostWorkloadReplacement,
		"cost.norm.action.quarantine":                   NormCostWorkloadReplacement / float64(len(structuralComponents)),
		"cost.norm.action.mig-rebind":                   NormCostSharedDeviceMutation,
		"cost.norm.action.model-shard-replace-per-rank": NormCostWorkloadReplacement,
		"cost.norm.action.endpoint-rotate.route-ready":  NormCostServiceRekey,
		"cost.norm.action.endpoint-rotate.fallback":     NormCostMetadataMutation,
		"cost.norm.action.adapter-rotate":               NormCostServingConfiguration,
		"cost.norm.action.kv-reset":                     NormCostStateReset,
		"cost.norm.action.kv-migrate-invalidate":        NormCostStateReset,
		"cost.norm.action.guardrail-rotate":             NormCostStateReset,
		"cost.norm.action.identity-rotate":              NormCostPartialIdentity,
		"cost.norm.action.route-rotate":                 NormCostMetadataMutation,
		"cost.norm.action.debugger":                     NormCostMetadataMutation,
		"cost.norm.action.custom-inject":                NormCostMetadataMutation,
		"cost.norm.action.request-drain":                NormCostMetadataMutation,
		"cost.norm.action.throttle":                     NormCostServingConfiguration,
	}
}

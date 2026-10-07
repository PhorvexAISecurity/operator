import type { DecisionEconomicsFields, OptionalFloat } from "./api";

export const INDEPENDENT_PREFERENCES = "independent-cost-preferences-v1";
const finite = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
const optionalValue = (v: OptionalFloat | null | undefined) => v?.present && finite(v.value) ? v.value : undefined;
export const exactNumber = (v: unknown) => finite(v) ? String(v) : "—";

// Support exact audit metadata and the attack API's validated flattened projection.
// Availability flags and OptionalFloat.presence always win over numeric aliases.
export function decisionEconomics(record: DecisionEconomicsFields) {
  const available = record.economicsAvailable !== false;
  const metadata = available ? record.economics : undefined;
  const version = available ? metadata?.version ?? record.economicsVersion : undefined;
  const independent = version === INDEPENDENT_PREFERENCES;
  const norm = available ? optionalValue(metadata?.normPreference ?? record.normPreference) : undefined;
  const flow = available ? optionalValue(metadata?.flowPreference ?? record.flowPreference) : undefined;
  const lambda = record.lambdaAvailable === false ? undefined
    : metadata?.lambdaRuntimeLegacy ? optionalValue(metadata.lambdaRuntimeLegacy)
    : finite(record.lambda) ? record.lambda : undefined;
  const coefficient = independent || !available ? undefined
    : metadata?.effectiveCostCoefficient ?? record.effectiveCostCoefficient;
  return {
    version: version || "not recorded", independent, norm, flow, lambda, coefficient,
    preferences: `βNorm=${exactNumber(norm)} · βFlow=${exactNumber(flow)}`,
    formula: independent ? "security − βNorm·CNorm − βFlow·CFlow" : "security − common coefficient·ECost",
  };
}

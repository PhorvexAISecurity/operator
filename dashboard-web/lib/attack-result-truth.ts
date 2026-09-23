import type { AttackResult } from "@/lib/api";

export function isCatalogueSignalResult(result: AttackResult): boolean {
  return result.evidenceKind === "catalogue-signal"
    || result.evidenceKind === "synthetic-detector-signal"
    || result.resultSchemaVersion === "catalogue-signal-v1"
    || result.resultSchemaVersion === "synthetic-detector-signal-v2"
    || result.producerRoute === "/api/workload/fire-scenario";
}

export function isUnversionedResult(result: AttackResult): boolean {
  return !result.resultSchemaVersion && !result.evidenceKind;
}

export function catalogueSignalState(result: AttackResult): {
  label: "SIGNAL ACCEPTED" | "SIGNAL RECORD PARTIAL";
  response: "RESPONSE OBSERVED" | "RESPONSE UNCONFIRMED" | "OBSERVATION UNAVAILABLE";
  responseDetail: string;
  limitation: string;
} {
  const partial = result.status === "partial" || !!result.observationError;
  let response: "RESPONSE OBSERVED" | "RESPONSE UNCONFIRMED" | "OBSERVATION UNAVAILABLE" = "RESPONSE UNCONFIRMED";
  if (result.responseObserved) response = "RESPONSE OBSERVED";
  else if (result.outcomeClass === "observation-unavailable") response = "OBSERVATION UNAVAILABLE";
  else if (result.outcomeClass === "response-unconfirmed") response = "RESPONSE UNCONFIRMED";
  else if (result.observationError) response = "OBSERVATION UNAVAILABLE";

  const responseDetail = result.responseObserved
    ? `${result.responseAction || "target response"}${result.responsePod ? ` on ${result.responsePod}` : ""}${(result.responseSeconds ?? 0) > 0 ? ` in ${result.responseSeconds}s` : ""}`
    : result.observationError || "No exact target response was confirmed during the observation window.";
  const limitation = result.stimulusEvidence?.limitation
    || "This synthetic signal does not execute or measure the named behavioral attack and carries no defense, dwell, containment, or ROI credit.";
  return {
    label: partial ? "SIGNAL RECORD PARTIAL" : "SIGNAL ACCEPTED",
    response,
    responseDetail,
    limitation,
  };
}

export function showSecurityOutcomeSections(result: AttackResult): boolean {
  return !isCatalogueSignalResult(result);
}

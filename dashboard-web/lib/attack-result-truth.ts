import type { AttackResult, AttackDecisionEvidence, CatalogCompat } from "@/lib/api";

export function canSendCatalogueSignal(item: CatalogCompat, armed: boolean): boolean {
  return armed && item.compatible === true && item.signalEligible === true;
}

export function exactCatalogueDecision(result: AttackResult): AttackDecisionEvidence | undefined {
  const stimulus = result.stimulusEvidence;
  if (!stimulus?.observed || !stimulus.eventUid || !stimulus.eventName || !stimulus.targetUid) return undefined;
  // The producer's summary is its ranked exact decision; retain that rank when
  // the bounded trace contains earlier observations of the same event.
  const candidates = [...(result.decisionEvidence ? [result.decisionEvidence] : []), ...(result.decisionTraceEvidence || [])];
  return candidates.find((row) => row.correlation === "exact-event-uid" && row.eventUid === stimulus.eventUid &&
    row.eventName === stimulus.eventName && row.targetUid === stimulus.targetUid &&
    (!stimulus.eventRule || row.eventRule === stimulus.eventRule));
}

export function isCatalogueSignalResult(result: AttackResult): boolean {
  return result.evidenceKind === "catalogue-signal"
    || result.evidenceKind === "synthetic-detector-signal"
    || result.resultSchemaVersion === "catalogue-signal-v1"
    || result.resultSchemaVersion === "synthetic-detector-signal-v2"
    || result.producerRoute === "/api/workload/fire-scenario";
}

export function attackCSVActuator(result: AttackResult): string {
  // The CSV column means a completed actuator in behavioral rows. A manager
  // selection on a signal-only row does not satisfy that meaning.
  return isCatalogueSignalResult(result) ? "" : result.phorvexAction || "";
}

export function isUnversionedResult(result: AttackResult): boolean {
  return !result.resultSchemaVersion && !result.evidenceKind;
}

export function catalogueSignalState(result: AttackResult): {
  label: "SIGNAL ACCEPTED" | "SIGNAL RECORD PARTIAL";
  response: "TARGET UID CHANGED" | "TARGET CHANGE UNCONFIRMED" | "OBSERVATION UNAVAILABLE";
  responseDetail: string;
  limitation: string;
} {
  const partial = result.status === "partial" || !!result.observationError;
  let response: "TARGET UID CHANGED" | "TARGET CHANGE UNCONFIRMED" | "OBSERVATION UNAVAILABLE" = "TARGET CHANGE UNCONFIRMED";
  if (result.responseObserved) response = "TARGET UID CHANGED";
  else if (result.outcomeClass === "observation-unavailable") response = "OBSERVATION UNAVAILABLE";
  else if (result.outcomeClass === "response-unconfirmed") response = "TARGET CHANGE UNCONFIRMED";
  else if (result.observationError) response = "OBSERVATION UNAVAILABLE";

  const responseDetail = result.responseObserved
    ? `Target Pod UID changed${result.responsePod ? ` for ${result.responsePod}` : ""}${(result.responseSeconds ?? 0) > 0 ? ` in ${result.responseSeconds}s` : ""}; cause not established.`
    : result.observationError || "No exact target Pod UID change was confirmed during the observation window.";
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
  return !isCatalogueSignalResult(result) && result.evidenceKind !== "voice-memory-live" && result.evidenceKind !== "litellm-live-client-policy";
}

export function hasAvailabilityCostEvidence(result: AttackResult): boolean {
  return result.evidenceKind !== "vllm-in-place-effect" && result.evidenceKind !== "vllm-unsupported-stimulus";
}

export function attackCSVRow(r: AttackResult): (string | number)[] {
  return attackCSVCells(r).map((value) => value ?? "");
}

function attackCSVCells(r: AttackResult): (string | number | undefined)[] {
  const identity = [r.firedAt, r.service, r.attack, r.mitre];
  if (isCatalogueSignalResult(r)) {
    return [...identity, "CATALOGUE SIGNAL · UNSCORED", "", ...Array(11).fill(""), r.observationError || r.stimulusEvidence?.limitation || "behavioral outcome not measured"];
  }
  if (r.evidenceKind === "voice-memory-live" || r.evidenceKind === "litellm-live-client-policy") {
    const scope = r.evidenceKind === "voice-memory-live"
      ? "Exact caller/note context containment; model obedience and generic dwell, availability and cost were not measured."
      : "Owned client containment; generic dwell, availability, cost and model replication were not measured.";
    return [...identity, r.outcome || r.status, r.actuated ? attackCSVActuator(r) : "", r.containment || "", ...Array(10).fill(""), scope];
  }
  if (!hasAvailabilityCostEvidence(r)) {
    return [...identity, r.outcome || r.status, attackCSVActuator(r), r.containment, r.timeToDefendSec, r.dwellSec,
      r.dwellOngoing ? "ongoing" : "bounded", ...Array(7).fill(""), r.why];
  }
  return [...identity, r.outcome || r.status, attackCSVActuator(r), r.containment, r.timeToDefendSec, r.dwellSec,
    r.dwellOngoing ? "ongoing" : "bounded", r.uptimeBefore, r.uptimeDip, r.uptimeAfter, r.cost?.without, r.cost?.r6, r.cost?.with, r.cost?.savings, r.why];
}

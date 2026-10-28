import * as React from "react";

interface Guidance {
  name: string;
  benignControl?: boolean;
  expectedActuators?: string[];
  responseGuidanceBasis?: "name-heuristic" | "explicit-effect" | "reviewed-catalogue-metadata" | "none";
  responseGuidance?: string;
}

const credentialLimit = "A captured Pod-bound API token may stop authenticating after its binding Pod is deleted; initial disclosure persists. Quarantine cannot revoke an off-Pod bearer token. No automatic detector or manager response is asserted.";

export function displayActuatorHints(item: Guidance): string[] {
  const hints = item.expectedActuators || [];
  return item.name === "c1-credtheft-rbac" ? hints.filter((hint) => hint !== "quarantine") : hints;
}

export function ScenarioResponseGuidance({ item }: { item: Guidance }) {
  const hints = displayActuatorHints(item);
  const basis = item.responseGuidanceBasis;
  const label = basis === "explicit-effect" ? "Expected effect operation" :
    basis === "reviewed-catalogue-metadata" ? "Review-pinned expected action (not evidence)" :
    basis === "name-heuristic" ? (hints.length > 0 ? "Name-based actuator hints" : "No actuator hint mapped") :
    basis === "none" ? "No actuator response asserted" :
    hints.length > 0 ? "Legacy actuator hints (basis unverified)" : "Response mapping unestablished";
  const guidance = item.name === "c1-credtheft-rbac" ? credentialLimit :
    item.responseGuidance || (item.benignControl === true
      ? "This benign functional control does not measure a security outcome."
      : "No automatic response or defense is established. Check case-specific detector, selection, effect, and outcome evidence.");
  return <div className="text-[11px] text-muted-foreground" data-guidance-basis={basis || "legacy-unknown"}>
    <span className="text-foreground">{label}</span>
    {basis !== "none" && hints.length > 0 && <>: <span className="font-mono">{hints.join(", ")}</span></>}
    <span>. {guidance}</span>
  </div>;
}

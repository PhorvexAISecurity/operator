import { Badge } from "@/components/ui/primitives";
import type { AttackResult } from "@/lib/api";
import { catalogueSignalState, exactCatalogueDecision } from "@/lib/attack-result-truth";
import { DecisionEvidencePanel } from "@/components/panels/decision-evidence";

export function CatalogueSignalResult({ result, compact = false }: { result: AttackResult; compact?: boolean }) {
  const state = catalogueSignalState(result);
  const exact = exactCatalogueDecision(result);
  const temporal = result.temporalDecisionEvidence || (result.decisionEvidence?.source === "temporal-candidate" ? result.decisionEvidence : undefined);
  const brainState = exact ? "exact event/target decision join" : temporal ? "temporal candidate only" : "unavailable";
  const selectedAction = exact?.selected === true && exact.action ? exact.action : "not established";
  return (
    <div className="space-y-2 rounded-md border border-warning/30 bg-warning/[0.04] p-2.5 text-[11px]">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="pending">{state.label}</Badge>
        <Badge variant={result.responseObserved ? "modeled" : "neutral"}>{state.response}</Badge>
        <span className="font-mono text-muted-foreground" title={result.id}>{result.id}</span>
      </div>
      <div className="text-foreground">{state.responseDetail}</div>
      <div className="text-muted-foreground">
        injected SecurityEvent <span className="font-mono text-foreground/85">{result.stimulusEvidence?.eventName || "unavailable"}</span>
        {result.stimulusEvidence?.eventRule ? <> · rule <span className="font-mono text-foreground/85">{result.stimulusEvidence.eventRule}</span></> : null}
      </div>
      <div className="text-muted-foreground">
        listed name-derived hint <span className="font-mono text-foreground/85">{result.expectedActuator || "unavailable"}</span>
        <> · brain decision {brainState}</>
        <> · exactly joined selected action <span className="font-mono text-foreground/85">{selectedAction}</span></>
      </div>
      <div className="text-muted-foreground">actuator/operation completion: not established without a separate exact receipt · manager dispatch alone is not completion</div>
      <div className="text-muted-foreground">
        behavioral attack executed: <span className="font-medium text-foreground">no</span> · behavioral outcome and landed reason: <span className="font-medium text-foreground">not evaluated</span>
      </div>
      {!compact && result.stimulusEvidence && (
        <div className="text-muted-foreground">
          accepted signal <span className="font-mono text-foreground/85">{result.stimulusEvidence.eventName || "—"}</span>
          {result.stimulusEvidence.targetUid ? <> · target UID <span className="font-mono text-foreground/85">{result.stimulusEvidence.targetUid.slice(0, 12)}…</span></> : null}
          {result.stimulusEvidence.correlation ? <> · correlation {result.stimulusEvidence.correlation}</> : null}
        </div>
      )}
      <DecisionEvidencePanel exact={exact ? [exact] : []} temporal={temporal} compact={compact} observationStartedAt={result.observationStartedAt} observationDeadline={result.observationDeadline} />
      {result.observationError && <div className="text-warning">observation error: {result.observationError}</div>}
      <div className="text-warning/90">limits: {state.limitation}</div>
    </div>
  );
}

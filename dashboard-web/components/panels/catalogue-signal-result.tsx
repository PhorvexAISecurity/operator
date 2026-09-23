import { Badge } from "@/components/ui/primitives";
import type { AttackResult } from "@/lib/api";
import { catalogueSignalState } from "@/lib/attack-result-truth";

export function CatalogueSignalResult({ result, compact = false }: { result: AttackResult; compact?: boolean }) {
  const state = catalogueSignalState(result);
  const decision = result.decisionEvidence;
  return (
    <div className="space-y-2 rounded-md border border-warning/30 bg-warning/[0.04] p-2.5 text-[11px]">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="pending">{state.label}</Badge>
        <Badge variant={result.responseObserved ? "modeled" : "neutral"}>{state.response}</Badge>
        <span className="font-mono text-muted-foreground" title={result.id}>{result.id}</span>
      </div>
      <div className="text-foreground">{state.responseDetail}</div>
      <div className="text-muted-foreground">
        behavioral attack executed: <span className="font-medium text-foreground">no</span> · security outcome: <span className="font-medium text-foreground">not measured</span>
      </div>
      {!compact && result.stimulusEvidence && (
        <div className="text-muted-foreground">
          accepted signal <span className="font-mono text-foreground/85">{result.stimulusEvidence.eventName || "—"}</span>
          {result.stimulusEvidence.targetUid ? <> · target UID <span className="font-mono text-foreground/85">{result.stimulusEvidence.targetUid.slice(0, 12)}…</span></> : null}
          {result.stimulusEvidence.correlation ? <> · correlation {result.stimulusEvidence.correlation}</> : null}
        </div>
      )}
      {decision && (
        <div className="border-t border-border/60 pt-2 text-muted-foreground">
          decision candidate: <span className="font-mono text-foreground/85">{decision.action || "—"}</span>
          {decision.reason ? <> · {decision.reason}</> : null}
          <> · selected {decision.selected ? "yes" : "no"} · actuated {decision.actuated ? "yes" : "no"}</>
          <div className="mt-1">Correlation: {decision.correlation}; this is diagnostic evidence, not behavioral mitigation.</div>
        </div>
      )}
      {result.observationError && <div className="text-warning">observation error: {result.observationError}</div>}
      <div className="text-warning/90">limits: {state.limitation}</div>
    </div>
  );
}

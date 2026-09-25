import type { AttackDecisionEvidence } from "@/lib/api";

function short(value?: string, keep = 12): string {
  if (!value) return "—";
  return value.length > keep ? `${value.slice(0, keep)}…` : value;
}

function yesNo(value: boolean | undefined): string {
  return value === undefined ? "unavailable" : value ? "yes" : "no";
}

export function DecisionEvidenceTrace({ decision, compact = false, observationStartedAt, observationDeadline }: { decision?: AttackDecisionEvidence; compact?: boolean; observationStartedAt?: string; observationDeadline?: string }) {
  if (!decision) {
    return (
      <div className="rounded-md border border-border/70 bg-muted/20 p-2.5 text-[11px] text-muted-foreground">
        <div className="font-medium text-foreground">Manager decision unavailable</div>
        <div className="mt-1">No event-bound or temporal decision record was returned. This is not a refusal, NOOP, failed actuator, or defense result.</div>
      </div>
    );
  }

  const exact = decision.correlation === "exact-event-uid" && !!decision.eventName && !!decision.eventUid && !!decision.targetUid;
  const temporal = decision.source === "temporal-candidate" || decision.correlation?.startsWith("temporal-");
  const dispatch = decision.dispatchOutcome || (decision.actuated ? "legacy-actuated" : "unavailable");
  const noop = decision.action === "noop" || dispatch === "not-attempted" || dispatch === "noop";
  const unavailable = !decision.decisionId && !decision.tickId && !decision.action && !decision.reason;
  const title = exact ? "Exact event match" : temporal ? "Weak temporal candidate" : unavailable ? "Decision evidence unavailable" : "Decision identity incomplete";
  const tone = exact ? "border-primary/30 bg-primary/[0.04]" : "border-warning/30 bg-warning/[0.04]";
  const missingAuthority = [
    !decision.source && "evidence source type",
    !decision.creatorIdentity && "creator identity",
    !decision.decisionId && "decision ID",
    !decision.tickId && "tick ID",
    !(decision.policyNamespace && decision.policyName && decision.policyUid) && "complete policy identity",
    !decision.brainImage && "brain image",
    !decision.gitSha && "git SHA",
  ].filter((value): value is string => !!value);

  return (
    <div className={`rounded-md border p-2.5 text-[11px] ${tone}`} data-decision-correlation={exact ? "exact" : temporal ? "temporal" : "incomplete"}>
      <div className="flex flex-wrap items-center gap-2">
        <span className={exact ? "font-medium text-primary" : "font-medium text-warning"}>{title}</span>
        {noop && <span className="rounded border border-border bg-muted/30 px-1.5 py-0.5 font-medium text-foreground">NOOP / NOT DISPATCHED</span>}
        <span className="text-muted-foreground">source {decision.source || "legacy / unavailable"}</span>
      </div>
      {exact ? (
        <div className="mt-1 text-muted-foreground">
          event <span className="font-mono text-foreground/85">{decision.eventName || "—"}</span>
          <> · UID <span className="font-mono text-foreground/85">{short(decision.eventUid)}</span></>
          <> · target <span className="font-mono text-foreground/85">{short(decision.targetUid)}</span></>
          {decision.eventRule ? <> · rule {decision.eventRule}</> : null}
          {decision.trustVerdict ? <> · trust {decision.trustVerdict}</> : null}
          {decision.declaredSource ? <> · declared source {decision.declaredSource}</> : null}
        </div>
      ) : temporal ? (
        <div className="mt-1 text-warning/90">Name/time proximity is a candidate only. No exact event UID and target join is claimed.</div>
      ) : (
        <div className="mt-1 text-warning/90">The returned identity is insufficient for an exact event-to-decision join.</div>
      )}
      {exact && missingAuthority.length > 0 && (
        <div className="mt-1 text-warning/90">
          Exact input match; decision identity is incomplete. Unavailable: {missingAuthority.join(", ")}.
        </div>
      )}
      <div className="mt-2 grid gap-1 text-muted-foreground md:grid-cols-2">
        <div>decision <span className="font-mono text-foreground/85">{short(decision.decisionId)}</span> · tick <span className="font-mono text-foreground/85">{short(decision.tickId)}</span></div>
        <div>policy <span className="font-mono text-foreground/85">{decision.policyNamespace && decision.policyName ? `${decision.policyNamespace}/${decision.policyName}` : "unavailable"}</span></div>
        <div>decision action <span className="font-mono text-foreground/85">{decision.action || "unavailable"}</span> · selected {yesNo(decision.selected)}</div>
        <div>feasible {yesNo(decision.feasible)}{decision.infeasibleWhy ? ` · ${decision.infeasibleWhy}` : ""}</div>
        <div>dispatch <span className="font-mono text-foreground/85">{dispatch}</span>{decision.dispatchReason ? ` · ${decision.dispatchReason}` : ""}</div>
        <div>handler <span className="font-mono text-foreground/85">{decision.handler || "unavailable"}</span> · manager actuation report {yesNo(decision.actuated)}</div>
      </div>
      {(decision.reason || decision.time) && (
        <div className="mt-2 text-muted-foreground">
          {decision.time ? <>recorded <span className="font-mono text-foreground/85">{decision.time}</span></> : null}
          {decision.time && decision.reason ? " · " : ""}{decision.reason ? <>reason {decision.reason}</> : null}
        </div>
      )}
      {(observationStartedAt || observationDeadline) && (
        <div className="mt-2 text-muted-foreground">
          observation window <span className="font-mono text-foreground/85">{observationStartedAt || "unavailable"}</span>
          <> → <span className="font-mono text-foreground/85">{observationDeadline || "unavailable"}</span></>
        </div>
      )}
      {(decision.dryRun !== undefined || decision.killSwitch !== undefined || decision.actuationBrakeCause) && (
        <div className="mt-2 text-muted-foreground">
          dry-run {yesNo(decision.dryRun)}{decision.dryRunCause ? ` (${decision.dryRunCause})` : ""}
          <> · kill switch {yesNo(decision.killSwitch)}{decision.killSwitchCause ? ` (${decision.killSwitchCause})` : ""}</>
          {decision.actuationBrakeCause ? <> · brake {decision.actuationBrakeCause}</> : null}
        </div>
      )}
      {(decision.actionStatus || []).length > 0 && (
        <div className="mt-2 border-t border-border/60 pt-2">
          <div className="font-medium text-foreground">Candidate status</div>
          {(decision.actionStatus || []).slice(0, compact ? 3 : 16).map((entry, index) => (
            <div key={`${entry.action}-${entry.status}-${index}`} className="mt-1 text-muted-foreground">
              <span className="font-mono text-foreground/85">{entry.action || "unknown"}</span> · {entry.status || "unavailable"}
              {entry.exclusionKind ? ` · ${entry.exclusionKind}` : ""}{entry.reason ? ` · ${entry.reason}` : ""}
              {entry.rbacUnknown ? " · RBAC unknown" : ""}
            </div>
          ))}
          {compact && (decision.actionStatus || []).length > 3 && <div className="mt-1 text-muted-foreground">+{(decision.actionStatus || []).length - 3} more candidate statuses in the full result</div>}
        </div>
      )}
      {!compact && (decision.rollbackRef || decision.mutationKind || (decision.objectsTouched || []).length > 0) && (
        <div className="mt-2 border-t border-border/60 pt-2 text-muted-foreground">
          operation: mutation {decision.mutationKind || "unavailable"}
          {decision.rollbackRef ? <> · rollback <span className="font-mono text-foreground/85">{decision.rollbackRef}</span></> : null}
          {(decision.objectsTouched || []).length > 0 ? <> · objects {(decision.objectsTouched || []).join(", ")}</> : null}
        </div>
      )}
      {(decision.brainImage || decision.gitSha || decision.policyUid || decision.creatorIdentity || decision.eventUid || decision.targetUid) && (
        <details className="mt-2 border-t border-border/60 pt-2 text-muted-foreground">
          <summary className="cursor-pointer font-medium text-foreground">Full source and authority identities</summary>
          <div className="mt-1 space-y-1 break-all font-mono text-[10px]">
            {decision.creatorIdentity && <div>creatorIdentity={decision.creatorIdentity}</div>}
            {decision.eventUid && <div>eventUid={decision.eventUid}</div>}
            {decision.targetUid && <div>targetUid={decision.targetUid}</div>}
            {decision.policyUid && <div>policyUid={decision.policyUid}</div>}
            {decision.brainImage && <div>brainImage={decision.brainImage}</div>}
            {decision.gitSha && <div>gitSha={decision.gitSha}</div>}
          </div>
        </details>
      )}
      <div className="mt-2 text-warning/90">The manager actuation report is not runtime effect confirmation; emitted-unconfirmed remains unconfirmed. Exact identity does not itself prove trusted influence or sole cause. Signal acceptance, a decision, selection, or dispatch alone carries no DEFENDED, containment, dwell, or ROI credit.</div>
    </div>
  );
}

export function DecisionEvidencePanel({ exact = [], temporal, legacy, compact = false, observationStartedAt, observationDeadline }: {
  exact?: AttackDecisionEvidence[];
  temporal?: AttackDecisionEvidence;
  legacy?: AttackDecisionEvidence;
  compact?: boolean;
  observationStartedAt?: string;
  observationDeadline?: string;
}) {
  const boundedExact = exact.slice(0, 16);
  const legacyIsTemporal = legacy?.source === "temporal-candidate" || legacy?.correlation?.startsWith("temporal-");
  const primary = boundedExact.length > 0 ? boundedExact : legacy && !(temporal && legacyIsTemporal) ? [legacy] : [];
  if (primary.length === 0 && !temporal) {
    return <DecisionEvidenceTrace observationStartedAt={observationStartedAt} observationDeadline={observationDeadline} />;
  }
  return (
    <div className="space-y-2">
      {primary.map((decision, index) => (
        <DecisionEvidenceTrace key={`${decision.eventUid || "event"}-${decision.decisionId || decision.tickId || index}`} decision={decision} compact={compact} observationStartedAt={observationStartedAt} observationDeadline={observationDeadline} />
      ))}
      {temporal && (
        <div>
          {primary.length > 0 && <div className="mb-1 text-[10px] uppercase tracking-wide text-muted-foreground">Separate weaker candidate</div>}
          <DecisionEvidenceTrace decision={temporal} compact={compact} observationStartedAt={observationStartedAt} observationDeadline={observationDeadline} />
        </div>
      )}
    </div>
  );
}

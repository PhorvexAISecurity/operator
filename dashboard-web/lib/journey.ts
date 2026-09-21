// Phorvex Console — the guided-journey model. Step states derive from REAL backend signals
// (never hardcoded): a step is "done"/"ready"/"locked" based on what data actually exists.
import { api, Lens } from "./api";
import { useSelectedTarget } from "./provider-store";
import { useOwnerTenant } from "./owner";
import { useApiRead, useAuditSnapshot, useScanSnapshot, useTargets } from "./query";
import { useQueryScope } from "./query";

export type StepId = "landing" | "connect" | "scan" | "discovered" | "attacklab" | "protect" | "prove" | "report" | "bench";
export type NodeState = "done" | "active" | "ready" | "locked";

export interface StepDef { id: StepId; n: number; label: string; tagline: string }

export const STEPS: StepDef[] = [
  { id: "connect", n: 1, label: "Connect", tagline: "pick the environment to defend" },
  { id: "scan", n: 2, label: "Scan", tagline: "derive the platform physics" },
  { id: "discovered", n: 3, label: "Discovered", tagline: "what the scan found" },
  { id: "attacklab", n: 4, label: "Attack Lab", tagline: "launch the attacker on a live workload, watch it" },
  { id: "protect", n: 5, label: "Protect / Run", tagline: "run Phorvex — where every method lives" },
  { id: "prove", n: 6, label: "Prove", tagline: "attack it, with & without Phorvex" },
  { id: "report", n: 7, label: "Report", tagline: "generate the evidence pack" },
  { id: "bench", n: 8, label: "Optimizer Bench", tagline: "tune the optimizer, benchmark vs R6-blind & attack-landed" },
];

export interface JourneySignals {
  connected: boolean;   // a runnable target exists
  hasCorpus: boolean;   // scan evidence for the selected scope (or unscoped retained corpus)
  hasAudit: boolean;    // live decisions have streamed (audit exists)
  hasBench: boolean;    // benchmark corpus present
  loading: boolean;
  diagnosticsError?: string;
}

// Health is deliberately public/minimal. Corpus availability requires the same verified
// identity and grant as the panels it unlocks; denied diagnostics remain unavailable.
export async function loadCorpusSignal(lens: Lens, context = ""): Promise<Pick<JourneySignals, "hasCorpus" | "diagnosticsError">> {
  // Diagnostics describes process-wide retained files, so it is useful only when no concrete
  // provider context is selected. It must not unlock a selected cluster based on another scope.
  if (context) return { hasCorpus: false };
  try {
    const diagnostics = await api.diagnostics(lens);
    return { hasCorpus: !!(diagnostics.hasP3Deep || diagnostics.hasPactuator) };
  } catch (error) {
    return { hasCorpus: false, diagnosticsError: String((error as Error).message || error) };
  }
}

export function useJourneySignals(lens: Lens): JourneySignals {
  const selected = useSelectedTarget();
  const { tenant } = useOwnerTenant(lens);
  const targetsQuery = useTargets(lens);
  const queryScope = useQueryScope(lens);
  const scanSnapshot = useScanSnapshot(lens, selected.context, "", false);
  const diagnostics = useApiRead({ lens, resource: "diagnostics", fetcher: (signal) => api.diagnostics(lens, signal), staleTime: 60_000, enabled: !selected.context });
  const benchmarkRead = useApiRead({ lens, resource: "benchmarks", fetcher: (signal) => api.benchmarks(lens, signal), staleTime: 60_000 });
  const auditSnapshot = useAuditSnapshot(lens, selected.context, lens === "owner" ? tenant : "", 1500, lens !== "owner" || !!tenant);
  const hasAudit = (auditSnapshot.data ?? []).length > 0;
  return {
    connected: (targetsQuery.data?.targets ?? []).some((x) => x.runnable && (!selected.context || x.context === selected.context)),
    hasCorpus: !!scanSnapshot.data || (!selected.context && !!(diagnostics.data?.hasP3Deep || diagnostics.data?.hasPactuator)) || (lens === "owner" && hasAudit),
    hasAudit,
    hasBench: (benchmarkRead.data?.groups ?? []).length > 0,
    loading: !queryScope.ready || targetsQuery.isPending || benchmarkRead.isPending || ((lens !== "owner" || !!tenant) && auditSnapshot.isPending) || (!selected.context && diagnostics.isPending),
    diagnosticsError: diagnostics.error ? String((diagnostics.error as Error).message || diagnostics.error) : undefined,
  };
}

export function stepState(id: StepId, sig: JourneySignals, active: StepId): NodeState {
  if (id === active) return "active";
  switch (id) {
    case "connect": return sig.connected ? "done" : "ready";
    case "scan": return sig.hasCorpus ? "done" : sig.connected ? "ready" : "locked";
    case "discovered": return sig.hasCorpus ? "ready" : "locked";
    case "attacklab": return sig.connected ? "ready" : "locked";
    case "protect": return sig.hasAudit ? "done" : sig.hasCorpus ? "ready" : "locked";
    case "prove": return sig.hasBench ? "done" : sig.connected ? "ready" : "locked";
    case "report": return sig.hasBench ? "ready" : "locked";
    case "bench": return "ready"; // self-contained in-process sim — always available
    default: return "ready";
  }
}

// URL helpers (deep-link a step).
export function readStep(): StepId {
  if (typeof window === "undefined") return "landing";
  const p = new URLSearchParams(window.location.search);
  return (p.get("step") as StepId) || "landing";
}
export function goStep(id: StepId) {
  const u = new URL(window.location.href);
  u.searchParams.set("step", id);
  window.history.pushState({}, "", u.toString());
  window.dispatchEvent(new Event("phorvex-nav"));
}

// Phorvex Console — the guided-journey model. Step states derive from REAL backend signals
// (never hardcoded): a step is "done"/"ready"/"locked" based on what data actually exists.
import * as React from "react";
import { api, Lens, API_BASE } from "./api";

export type StepId = "landing" | "connect" | "scan" | "discovered" | "attacklab" | "protect" | "prove" | "report";
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
];

export interface JourneySignals {
  connected: boolean;   // a runnable target exists
  hasCorpus: boolean;   // scan/metrics corpus on disk
  hasAudit: boolean;    // live decisions have streamed (audit exists)
  hasBench: boolean;    // benchmark corpus present
  loading: boolean;
}

export function useJourneySignals(lens: Lens): JourneySignals {
  const [s, setS] = React.useState<JourneySignals>({ connected: false, hasCorpus: false, hasAudit: false, hasBench: false, loading: true });
  React.useEffect(() => {
    let live = false;
    (async () => {
      const out: JourneySignals = { connected: false, hasCorpus: false, hasAudit: false, hasBench: false, loading: false };
      try { const h = await api.health(); out.hasCorpus = !!(h.hasP3Deep || h.hasPactuator); } catch {}
      try { const t = await api.targets(lens); out.connected = (t.targets || []).some((x) => x.runnable); } catch {}
      try { const b = await api.benchmarks(lens); out.hasBench = (b.groups || []).length > 0; } catch {}
      // a 1.5s probe of the SSE: did any decision stream?
      try {
        const es = new EventSource(`${API_BASE}/api/live?lens=${lens}`);
        es.onmessage = () => { live = true; };
        await new Promise((r) => setTimeout(r, 1500));
        es.close();
      } catch {}
      out.hasAudit = live;
      setS(out);
    })();
  }, [lens]);
  return s;
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

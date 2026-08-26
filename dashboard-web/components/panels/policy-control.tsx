"use client";
import * as React from "react";
import { api, Lens, PolicyView, PolicyEdit } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { Empty } from "@/components/ui/more";
import { Loader2, SlidersHorizontal, Save, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";

// PolicyControlPanel — LIVE editing of the PhorvexPolicy that governs each app.
//
// This is the console's write control plane: change the operator mode (active/observe), the
// dry-run flag, the per-tick move budget, and the enabled actuator set, and it patches the real
// PhorvexPolicy CR in the cluster. It is gated to the operator lens behind the Cognito auth on
// console.phorvex.ai, which is what makes a cluster write from a browser safe.
//
// Not read-only: what you change here changes what Phorvex is allowed to do to your cluster.
// Fallback actuator set, used only until the per-app applicable list loads (or if it can't be
// fetched). The real picker per policy uses the actuators APPLICABLE TO THAT APP'S STACK, fetched
// from /api/workload/attacks — so a serving-only actuator like route-rotate is never offered on a
// plain workload, which is what stops the brain from selecting an actuator it can't actuate. The
// brain still decides WHICH of the enabled actuators to run.
const GENERIC_ACTUATORS = ["rotate", "quarantine", "noop", "identity-rotate", "debugger", "custom-inject"];

type Draft = { mode: string; maxMovesPerTick: string; enabled: string[] };

function readDraft(p: PolicyView): Draft {
  const spec = p.spec || {};
  return {
    // "observe" is the decide-but-never-enact mode; the CRD has no separate dryRun field.
    mode: spec.mode || p.mode || "active",
    maxMovesPerTick: String(spec.budget?.maxMovesPerTick ?? ""),
    enabled: spec.actions?.enabled || [],
  };
}

export function PolicyControlPanel({ lens }: { lens: Lens }) {
  const [policies, setPolicies] = React.useState<PolicyView[] | null>(null);
  const [available, setAvailable] = React.useState(true);
  const [drafts, setDrafts] = React.useState<Record<string, Draft>>({});
  // per-namespace applicable actuators, fetched from the compat endpoint (stack-scoped).
  const [actuatorsByNs, setActuatorsByNs] = React.useState<Record<string, string[]>>({});
  const [saving, setSaving] = React.useState("");
  const [msg, setMsg] = React.useState("");
  const [err, setErr] = React.useState("");

  const load = React.useCallback(() => {
    setErr("");
    api.cluster(lens)
      .then((d) => {
        const ps = d.policies || [];
        setPolicies(ps);
        setAvailable(d.available);
        setDrafts(Object.fromEntries(ps.map((p) => [`${p.namespace}/${p.name}`, readDraft(p)])));
        // Fetch the stack-applicable actuator set for each governed namespace, so the picker
        // offers only what the brain can actually run there.
        Array.from(new Set(ps.map((p) => p.namespace))).forEach((ns) => {
          api.workloadAttacks(ns, lens)
            .then((w) => { if (w.policyActuators) setActuatorsByNs((m) => ({ ...m, [ns]: w.policyActuators! })); })
            .catch(() => {});
        });
      })
      .catch((e) => setErr(String(e.message || e)));
  }, [lens]);

  React.useEffect(() => { load(); }, [load]);

  const key = (p: PolicyView) => `${p.namespace}/${p.name}`;
  const set = (k: string, patch: Partial<Draft>) => setDrafts((d) => ({ ...d, [k]: { ...d[k], ...patch } }));

  const save = async (p: PolicyView) => {
    const k = key(p);
    const d = drafts[k];
    setSaving(k); setMsg(""); setErr("");
    const body: PolicyEdit = { namespace: p.namespace, name: p.name };
    if (d.mode) body.mode = d.mode as "active" | "observe";
    if (d.maxMovesPerTick.trim() !== "") {
      const n = parseInt(d.maxMovesPerTick, 10);
      if (!Number.isNaN(n)) body.maxMovesPerTick = n;
    }
    body.enabledActions = d.enabled;
    try {
      const r = await api.policyEdit(body, lens);
      setMsg(`Patched ${r.namespace}/${r.name} — live now.`);
      load();
    } catch (e: any) {
      setErr(String(e.message || e));
    } finally {
      setSaving("");
    }
  };

  if (err && !policies) return <div className="text-[12px] text-danger">error: {err}</div>;
  if (!policies) return <div className="flex items-center gap-2 text-[12px] text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> loading policies…</div>;
  if (!available || policies.length === 0) return <Empty msg="No PhorvexPolicy found on this cluster." />;

  return (
    <div className="space-y-4">
      <Card><CardContent className="flex items-center justify-between p-4">
        <div className="flex items-center gap-2 text-[13px]">
          <SlidersHorizontal className="h-4 w-4 text-primary" />
          <span className="font-medium">Live policy control</span>
          <Badge variant="real">writes the cluster</Badge>
        </div>
        <button onClick={load} className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground"><RefreshCw className="h-3 w-3" /> refresh</button>
      </CardContent></Card>

      {policies.map((p) => {
        const k = key(p);
        const d = drafts[k];
        if (!d) return null;
        return (
          <Card key={k}><CardContent className="p-4">
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <span className="font-medium text-[13px]">{p.namespace}/{p.name}</span>
              <Badge variant={d.mode === "active" ? "real" : "neutral"}>{d.mode}</Badge>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {/* mode */}
              <label className="text-[12px]">
                <div className="mb-1 text-muted-foreground">Mode</div>
                <select value={d.mode} onChange={(e) => set(k, { mode: e.target.value })}
                  className="w-full rounded-md border border-border bg-elevated/30 px-2 py-1.5 text-[13px]">
                  <option value="active">active — decides and actuates</option>
                  <option value="observe">observe — decides only (no enact)</option>
                </select>
              </label>
              {/* budget */}
              <label className="text-[12px]">
                <div className="mb-1 text-muted-foreground">Max moves per tick</div>
                <input type="number" min={0} max={100} value={d.maxMovesPerTick}
                  onChange={(e) => set(k, { maxMovesPerTick: e.target.value })}
                  className="w-full rounded-md border border-border bg-elevated/30 px-2 py-1.5 text-[13px]" />
              </label>
            </div>
            {/* enabled actuators — only those RUNNABLE on this app's stack, so the brain is never
                offered one it would select but couldn't actuate. Brain still picks which one runs. */}
            <div className="mt-3 text-[12px]">
              <div className="mb-1.5 flex items-center gap-2 text-muted-foreground">
                <span>Allowed actuators</span>
                <span className="text-[10px] text-muted-foreground/60">— the brain chooses which one to run from this set</span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {(actuatorsByNs[p.namespace] || GENERIC_ACTUATORS).map((a) => {
                  const on = d.enabled.includes(a);
                  return (
                    <button key={a} type="button"
                      onClick={() => set(k, { enabled: on ? d.enabled.filter((x) => x !== a) : [...d.enabled, a] })}
                      className={cn("rounded-md border px-2 py-1 font-mono text-[11px] transition-colors",
                        on ? "border-primary bg-primary/10 text-foreground" : "border-border bg-elevated/30 text-muted-foreground hover:bg-elevated/60")}>
                      {a}
                    </button>
                  );
                })}
              </div>
              {/* any enabled actuator no longer runnable here (e.g. set before this guard) shown so it can be removed */}
              {d.enabled.filter((a) => !(actuatorsByNs[p.namespace] || GENERIC_ACTUATORS).includes(a)).map((a) => (
                <button key={a} type="button" onClick={() => set(k, { enabled: d.enabled.filter((x) => x !== a) })}
                  className="mt-1.5 mr-1.5 rounded-md border border-warning/40 bg-warning/[0.08] px-2 py-1 font-mono text-[11px] text-warning">
                  {a} ✕ not runnable here
                </button>
              ))}
            </div>
            <div className="mt-3 flex justify-end">
              <Button size="sm" variant="primary" disabled={saving !== ""} onClick={() => save(p)}>
                {saving === k ? <><Loader2 className="h-3.5 w-3.5 animate-spin" /> patching…</> : <><Save className="h-3.5 w-3.5" /> Apply live</>}
              </Button>
            </div>
          </CardContent></Card>
        );
      })}

      {msg && <div className="rounded-md border border-success/25 bg-success/[0.06] p-3 text-[12.5px] text-foreground">{msg}</div>}
      {err && <div className="rounded-md border border-danger/25 bg-danger/[0.06] p-3 text-[12.5px] text-danger">{err}</div>}
    </div>
  );
}

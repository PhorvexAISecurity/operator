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
type Draft = { mode: string; dryRun: boolean; maxMovesPerTick: string; enabled: string };

function readDraft(p: PolicyView): Draft {
  const spec = p.spec || {};
  return {
    mode: spec.mode || p.mode || "active",
    dryRun: !!spec.dryRun,
    maxMovesPerTick: String(spec.budget?.maxMovesPerTick ?? ""),
    enabled: (spec.actions?.enabled || []).join(", "),
  };
}

export function PolicyControlPanel({ lens }: { lens: Lens }) {
  const [policies, setPolicies] = React.useState<PolicyView[] | null>(null);
  const [available, setAvailable] = React.useState(true);
  const [drafts, setDrafts] = React.useState<Record<string, Draft>>({});
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
    body.dryRun = d.dryRun;
    if (d.maxMovesPerTick.trim() !== "") {
      const n = parseInt(d.maxMovesPerTick, 10);
      if (!Number.isNaN(n)) body.maxMovesPerTick = n;
    }
    const acts = d.enabled.split(",").map((s) => s.trim()).filter(Boolean);
    body.enabledActions = acts;
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
              {d.dryRun && <Badge variant="pending">dry-run</Badge>}
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              {/* mode */}
              <label className="text-[12px]">
                <div className="mb-1 text-muted-foreground">Mode</div>
                <select value={d.mode} onChange={(e) => set(k, { mode: e.target.value })}
                  className="w-full rounded-md border border-border bg-elevated/30 px-2 py-1.5 text-[13px]">
                  <option value="active">active — decides and actuates</option>
                  <option value="observe">observe — decides only</option>
                </select>
              </label>
              {/* dryRun */}
              <label className="flex cursor-pointer items-center gap-2 text-[12px] sm:mt-6">
                <input type="checkbox" checked={d.dryRun} onChange={(e) => set(k, { dryRun: e.target.checked })} />
                <span className="text-muted-foreground">dry-run (never enact, even in active mode)</span>
              </label>
              {/* budget */}
              <label className="text-[12px]">
                <div className="mb-1 text-muted-foreground">Max moves per tick</div>
                <input type="number" min={0} max={100} value={d.maxMovesPerTick}
                  onChange={(e) => set(k, { maxMovesPerTick: e.target.value })}
                  className="w-full rounded-md border border-border bg-elevated/30 px-2 py-1.5 text-[13px]" />
              </label>
              {/* enabled actuators */}
              <label className="text-[12px]">
                <div className="mb-1 text-muted-foreground">Enabled actuators (comma-separated)</div>
                <input type="text" value={d.enabled} placeholder="rotate, quarantine, kv-reset"
                  onChange={(e) => set(k, { enabled: e.target.value })}
                  className="w-full rounded-md border border-border bg-elevated/30 px-2 py-1.5 font-mono text-[12px]" />
              </label>
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

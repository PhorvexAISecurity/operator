"use client";
// Optimizer Bench · live section — the economic knobs of every app's LIVE PhorvexPolicy.
//
// Unlike the simulation below it, this section writes the real policy (an audited merge patch
// through /api/optimizer/runtime/apply) and then shows, per knob, whether the brain's own newest
// decision trace at the new policy generation carries the value. VERIFIED is evidence the brain
// decided with the value; it is not evidence that the value is better.
import * as React from "react";
import {
  api, ApiError, Lens, EconomicsMode, OptimizerRuntime, ParameterLogEntry, RuntimeParamDef, RuntimePolicy, RuntimeParamStatus, OptionalValue,
} from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";
import { Activity, CheckCircle2, CircleSlash, Clock, Loader2, RefreshCw, RotateCcw, ShieldAlert, Upload, XCircle } from "lucide-react";

const MODE_LABEL: Record<EconomicsMode, string> = {
  legacy: "Legacy runtime λ", fixed: "Fixed β", independent: "Independent β_N/β_F",
};
const MODE_HINT: Record<EconomicsMode, string> = {
  legacy: "The brain learns λ at runtime (live today: 0). With λ = 0 the cost terms do not price the objective; only the CHi gate uses them.",
  fixed: "β replaces the runtime λ: gain = coverage·prov − β·ECost. Takes effect on the next tick.",
  independent: "β_N and β_F price the unweighted CNorm and CFlow separately in the objective.",
};
const DURATION_KEYS = new Set(["proactiveFloorSeconds", "antiOverRotationSeconds"]);

function fmtValue(key: string, v?: OptionalValue): string {
  if (!v || !v.present) return "—";
  if (DURATION_KEYS.has(key)) {
    let s = Math.round(v.value); let out = "";
    for (const [u, n] of [["d", 86400], ["h", 3600], ["m", 60]] as const) if (s >= n) { out += `${Math.floor(s / n)}${u}`; s %= n; }
    return out + (s || !out ? `${s}s` : "");
  }
  return Number.isInteger(v.value) ? String(v.value) : String(+v.value.toPrecision(6));
}

function Verdict({ st }: { st?: RuntimeParamStatus }) {
  if (!st) return null;
  const tip = [st.observed ? `brain trace: ${st.observed.present ? st.observed.value : "absent"}` : "", st.note || ""].filter(Boolean).join(" · ");
  switch (st.status) {
    case "VERIFIED": return <span title={tip || "the brain's decision at the current generation carries this value"}><CheckCircle2 className="h-3.5 w-3.5 text-success" /></span>;
    case "PENDING": return <span title={tip}><Clock className="h-3.5 w-3.5 text-warning" /></span>;
    case "MISMATCH": return <span title={tip}><XCircle className="h-3.5 w-3.5 text-danger" /></span>;
    case "NOT_APPLICABLE": return <span title="not used in this economics mode"><CircleSlash className="h-3.5 w-3.5 text-muted-foreground/50" /></span>;
    default: return <span title={tip || "no decision of this policy in the newest audit window"}><Activity className="h-3.5 w-3.5 text-muted-foreground/60" /></span>;
  }
}

function when(iso?: string) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export function RuntimeParameters({ lens }: { lens: Lens }) {
  const [data, setData] = React.useState<OptimizerRuntime | null>(null);
  const [log, setLog] = React.useState<ParameterLogEntry[]>([]);
  const [canEdit, setCanEdit] = React.useState(false);
  const [err, setErr] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [editing, setEditing] = React.useState<string | null>(null);
  const [selected, setSelected] = React.useState<Set<string>>(new Set());

  const load = React.useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    try {
      const [rt, lg] = await Promise.all([api.optimizerRuntime(lens, signal), api.parameterLog(lens, signal).catch(() => ({ entries: [] as ParameterLogEntry[] }))]);
      setData(rt); setLog(lg.entries || []); setErr("");
    } catch (e: unknown) {
      if (!(e instanceof DOMException && e.name === "AbortError")) setErr(String((e as Error)?.message || e));
    } finally { setLoading(false); }
  }, [lens]);

  React.useEffect(() => {
    const ac = new AbortController();
    void load(ac.signal);
    api.session(lens, ac.signal).then((s) => setCanEdit(!!s.canEdit)).catch(() => setCanEdit(false));
    const t = window.setInterval(() => void load(), 10_000);
    return () => { ac.abort(); window.clearInterval(t); };
  }, [lens, load]);

  const catalogue = data?.catalogue || [];
  const policies = data?.policies || [];
  const keyOf = (p: RuntimePolicy) => `${p.namespace}/${p.name}`;
  const editingPolicy = policies.find((p) => keyOf(p) === editing) || null;

  return (
    <Card>
      <CardContent className="space-y-4 p-4">
        <div className="flex flex-wrap items-start gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 text-[13px] font-semibold text-foreground"><Upload className="h-4 w-4 text-primary" /> Live runtime parameters · every app</div>
            <p className="mt-1 max-w-4xl text-[12px] leading-relaxed text-muted-foreground">
              These knobs write the <span className="text-foreground">live PhorvexPolicy</span> of each app (an audited patch; mode and actuators are not touched — the brain still chooses the actuator).
              Each value is then checked against the brain&apos;s own newest decision trace: <CheckCircle2 className="inline h-3 w-3 text-success" /> the decision at the new policy generation carries it,
              {" "}<Clock className="inline h-3 w-3 text-warning" /> waiting for that decision, <XCircle className="inline h-3 w-3 text-danger" /> the brain used a different value.
            </p>
          </div>
          <Button size="sm" variant="outline" onClick={() => void load()} disabled={loading} className="gap-1.5">
            {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />} Refresh
          </Button>
        </div>

        {err && <div className="rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger">{err}</div>}
        {data?.decisionAuditError && <div className="rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-[12px] text-warning">Decision audit unavailable — values cannot be verified: {data.decisionAuditError}</div>}

        {policies.length > 0 && (
          <div className="overflow-x-auto rounded-md border border-border">
            <table className="w-full text-[11px]">
              <thead className="bg-muted/30 text-[10px] uppercase tracking-wide text-muted-foreground">
                <tr>
                  <th className="px-2 py-2 text-left"><input type="checkbox" aria-label="Select all apps" checked={selected.size === policies.length && policies.length > 0}
                    onChange={(e) => setSelected(e.target.checked ? new Set(policies.map(keyOf)) : new Set())} /></th>
                  <th className="px-2 py-2 text-left">App policy</th>
                  <th className="px-2 py-2 text-left">Economics</th>
                  {catalogue.map((c) => <th key={c.key} className="px-2 py-2 text-left" title={`${c.specPath}\n${c.effect}`}>{c.symbol}<div className="normal-case tracking-normal text-muted-foreground/70">{c.label}</div></th>)}
                  <th className="px-2 py-2 text-left">Brain</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {policies.map((p) => {
                  const byKey = Object.fromEntries(p.parameters.map((s) => [s.key, s]));
                  return (
                    <tr key={keyOf(p)} className={cn("border-t border-border", editing === keyOf(p) && "bg-primary/5")}>
                      <td className="px-2 py-2"><input type="checkbox" aria-label={`Select ${keyOf(p)}`} checked={selected.has(keyOf(p))}
                        onChange={(e) => setSelected((s) => { const n = new Set(s); if (e.target.checked) n.add(keyOf(p)); else n.delete(keyOf(p)); return n; })} /></td>
                      <td className="px-2 py-2 font-mono text-foreground">{keyOf(p)}<div className="text-[10px] text-muted-foreground">generation {p.generation}{p.error ? ` · ${p.error}` : ""}</div></td>
                      <td className="px-2 py-2"><Badge variant={p.economicsMode === "legacy" ? "neutral" : "accent"}>{MODE_LABEL[p.economicsMode] || p.economicsMode}</Badge>
                        {p.economicsModeMatches === false && <div className="mt-0.5 text-[10px] text-danger">brain mode: {p.brain?.economicsMode}</div>}</td>
                      {catalogue.map((c) => (
                        <td key={c.key} className="px-2 py-2"><span className="inline-flex items-center gap-1 font-mono tabular text-foreground">{fmtValue(c.key, p.configured.values[c.key])}<Verdict st={byKey[c.key]} /></span></td>
                      ))}
                      <td className="px-2 py-2 text-[10px] text-muted-foreground">
                        {p.brain ? <>
                          <div>{when(p.brain.decisionTime)}</div>
                          <div>gen {p.brain.generation} · coeff {+p.brain.effectiveCostCoefficient.toPrecision(4)} · λ {+p.brain.lambdaRuntime.toPrecision(4)}</div>
                        </> : "no recent decision"}
                      </td>
                      <td className="px-2 py-2"><Button size="sm" variant="ghost" disabled={!canEdit} onClick={() => setEditing(editing === keyOf(p) ? null : keyOf(p))}>{editing === keyOf(p) ? "Close" : "Edit"}</Button></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {!canEdit && policies.length > 0 && <div className="text-[11px] text-muted-foreground">Your session is read-only here; editing needs the operator role for the app&apos;s tenant.</div>}

        {editingPolicy && (
          <Editor key={keyOf(editingPolicy) + editingPolicy.generation} lens={lens} policy={editingPolicy} catalogue={catalogue}
            targets={selected.size > 0 ? policies.filter((p) => selected.has(keyOf(p))) : [editingPolicy]}
            onApplied={() => void load()} />
        )}

        <ChangeLog entries={log} canEdit={canEdit} lens={lens} onRestored={() => void load()} catalogue={catalogue} />
      </CardContent>
    </Card>
  );
}

function Editor({ lens, policy, catalogue, targets, onApplied }: {
  lens: Lens; policy: RuntimePolicy; catalogue: RuntimeParamDef[]; targets: RuntimePolicy[]; onApplied: () => void;
}) {
  const [mode, setMode] = React.useState<EconomicsMode>(policy.economicsMode);
  const [dirty, setDirty] = React.useState<Record<string, string>>({});
  const [note, setNote] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [result, setResult] = React.useState<{ app: string; ok: boolean; text: string }[]>([]);
  const [needConfirm, setNeedConfirm] = React.useState<string[] | null>(null);

  const visible = (c: RuntimeParamDef) => (c.key === "beta" ? mode === "fixed" : c.key === "normPreference" || c.key === "flowPreference" ? mode === "independent" : true);
  const shown = (c: RuntimeParamDef) => {
    if (dirty[c.key] !== undefined) return dirty[c.key];
    const v = policy.configured.values[c.key];
    return v?.present ? String(v.value) : "";
  };

  function changes(): { set: Record<string, number>; problems: string[] } {
    const set: Record<string, number> = {}; const problems: string[] = [];
    for (const c of catalogue) {
      if (!visible(c)) continue;
      const raw = dirty[c.key];
      const needed = (c.key === "beta" && mode === "fixed" && mode !== policy.economicsMode) ||
        ((c.key === "normPreference" || c.key === "flowPreference") && mode === "independent" && mode !== policy.economicsMode);
      const text = raw !== undefined ? raw : needed ? shown(c) : undefined;
      if (text === undefined) continue;
      const v = Number(text);
      if (text.trim() === "" || !Number.isFinite(v)) { problems.push(`${c.label}: enter a number`); continue; }
      if (v < c.min || v > c.max || (c.minExclusive && v === c.min)) { problems.push(`${c.label}: outside ${c.minExclusive ? "(" : "["}${c.min}, ${c.max}]`); continue; }
      if (c.integer && !Number.isInteger(v)) { problems.push(`${c.label}: whole number`); continue; }
      set[c.key] = v;
    }
    return { set, problems };
  }

  async function apply(confirmProtected = false) {
    const { set, problems } = changes();
    if (problems.length) { setResult([{ app: "", ok: false, text: problems.join(" · ") }]); return; }
    const modeChanged = mode !== policy.economicsMode;
    if (!modeChanged && Object.keys(set).length === 0) { setResult([{ app: "", ok: false, text: "Nothing changed." }]); return; }
    setBusy(true); setNeedConfirm(null);
    const out: { app: string; ok: boolean; text: string }[] = [];
    for (const t of targets) {
      const app = `${t.namespace}/${t.name}`;
      try {
        const r = await api.optimizerApply({ namespace: t.namespace, name: t.name, expectedGeneration: t.generation, set,
          economicsMode: mode !== t.economicsMode ? mode : undefined, confirmProtected, note: note.trim() || undefined }, lens);
        out.push({ app, ok: true, text: r.unchanged ? "already at these values" : `applied · generation ${r.previousGeneration} → ${r.generation} · change ${r.changeId}` });
      } catch (e: unknown) {
        const status = e instanceof ApiError ? e.status : 0;
        if (status === 428) {
          setNeedConfirm([app]);
        }
        out.push({ app, ok: false, text: String((e as Error)?.message || e) });
      }
    }
    setResult(out); setBusy(false); setDirty({}); onApplied();
  }

  return (
    <div className="space-y-3 rounded-md border border-primary/30 bg-primary/5 p-3">
      <div className="text-[12px] font-medium text-foreground">
        Edit · {targets.length === 1 ? `${targets[0].namespace}/${targets[0].name}` : `${targets.length} selected apps (only the fields you change are sent)`}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] uppercase tracking-wide text-muted-foreground">Economics mode</span>
        {(["legacy", "fixed", "independent"] as EconomicsMode[]).map((m) => (
          <button key={m} onClick={() => setMode(m)} className={cn("rounded-md border px-2.5 py-1 text-[11px]",
            mode === m ? "border-primary/50 bg-primary/10 text-foreground" : "border-border text-muted-foreground hover:bg-elevated")}>{MODE_LABEL[m]}</button>
        ))}
      </div>
      <div className="text-[11px] text-muted-foreground">{MODE_HINT[mode]}</div>
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {catalogue.filter(visible).map((c) => (
          <label key={c.key} className="space-y-1 rounded-md border border-border bg-background/40 p-2">
            <div className="flex items-center gap-1.5 text-[11px] text-foreground">
              <span className="font-mono">{c.symbol}</span> {c.label}{c.unit ? <span className="text-muted-foreground"> · {c.unit}</span> : null}
              {c.protected && <span title={`protected: loosening (${c.safeDirection === "lower" ? "raising" : "lowering"} it) needs SRE/security approval`}><ShieldAlert className="h-3 w-3 text-warning" /></span>}
            </div>
            <input value={shown(c)} inputMode="decimal" onChange={(e) => setDirty((d) => ({ ...d, [c.key]: e.target.value }))}
              className={cn("w-full rounded-md border bg-background/60 px-2 py-1 font-mono text-[12px] tabular text-foreground focus:border-primary focus:outline-none",
                dirty[c.key] !== undefined ? "border-primary/60" : "border-border")} />
            <div className="text-[10px] leading-snug text-muted-foreground/80">{c.effect}</div>
          </label>
        ))}
      </div>
      <input value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} placeholder="Note for the change log (e.g. benchmark arm β=1.5)"
        className="w-full rounded-md border border-border bg-background/60 px-2 py-1 text-[12px] text-foreground focus:border-primary focus:outline-none" />
      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" onClick={() => void apply(false)} disabled={busy} className="gap-1.5">
          {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Upload className="h-3.5 w-3.5" />} Apply to {targets.length === 1 ? "this app" : `${targets.length} apps`}
        </Button>
        {needConfirm && (
          <Button size="sm" variant="outline" onClick={() => void apply(true)} disabled={busy} className="gap-1.5 text-warning">
            <ShieldAlert className="h-3.5 w-3.5" /> Loosening is approved — apply anyway
          </Button>
        )}
        <span className="text-[10px] text-muted-foreground">Writes the live policy. The brain picks the values up on its next tick.</span>
      </div>
      {result.length > 0 && (
        <ul className="space-y-1 text-[11px]">
          {result.map((r, i) => <li key={i} className={r.ok ? "text-success" : "text-danger"}>{r.app ? <span className="font-mono">{r.app}: </span> : null}{r.text}</li>)}
        </ul>
      )}
    </div>
  );
}

function ChangeLog({ entries, canEdit, lens, onRestored, catalogue }: {
  entries: ParameterLogEntry[]; canEdit: boolean; lens: Lens; onRestored: () => void; catalogue: RuntimeParamDef[];
}) {
  const [busy, setBusy] = React.useState("");
  const [msg, setMsg] = React.useState("");
  const label = (key: string) => catalogue.find((c) => c.key === key)?.symbol || key;
  async function restore(e: ParameterLogEntry) {
    if (!e.changeId) return;
    setBusy(e.changeId); setMsg("");
    try {
      const r = await api.optimizerApply({ namespace: e.namespace, name: e.policy, restoreChangeId: e.changeId, confirmProtected: true, note: `restore ${e.changeId}` }, lens);
      setMsg(`restored ${e.namespace}/${e.policy} · generation ${r.previousGeneration} → ${r.generation}`);
      onRestored();
    } catch (err: unknown) { setMsg(String((err as Error)?.message || err)); }
    finally { setBusy(""); }
  }
  return (
    <div className="space-y-2">
      <div className="text-[12px] font-medium text-foreground">Change log <span className="text-[10px] font-normal text-muted-foreground">· every console write of these parameters, newest first</span></div>
      {msg && <div className="text-[11px] text-muted-foreground">{msg}</div>}
      {entries.length === 0 ? <div className="text-[11px] text-muted-foreground">No runtime parameter changes yet.</div> : (
        <div className="max-h-80 overflow-y-auto rounded-md border border-border">
          <table className="w-full text-[11px]">
            <thead className="sticky top-0 bg-muted/60 text-[10px] uppercase tracking-wide text-muted-foreground">
              <tr><th className="px-2 py-1.5 text-left">Time</th><th className="px-2 py-1.5 text-left">App</th><th className="px-2 py-1.5 text-left">Change</th>
                <th className="px-2 py-1.5 text-left">Generation</th><th className="px-2 py-1.5 text-left">Outcome</th><th className="px-2 py-1.5 text-left">By</th><th /></tr>
            </thead>
            <tbody>
              {entries.map((e, i) => (
                <tr key={(e.changeId || "") + i} className="border-t border-border align-top">
                  <td className="whitespace-nowrap px-2 py-1.5 text-muted-foreground">{when(e.time)}</td>
                  <td className="px-2 py-1.5 font-mono text-foreground">{e.namespace}/{e.policy}</td>
                  <td className="px-2 py-1.5">
                    {e.economicsModeBefore && e.economicsModeAfter && e.economicsModeBefore !== e.economicsModeAfter &&
                      <div>mode: {MODE_LABEL[e.economicsModeBefore]} → {MODE_LABEL[e.economicsModeAfter]}</div>}
                    {(e.parameters || []).map((c) => <div key={c.key}><span className="font-mono">{label(c.key)}</span>: {fmtValue(c.key, c.before)} → {fmtValue(c.key, c.after)}</div>)}
                    {e.restoreOf && <div className="text-muted-foreground">restore of {e.restoreOf}</div>}
                    {e.note && <div className="text-muted-foreground">“{e.note}”</div>}
                  </td>
                  <td className="whitespace-nowrap px-2 py-1.5 font-mono">{e.previousGeneration ?? "?"} → {e.generation ?? "?"}</td>
                  <td className="px-2 py-1.5"><Badge variant={e.verdict === "applied" ? "real" : e.verdict === "effect-unknown" ? "pending" : "danger"}>{e.verdict}</Badge>
                    {e.message && e.verdict !== "applied" && <div className="mt-0.5 max-w-xs text-[10px] text-danger">{e.message}</div>}</td>
                  <td className="max-w-[12rem] truncate px-2 py-1.5 text-muted-foreground" title={e.actor}>{e.actor.split("#").pop()}</td>
                  <td className="px-2 py-1.5">{e.verdict === "applied" && e.changeId && canEdit &&
                    <Button size="sm" variant="ghost" disabled={!!busy} onClick={() => void restore(e)} className="gap-1" title="Re-apply the values this change replaced">
                      {busy === e.changeId ? <Loader2 className="h-3 w-3 animate-spin" /> : <RotateCcw className="h-3 w-3" />} Restore</Button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

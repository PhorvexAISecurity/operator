'use client';

import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api';

// Brain parameters: which runtime optimizer parameters each app's brain is deciding with. Values
// are set in the Console's Optimizer Bench (an audited live-policy write); the Console checks each
// one against the brain's own newest decision trace, and this view shows that verdict, the
// Console's change log and a timeline of observations. Read-only.

type IconType = (props: { name: string; size?: number }) => React.ReactElement;
interface Opt { present: boolean; value: number }
interface Def { key: string; label: string; symbol: string; specPath: string; unit?: string; effect: string; protected?: boolean }
interface Status { key: string; configured: Opt; observed?: Opt; status: string; note?: string }
interface Brain { decisionTime: string; generation: number; economicsMode: string; effectiveCostCoefficient: number; lambdaRuntime: number; action: string }
interface Policy { namespace: string; name: string; generation: number; economicsMode: string; configured: { values: Record<string, Opt> }; brain?: Brain; parameters: Status[]; economicsModeMatches?: boolean; error?: string }
interface Change { key: string; before: Opt; after: Opt }
interface LogEntry { time: string; actor: string; namespace: string; policy: string; verdict: string; message?: string; changeId?: string; previousGeneration?: number; generation?: number; economicsModeBefore?: string; economicsModeAfter?: string; parameters?: Change[]; note?: string; restoreOf?: string }
interface Observation { observedAt: string; policyKey: string; generation: number; economicsMode: string; brainGeneration?: number; brainDecisionTime?: string; effectiveCostCoefficient?: number; lambdaRuntime?: number; parameters: { key: string; configured: number | ''; brain: number | ''; status: string }[] }
interface Snapshot {
  fetchedAt: string; errors: string[];
  runtime?: { catalogue: Def[]; policies: Policy[]; decisionAuditError?: string; decisionRecordsScanned?: number } | null;
  log?: { entries: LogEntry[] } | null;
  observations?: Observation[];
}

const MODE: Record<string, string> = { legacy: 'Legacy runtime λ', fixed: 'Fixed β', independent: 'Independent β_N/β_F' };
const DURATIONS = new Set(['proactiveFloorSeconds', 'antiOverRotationSeconds']);
const VERDICT: Record<string, [string, string]> = {
  VERIFIED: ['good', 'verified'], PENDING: ['warning', 'pending'], MISMATCH: ['danger', 'mismatch'],
  NOT_APPLICABLE: ['muted', 'n/a'], NO_RECENT_DECISION: ['neutral', 'no decision'],
};

function show(key: string, v?: Opt | number | ''): string {
  const n = typeof v === 'object' ? (v?.present ? v.value : null) : v === '' || v === undefined ? null : v;
  if (n === null) return '—';
  if (DURATIONS.has(key)) {
    let s = Math.round(n); let out = '';
    for (const [u, size] of [['d', 86400], ['h', 3600], ['m', 60]] as const) if (s >= size) { out += `${Math.floor(s / size)}${u}`; s %= size; }
    return out + (s || !out ? `${s}s` : '');
  }
  return Number.isInteger(n) ? String(n) : String(+n.toPrecision(6));
}
function when(iso?: string) {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'medium' });
}

export function BrainParameters({ Icon, onError }: { Icon: IconType; onError: (e: unknown) => void }) {
  const [data, setData] = useState<Snapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const load = useCallback(async (fresh: boolean) => {
    setBusy(true);
    try { setData(await api<Snapshot>(`/parameters${fresh ? '?fresh=1' : ''}`, {}, 120_000)); }
    catch (e) { onError(e); } finally { setBusy(false); }
  }, [onError]);
  useEffect(() => {
    void load(false);
    const t = window.setInterval(() => void load(false), 30_000);
    return () => window.clearInterval(t);
  }, [load]);

  const catalogue = data?.runtime?.catalogue || [];
  const policies = data?.runtime?.policies || [];
  const symbol = (key: string) => catalogue.find((c) => c.key === key)?.symbol || key;
  const unavailable = (data?.errors || []).length > 0 && !data?.runtime;

  return <>
    <div className="page-heading"><div><span className="eyebrow">BRAIN PARAMETERS</span><h1>Runtime parameters the brain decides with</h1>
      <p>Set per app in the Console&apos;s Optimizer Bench. Each value is checked against the brain&apos;s own newest decision trace at the policy generation in force; every benchmark run records the same view at its start and end.</p></div>
      <button className="button secondary" disabled={busy} onClick={() => void load(true)}>{busy ? <span className="spinner"/> : <Icon name="refresh" size={16}/>}Refresh from Console</button></div>

    {unavailable && <div className="notice warning"><strong>Console parameters unavailable.</strong><ul>{data!.errors.map((e, i) => <li key={i}>{e}</li>)}</ul>
      <span className="field-hint">The deployed Console must include the runtime-parameter endpoints (Optimizer Bench live section).</span></div>}
    {data?.runtime?.decisionAuditError && <div className="notice warning">Decision audit unavailable — values cannot be verified: {data.runtime.decisionAuditError}</div>}

    {policies.length > 0 && <section className="panel ml-table-panel">
      <h2>Current values · {policies.length} app policies <small className="field-hint">read {when(data?.fetchedAt)} · {data?.runtime?.decisionRecordsScanned ?? 0} decision records scanned</small></h2>
      <table className="ml-table compact">
        <thead><tr><th>App policy</th><th>Economics</th>{catalogue.map((c) => <th key={c.key} title={`${c.specPath}\n${c.effect}`}>{c.symbol}<small>{c.label}</small></th>)}<th>Brain decision</th></tr></thead>
        <tbody>{policies.map((p) => {
          const st = Object.fromEntries(p.parameters.map((s) => [s.key, s]));
          return <tr key={p.namespace + '/' + p.name}>
            <td><code>{p.namespace}/{p.name}</code><small>generation {p.generation}{p.error ? ` · ${p.error}` : ''}</small></td>
            <td>{MODE[p.economicsMode] || p.economicsMode}{p.economicsModeMatches === false && <small>brain: {MODE[p.brain?.economicsMode || ''] || p.brain?.economicsMode}</small>}</td>
            {catalogue.map((c) => {
              const s = st[c.key]; const [cls, label] = VERDICT[s?.status || ''] || ['neutral', s?.status || '—'];
              return <td key={c.key} title={[s?.observed ? `brain trace: ${show(c.key, s.observed)}` : '', s?.note || ''].filter(Boolean).join(' · ')}>
                <code>{show(c.key, p.configured.values[c.key])}</code><small><span className={`badge ${cls}`}>{label}</span></small></td>;
            })}
            <td>{p.brain ? <>{when(p.brain.decisionTime)}<small>gen {p.brain.generation} · {p.brain.action} · coeff {+p.brain.effectiveCostCoefficient.toPrecision(4)} · λ {+p.brain.lambdaRuntime.toPrecision(4)}</small></> : <small>no decision in the newest audit window</small>}</td>
          </tr>;
        })}</tbody>
      </table>
      <p className="field-hint ml-table-note">verified = the brain&apos;s decision at the current policy generation carries the configured value · pending = waiting for that decision · mismatch = the brain used a different value · n/a = not used in this economics mode. Verification shows the brain priced with the value, not that the value is better.</p>
    </section>}

    <section className="panel ml-table-panel" style={{ marginTop: 20 }}>
      <h2>Console change log <small className="field-hint">every Optimizer Bench write of these parameters, newest first</small></h2>
      {(data?.log?.entries || []).length === 0 ? <p className="field-hint ml-table-note">No runtime parameter changes recorded.</p> :
        <table className="ml-table compact"><thead><tr><th>Time</th><th>App</th><th>Change</th><th>Generation</th><th>Outcome</th><th>By</th></tr></thead>
          <tbody>{data!.log!.entries.map((e, i) => <tr key={(e.changeId || '') + i}>
            <td>{when(e.time)}<small>{e.changeId}</small></td><td><code>{e.namespace}/{e.policy}</code></td>
            <td>{e.economicsModeBefore && e.economicsModeAfter && e.economicsModeBefore !== e.economicsModeAfter && <div>mode: {MODE[e.economicsModeBefore]} → {MODE[e.economicsModeAfter]}</div>}
              {(e.parameters || []).map((c) => <div key={c.key}><code>{symbol(c.key)}</code> {show(c.key, c.before)} → {show(c.key, c.after)}</div>)}
              {e.restoreOf && <small>restore of {e.restoreOf}</small>}{e.note && <small>“{e.note}”</small>}</td>
            <td><code>{e.previousGeneration ?? '?'} → {e.generation ?? '?'}</code></td>
            <td><span className={`badge ${e.verdict === 'applied' ? 'good' : e.verdict === 'effect-unknown' ? 'warning' : 'danger'}`}>{e.verdict}</span>{e.message && e.verdict !== 'applied' && <small>{e.message}</small>}</td>
            <td><small>{e.actor.split('#').pop()}</small></td></tr>)}</tbody></table>}
    </section>

    <section className="panel ml-table-panel" style={{ marginTop: 20 }}>
      <h2>Observation timeline <small className="field-hint">a row each time an app&apos;s configured values, generation or verification changed</small></h2>
      {(data?.observations || []).length === 0 ? <p className="field-hint ml-table-note">No observations yet.</p> :
        <table className="ml-table compact"><thead><tr><th>Observed</th><th>App</th><th>Policy → brain generation</th><th>Economics</th><th>Values (configured · verdict)</th></tr></thead>
          <tbody>{data!.observations!.slice(0, 200).map((o, i) => {
            const counts: Record<string, number> = {};
            for (const p of o.parameters) counts[p.status] = (counts[p.status] || 0) + 1;
            return <tr key={o.policyKey + o.observedAt + i}>
              <td>{when(o.observedAt)}</td><td><code>{o.policyKey}</code></td>
              <td><code>{o.generation} → {o.brainGeneration ?? '—'}</code><small>{o.brainDecisionTime ? `decision ${when(o.brainDecisionTime)}` : 'no decision'}</small></td>
              <td>{MODE[o.economicsMode] || o.economicsMode}<small>coeff {o.effectiveCostCoefficient ?? '—'} · λ {o.lambdaRuntime ?? '—'}</small></td>
              <td><small>{o.parameters.filter((p) => p.status !== 'NOT_APPLICABLE').map((p) => `${symbol(p.key)}=${show(p.key, p.configured)}`).join(' · ')}</small>
                <small>{Object.entries(counts).map(([k, n]) => `${(VERDICT[k] || ['', k])[1]} ${n}`).join(' · ')}</small></td></tr>;
          })}</tbody></table>}
    </section>
  </>;
}

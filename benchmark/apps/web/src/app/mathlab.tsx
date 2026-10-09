'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api } from '../lib/api';
import { DotWhisker, GroupedBars, StackedShares, fmt, type Point } from './charts';

// Math/OR Benchmark Lab views: parameter catalogue -> experiment design -> preflight ->
// replay run -> comparison -> evidence export. Replay only: nothing here can change a
// production setting, and every chart is labeled as decision-mechanism evidence.

export type MathView = 'math-params' | 'math-new' | 'math-runs' | 'math-run';
type IconType = (props: { name: string; size?: number }) => React.ReactElement;

interface RegistryItem {
  param_id: string; name: string; symbol?: string; group?: string; role?: string; impact?: string; class: string; scope?: string;
  config_key?: string | null; units?: string; default_value?: string; admission_domain?: string; validation?: string;
  apply_mechanism?: string; effect_latency?: string; protected: boolean; safe_direction?: string | null; active_status: string;
  control: string; experiment_modes: string[]; replay_override?: { domain?: { min?: number; max?: number }; unset_allowed?: boolean; unset_semantics?: string } | null;
  experimental_range_status?: string; couplings?: string[]; metric_ids?: { primary?: string | null; secondary?: string[]; guardrails?: string[] };
  source_locations?: string[]; source_verified_at_sha?: string; verification?: string; recon_status?: string; changed_since_audit?: string;
  delta_summary?: string; warnings?: string[]; notes?: string; origin?: string;
  configured_value?: unknown; configured_present?: boolean; effective_value?: unknown; effective_source?: string | null; effective_status?: string;
}
interface Registry { schema_version: string; registry_version: string; source?: Record<string, string>; counts?: Record<string, unknown>; items: RegistryItem[];
  inspection: null | { snapshot_digest: string; captured_at: string; git_sha: string; policy: string; economics_mode: string; learned?: Record<string, unknown>; process_config_hash?: string } }
interface PolicyStatus { policy: string; snapshots_held: number; last_sync: null | { finished_at?: string; downloaded?: number; listed?: number; corpus?: Record<string, unknown> }; inspection: { available: boolean } }
interface Policies { binary: null | { git_sha?: string; image_digest?: string; image?: string; binary_sha256?: string }; policies: PolicyStatus[] }
interface Experiment { id: string; status: string; createdAt: string; finishedAt?: string; title?: string; parameter_id?: string; policy?: string; arms?: number; progress?: Progress | null }
interface Progress { state?: string; stage?: string; message?: string; completed?: number | null; total?: number | null }
interface Check { id: string; status: string; message: string; evidence?: unknown }
interface Preflight { status: string; checks: Check[]; errors: { error_code: string; field: string; reason: string }[]; cohort?: { snapshots: number } }
interface MetricRow { arm_id: string; metric_id: string; metric_name: string; metric_kind: string; metric_proposed: boolean; dimension: string | null; unit: string;
  numerator: number | null; denominator: number | null; value: number | null; n: number | null; paired_n: number | null; ci_low: number | null; ci_high: number | null;
  ci_method: string | null; comparison: string; comparison_status: string; data_status: string; reason: string | null; effective_value_label: string; population: string | null; definition: string }
interface Plots { dose_response?: Record<string, { arm_id: string; x_label: string; is_control: boolean; value: number | null; ci_low: number | null; ci_high: number | null; n: number | null }[]>;
  paired?: Record<string, { arm_id: string; x_label: string; value: number | null; ci_low: number | null; ci_high: number | null; n: number | null }[]>;
  funnel?: Record<string, { stage: string; count: number }[]>; g9?: Record<string, Record<string, number>>; noop?: Record<string, Record<string, number>> }
interface Detail extends Experiment { request: Record<string, any>; preflight?: Preflight; message?: string; result?: any; manifest?: any; artifacts: string[] }

const CLASS_LABEL: Record<string, string> = {
  CONFIGURABLE_NOW: 'Configurable now', CONFIGURABLE_WITH_REDEPLOY: 'Needs rollout/recreate', INTERNAL_CONSTANT: 'Internal constant',
  LEARNED_STATE: 'Learned state', DERIVED_RUNTIME: 'Derived at runtime', OBSERVED_INPUT: 'Observed input', REPORT_ONLY: 'Report only',
  UNSUPPORTED_OR_UNKNOWN: 'Unwired / unknown',
};
const PRESETS: Record<string, { values: (number | 'UNSET')[]; hint: string }> = {
  'P-OBJ-003': { values: ['UNSET', 0, 0.25, 0.5, 1, 2], hint: 'UNSET keeps the policy\'s own economics (legacy runtime λ live today). A number switches to fixed-β mode.' },
  'P-FEA-006': { values: [0.8, 1.0, 1.4, 1.8, 2.5], hint: 'Hypothetical CHi ceilings for replay only. A higher ceiling admitting more candidates is not evidence that it is safe.' },
};
const KIND_LABEL: Record<string, string> = { PROCESS: 'Decision mechanism', ESTIMATED_MODEL: 'Model estimate', OBSERVATIONAL: 'Production record',
  VERIFIED_SECURITY_OUTCOME: 'Verified security outcome', OBSERVED_DISRUPTION: 'Observed disruption' };
const RUNNING = new Set(['QUEUED', 'RUNNING']);

function show(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'number') return fmt(value, 6);
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}
function when(value?: string) { return value ? new Date(value).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' }) : '—'; }
function StatusBadge({ status }: { status: string }) {
  const tone = ['COMPLETE', 'PASS', 'MATCHED_REPLAY', 'OBSERVED'].includes(status) ? 'good' : ['RUNNING', 'QUEUED'].includes(status) ? 'active'
    : ['PARTIAL', 'WARN', 'OBSERVATIONAL', 'INTERRUPTED', 'SOURCE_CONSTANT'].includes(status) ? 'warning' : ['INFO', 'UNAVAILABLE'].includes(status) ? 'neutral' : 'danger';
  return <span className={`badge ${tone}`}>{status.replaceAll('_', ' ').toLowerCase()}</span>;
}

export function MathLab({ view, setView, Icon, onError }: { view: MathView; setView: (v: MathView) => void; Icon: IconType; onError: (e: unknown) => void }) {
  const [policies, setPolicies] = useState<Policies | null>(null);
  const [policy, setPolicy] = useState('');
  const [registry, setRegistry] = useState<Registry | null>(null);
  const [syncJob, setSyncJob] = useState<{ id: string; status: string; progress?: Progress & { result?: any } } | null>(null);
  const [experiments, setExperiments] = useState<Experiment[]>([]);
  const [selected, setSelected] = useState<string>('');
  const [designParam, setDesignParam] = useState<string>('P-FEA-006');

  const loadPolicies = useCallback(async () => {
    const p = await api<Policies>('/math/policies');
    setPolicies(p);
    setPolicy(current => current || p.policies[0]?.policy || '');
  }, []);
  const loadRegistry = useCallback(async (pol: string) => { setRegistry(await api<Registry>('/math/registry' + (pol ? `?policy=${encodeURIComponent(pol)}` : ''))); }, []);
  const loadExperiments = useCallback(async () => { setExperiments(await api<Experiment[]>('/math/experiments')); }, []);

  useEffect(() => { void loadPolicies().catch(onError); void loadExperiments().catch(onError); }, [loadPolicies, loadExperiments, onError]);
  useEffect(() => { if (policy) void loadRegistry(policy).catch(onError); }, [policy, loadRegistry, onError]);
  useEffect(() => {
    if (!syncJob || !RUNNING.has(syncJob.status)) return;
    const timer = setInterval(() => { void api<any>(`/math/jobs/${syncJob.id}`).then(job => { setSyncJob(job); if (!RUNNING.has(job.status)) { void loadPolicies(); void loadRegistry(policy); } }).catch(onError); }, 2000);
    return () => clearInterval(timer);
  }, [syncJob, policy, loadPolicies, loadRegistry, onError]);
  useEffect(() => {
    if (!experiments.some(e => RUNNING.has(e.status))) return;
    const timer = setInterval(() => void loadExperiments().catch(onError), 2500);
    return () => clearInterval(timer);
  }, [experiments, loadExperiments, onError]);

  async function sync() {
    try { const job = await api<any>('/math/sync', { method: 'POST', body: JSON.stringify({ policy }) }); setSyncJob(job); } catch (e) { onError(e); }
  }
  const status = policies?.policies.find(p => p.policy === policy);
  const header = <PolicyBar Icon={Icon} policies={policies} policy={policy} setPolicy={setPolicy} status={status} registry={registry} sync={sync} syncJob={syncJob}/>;

  if (view === 'math-params') return <Catalogue Icon={Icon} header={header} registry={registry} onDesign={id => { setDesignParam(id); setView('math-new'); }}/>;
  if (view === 'math-new') return <Builder Icon={Icon} header={header} registry={registry} policy={policy} param={designParam} setParam={setDesignParam} onError={onError}
    onCreated={id => { setSelected(id); void loadExperiments(); setView('math-run'); }}/>;
  if (view === 'math-runs') return <Experiments Icon={Icon} experiments={experiments} open={id => { setSelected(id); setView('math-run'); }} create={() => setView('math-new')}/>;
  return <ExperimentView Icon={Icon} id={selected} onError={onError} back={() => setView('math-runs')}/>;
}

function PolicyBar({ Icon, policies, policy, setPolicy, status, registry, sync, syncJob }: { Icon: IconType; policies: Policies | null; policy: string; setPolicy: (p: string) => void;
  status?: PolicyStatus; registry: Registry | null; sync: () => void; syncJob: { status: string; progress?: Progress & { result?: any } } | null }) {
  const running = !!syncJob && RUNNING.has(syncJob.status);
  const ins = registry?.inspection;
  return <section className="panel ml-policybar">
    <div className="ml-policy-select"><label htmlFor="ml-policy">Captured policy</label>
      <select id="ml-policy" value={policy} onChange={e => setPolicy(e.target.value)}>{(policies?.policies || []).map(p => <option key={p.policy}>{p.policy}</option>)}</select></div>
    <div className="ml-facts">
      <span><small>Recorded ticks held</small><strong>{status?.snapshots_held ?? '—'}</strong></span>
      <span><small>Last sync</small><strong>{when(status?.last_sync?.finished_at)}</strong></span>
      <span><small>Replay binary</small><strong><code>{policies?.binary?.git_sha ? policies.binary.git_sha.slice(0, 10) : 'not resolved'}</code></strong></span>
      <span><small>Economics mode</small><strong><code>{ins?.economics_mode || '—'}</code></strong></span>
    </div>
    <button className="button secondary" disabled={running || !policy} onClick={sync}>{running ? <span className="spinner"/> : <Icon name="refresh" size={16}/>}{running ? (syncJob?.progress?.message || 'Syncing…') : 'Sync recorded ticks'}</button>
    {syncJob && !running && syncJob.status !== 'COMPLETE' && <div className="notice error ml-wide">Sync {syncJob.status.toLowerCase()}: {syncJob.progress?.message || 'see the job record'}</div>}
    {syncJob?.progress?.result?.binary_error && <div className="notice warning ml-wide">Replay binary unavailable: {syncJob.progress.result.binary_error}. Snapshots were still synced; experiments stay blocked until the deployed image ships brain-replay.</div>}
  </section>;
}

function Catalogue({ Icon, header, registry, onDesign }: { Icon: IconType; header: React.ReactNode; registry: Registry | null; onDesign: (id: string) => void }) {
  const [query, setQuery] = useState('');
  const [cls, setCls] = useState('');
  const [role, setRole] = useState('');
  const [onlyProtected, setOnlyProtected] = useState(false);
  const [open, setOpen] = useState<string>('');
  const items = useMemo(() => (registry?.items || []).filter(i => {
    const text = `${i.param_id} ${i.name} ${i.symbol || ''} ${i.config_key || ''}`.toLowerCase();
    return (!query || text.includes(query.toLowerCase())) && (!cls || i.class === cls) && (!role || i.role === role) && (!onlyProtected || i.protected);
  }), [registry, query, cls, role, onlyProtected]);
  const roles = useMemo(() => [...new Set((registry?.items || []).map(i => i.role).filter(Boolean))].sort() as string[], [registry]);
  const detail = registry?.items.find(i => i.param_id === open);
  return <>
    <div className="page-heading"><div><span className="eyebrow">MATH LAB · PARAMETER REGISTRY</span><h1>Brain parameters</h1>
      <p>{registry ? `${registry.items.length} quantities · registry ${registry.registry_version} · verified at ${registry.source?.source_sha?.slice(0, 10) ?? '—'}` : 'Loading…'}{registry?.inspection ? ` · effective values from tick ${registry.inspection.snapshot_digest.slice(0, 10)} (${when(registry.inspection.captured_at)})` : ' · no recorded tick yet: effective values unavailable'}</p></div></div>
    {header}
    <div className="ml-filters">
      <input type="search" placeholder="Search id, name, symbol or key" value={query} onChange={e => setQuery(e.target.value)} aria-label="Search parameters"/>
      <select value={cls} onChange={e => setCls(e.target.value)} aria-label="Class"><option value="">All classes</option>{Object.entries(CLASS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
      <select value={role} onChange={e => setRole(e.target.value)} aria-label="Role"><option value="">All roles</option>{roles.map(r => <option key={r}>{r}</option>)}</select>
      <label className="ml-check"><input type="checkbox" checked={onlyProtected} onChange={e => setOnlyProtected(e.target.checked)}/>Protected only</label>
      <span className="field-hint">{items.length} shown</span>
    </div>
    <section className="panel ml-table-panel"><table className="ml-table">
      <thead><tr><th>Parameter</th><th>Class</th><th>Configured</th><th>Effective</th><th>Status</th><th/></tr></thead>
      <tbody>{items.map(i => <tr key={i.param_id} className={open === i.param_id ? 'selected' : ''} onClick={() => setOpen(open === i.param_id ? '' : i.param_id)}>
        <td><code>{i.param_id}</code> <strong>{i.name}</strong>{i.symbol && <span className="ml-symbol">{i.symbol}</span>}<small>{i.config_key || i.effective_source || ''}</small></td>
        <td>{CLASS_LABEL[i.class] || i.class}{i.protected && <span className="badge warning ml-inline">protected</span>}</td>
        <td>{i.configured_present ? show(i.configured_value) : <span className="ml-muted">{i.config_key ? 'not set' : '—'}</span>}</td>
        <td>{show(i.effective_value)}<small>{i.effective_status && i.effective_status !== 'UNAVAILABLE' ? i.effective_status.toLowerCase().replace('_', ' ') : 'unavailable'}</small></td>
        <td>{i.control === 'EXPERIMENT_KNOB' ? <span className="badge good">replay knob</span> : i.control === 'NO_LIVE_EFFECT' ? <span className="badge neutral">no live effect</span> : <span className="badge neutral">read-only</span>}</td>
        <td>{i.control === 'EXPERIMENT_KNOB' && <button className="button tiny" onClick={e => { e.stopPropagation(); onDesign(i.param_id); }}>Design sweep</button>}</td>
      </tr>)}</tbody></table></section>
    {detail && <aside className="panel ml-detail" aria-label={`${detail.param_id} details`}>
      <div className="panel-heading"><Icon name="layers"/><div><h2>{detail.param_id} · {detail.name}</h2><p>{detail.symbol ? `${detail.symbol} · ` : ''}{detail.role} · {detail.impact} · scope {detail.scope}</p></div>
        <button className="icon-button" aria-label="Close details" onClick={() => setOpen('')}><Icon name="stop" size={14}/></button></div>
      {(detail.warnings || []).length > 0 && <div className="notice warning"><ul>{detail.warnings!.map((w, k) => <li key={k}>{w}</li>)}</ul></div>}
      <dl className="ml-dl">
        {([['Config key', detail.config_key], ['Configured', detail.configured_present ? show(detail.configured_value) : 'not set in the CR'],
          ['Effective', `${show(detail.effective_value)} — ${detail.effective_source || 'unavailable'}`], ['Default', detail.default_value], ['Units', detail.units],
          ['Admission domain', detail.admission_domain], ['Validation', detail.validation], ['Experimental range', detail.experimental_range_status],
          ['Apply mechanism', detail.apply_mechanism], ['Effect latency', detail.effect_latency], ['Active status', detail.active_status],
          ['Safe direction', detail.safe_direction], ['Couplings', (detail.couplings || []).join(', ')],
          ['Metrics', [detail.metric_ids?.primary, ...(detail.metric_ids?.secondary || [])].filter(Boolean).join(', ')], ['Guardrails', (detail.metric_ids?.guardrails || []).join(', ')],
          ['Source', (detail.source_locations || []).join('; ')], ['Verification', `${detail.verification} at ${detail.source_verified_at_sha?.slice(0, 10) || '—'} · ${detail.recon_status}`],
          ['Change since audit', detail.delta_summary], ['Notes', detail.notes]] as [string, unknown][]).filter(([, v]) => v !== undefined && v !== null && v !== '').map(([k, v]) =>
          <div key={k}><dt>{k}</dt><dd>{String(v)}</dd></div>)}
      </dl>
    </aside>}
  </>;
}

function Builder({ Icon, header, registry, policy, param, setParam, onError, onCreated }: { Icon: IconType; header: React.ReactNode; registry: Registry | null; policy: string; param: string; setParam: (p: string) => void;
  onError: (e: unknown) => void; onCreated: (id: string) => void }) {
  const knobs = (registry?.items || []).filter(i => i.control === 'EXPERIMENT_KNOB');
  const knob = knobs.find(k => k.param_id === param);
  const [values, setValues] = useState<(number | 'UNSET')[]>(PRESETS[param]?.values || []);
  const [draft, setDraft] = useState('');
  const [title, setTitle] = useState('');
  const [hypothesis, setHypothesis] = useState('');
  const [maxSnapshots, setMaxSnapshots] = useState(500);
  const [preflight, setPreflight] = useState<Preflight | null>(null);
  const [busy, setBusy] = useState('');
  const stamp = useRef('');
  useEffect(() => { setValues(PRESETS[param]?.values || []); setPreflight(null); setTitle(param === 'P-FEA-006' ? 'Cost-ceiling (G9) binding sweep' : param === 'P-OBJ-003' ? 'Disruption-aversion (β) pricing sweep' : ''); }, [param]);
  const body = useMemo(() => ({
    title: title || `${param} sweep`, mode: 'REPLAY', parameter_id: param, policy,
    arms: [{ arm_id: 'control', value_source: 'RECORDED_EFFECTIVE' }, ...values.map(v => v === 'UNSET' ? { arm_id: 'unset', unset: true } : { arm_id: `v${String(v).replace('.', '_')}`, value: v })],
    cohort: { max_snapshots: maxSnapshots }, hypothesis: hypothesis || undefined,
    primary_metric_id: param === 'P-FEA-006' ? 'M-P04' : 'M-P21', secondary_metric_ids: ['M-P21', 'M-P22', 'M-P23', 'M-P25', 'M-P26'],
    safety_metric_ids: ['M-D02', 'M-D05', 'M-D06', 'M-D07'],
  }), [title, param, policy, values, maxSnapshots, hypothesis]);
  const key = JSON.stringify(body);
  const domain = knob?.replay_override?.domain;
  function addValue() {
    const v = Number(draft);
    if (!draft.trim() || !isFinite(v)) return;
    if (domain && ((domain.min !== undefined && v < domain.min) || (domain.max !== undefined && v > domain.max))) { onError(new Error(`Value outside the replay domain [${domain.min}, ${domain.max}]`)); return; }
    if (!values.includes(v)) setValues([...values, v].sort((a, b) => (a === 'UNSET' ? -1 : b === 'UNSET' ? 1 : (a as number) - (b as number))));
    setDraft('');
  }
  async function runPreflight() {
    setBusy('preflight');
    try { const pf = await api<Preflight>('/math/experiments/preflight', { method: 'POST', body: key }, 90_000); setPreflight(pf); stamp.current = key; }
    catch (e) { onError(e); } finally { setBusy(''); }
  }
  async function start() {
    setBusy('start');
    try { const exp = await api<{ id: string }>('/math/experiments', { method: 'POST', body: key }, 90_000); onCreated(exp.id); }
    catch (e) { onError(e); } finally { setBusy(''); }
  }
  const ready = preflight?.status === 'PASS' && stamp.current === key;
  return <>
    <div className="page-heading"><div><span className="eyebrow">MATH LAB · NEW EXPERIMENT</span><h1>Design a replay sweep</h1>
      <p>Change one parameter, replay the same recorded ticks for every value, and compare against the recorded control.</p></div></div>
    {header}
    <div className="configure-grid">
      <section className="panel configure-panel">
        <div className="panel-heading"><span className="step-number">1</span><div><h2>Parameter and hypothesis</h2><p>Only registry replay knobs can be varied.</p></div></div>
        <label>Parameter</label>
        <div className="ml-knobs">{knobs.map(k => <button type="button" key={k.param_id} className={`app-chip ${k.param_id === param ? 'checked' : ''}`} role="radio" aria-checked={k.param_id === param} onClick={() => setParam(k.param_id)}>
          <code>{k.param_id}</code> {k.name}</button>)}</div>
        {knob && <div className="ml-knob-facts"><span>Recorded effective: <strong>{show(knob.effective_value)}</strong></span><span>Replay domain: <strong>[{domain?.min ?? '—'}, {domain?.max ?? '—'}]</strong></span>
          <span>Experimental range: <strong>{(knob.experimental_range_status || 'UNVALIDATED').toLowerCase()}</strong></span>{knob.protected && <span className="badge warning">protected</span>}</div>}
        {knob && (knob.warnings || []).map((w, i) => <p key={i} className="field-hint">⚠ {w}</p>)}
        <label htmlFor="ml-title">Title</label><input id="ml-title" maxLength={200} value={title} onChange={e => setTitle(e.target.value)}/>
        <label htmlFor="ml-hyp">Hypothesis</label><textarea id="ml-hyp" rows={3} maxLength={2000} value={hypothesis} onChange={e => setHypothesis(e.target.value)}
          placeholder={param === 'P-FEA-006' ? 'The CHi ceiling is the sole binding gate for useful candidates on vLLM.' : 'A fixed disruption price changes which moves are selected.'}/>
      </section>
      <section className="panel configure-panel">
        <div className="panel-heading"><span className="step-number">2</span><div><h2>Arms and cohort</h2><p>{PRESETS[param]?.hint}</p></div></div>
        <label>Values (control is the recorded effective value)</label>
        <div className="ml-values"><span className="app-chip checked">control · recorded</span>{values.map(v => <button type="button" key={String(v)} className="app-chip" onClick={() => setValues(values.filter(x => x !== v))} title="Remove">{String(v)} ×</button>)}</div>
        <div className="ml-add"><input inputMode="decimal" placeholder="Add a value" value={draft} onChange={e => setDraft(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addValue(); } }}/>
          <button type="button" className="button secondary" onClick={addValue}>Add</button>{knob?.replay_override?.unset_allowed && !values.includes('UNSET') && <button type="button" className="button secondary" onClick={() => setValues(['UNSET', ...values])}>Add UNSET</button>}</div>
        <label htmlFor="ml-max">Most recent recorded ticks to replay</label><input id="ml-max" type="number" min={1} max={5000} value={maxSnapshots} onChange={e => setMaxSnapshots(Math.max(1, Math.min(5000, Number(e.target.value) || 1)))}/>
        <p className="field-hint">Primary metric: <code>{body.primary_metric_id}</code> · guardrails M-D02/05/06/07 are reported UNAVAILABLE in replay, never as zero.</p>
      </section>
    </div>
    <section className="panel ml-pad">
      <div className="panel-heading"><span className="step-number">3</span><div><h2>Preflight</h2><p>Version pin, cohort sufficiency, comparability and domain checks. A run starts only after a passing preflight of exactly this design.</p></div></div>
      {preflight && <ul className="ml-checks">{preflight.checks.map((c, i) => <li key={i}><StatusBadge status={c.status}/><code>{c.id}</code><span>{c.message}</span></li>)}</ul>}
      <div className="plan-footer"><span>{preflight ? `${preflight.cohort?.snapshots ?? 0} ticks in the cohort · ${values.length} trial arms` : 'Run preflight to check this design.'}</span>
        <div className="heading-actions"><button className="button secondary" disabled={!!busy || !policy || values.length === 0} onClick={() => void runPreflight()}>{busy === 'preflight' ? <span className="spinner"/> : <Icon name="shield" size={16}/>}Run preflight</button>
          <button className="button primary" disabled={!ready || !!busy} onClick={() => void start()}>{busy === 'start' ? <span className="spinner"/> : <Icon name="play" size={16}/>}Start replay</button></div></div>
    </section>
  </>;
}

function Experiments({ Icon, experiments, open, create }: { Icon: IconType; experiments: Experiment[]; open: (id: string) => void; create: () => void }) {
  return <>
    <div className="page-heading"><div><span className="eyebrow">MATH LAB · EXPERIMENTS</span><h1>Replay experiments</h1><p>Immutable experiments; each keeps its manifest, cohort and evidence.</p></div>
      <button className="button primary" onClick={create}><Icon name="lab" size={18}/>New experiment</button></div>
    <section className="panel history-panel">{experiments.length === 0 ? <div className="empty-state"><Icon name="history" size={40}/><h2>No experiments yet.</h2><p>Sync recorded ticks, then design a sweep.</p></div>
      : experiments.map(e => <button key={e.id} className="history-row" onClick={() => open(e.id)}><span className="history-icon"><Icon name="layers"/></span>
        <span className="history-title"><strong>{e.title}</strong><small><span dir="ltr">{e.id}</span> · {when(e.createdAt)}</small></span>
        <span className="history-meta"><code>{e.parameter_id}</code><span>{e.policy} · {e.arms} arms</span></span>
        <span>{RUNNING.has(e.status) && e.progress?.message ? <small className="ml-muted">{e.progress.message}</small> : null}<StatusBadge status={e.status}/></span><Icon name="arrow" size={18}/></button>)}</section>
  </>;
}

function ExperimentView({ Icon, id, onError, back }: { Icon: IconType; id: string; onError: (e: unknown) => void; back: () => void }) {
  const [detail, setDetail] = useState<Detail | null>(null);
  const [metrics, setMetrics] = useState<MetricRow[]>([]);
  const [plots, setPlots] = useState<Plots>({});
  const [metric, setMetric] = useState('');
  const [arm, setArm] = useState('');
  const load = useCallback(async () => {
    const d = await api<Detail>(`/math/experiments/${id}`);
    setDetail(d);
    if (!RUNNING.has(d.status)) { setMetrics(await api<MetricRow[]>(`/math/experiments/${id}/metrics`)); setPlots(await api<Plots>(`/math/experiments/${id}/plots`)); }
  }, [id]);
  useEffect(() => { if (id) void load().catch(onError); }, [id, load, onError]);
  useEffect(() => { if (!detail || !RUNNING.has(detail.status)) return; const t = setInterval(() => void load().catch(onError), 2000); return () => clearInterval(t); }, [detail, load, onError]);
  const metricIds = Object.keys(plots.dose_response || {});
  useEffect(() => { if (!metric && metricIds.length) setMetric(detail?.request?.primary_metric_id && metricIds.includes(detail.request.primary_metric_id) ? detail.request.primary_metric_id : metricIds[0]); }, [metricIds, metric, detail]);
  const arms: string[] = (detail?.request?.arms || []).map((a: any) => a.arm_id);
  useEffect(() => { if (!arm && arms.length > 1) setArm(arms[1]); }, [arms, arm]);
  if (!detail) return <div className="loading-line"><span className="spinner"/>Loading experiment…</div>;
  const result = detail.result;
  const comparison = result?.comparison_status || '—';
  const control = arms[0];
  const catalog = (id: string) => metrics.find(m => m.metric_id === id);
  const order = (x: unknown) => (typeof x === 'number' ? x : -Infinity);
  const toPoints = (rows: any[] | undefined): Point[] => [...(rows || [])].sort((a, b) => order(a.x_value) - order(b.x_value))
    .map(r => ({ key: r.arm_id, label: r.is_control ? `control ${String(r.x_label).replace('recorded ', '')}` : r.x_label, value: r.value, low: r.ci_low, high: r.ci_high, n: r.n, control: r.is_control }));
  const armLabel = (a: string) => a === control ? `control (${String(result?.arm_values?.[a]?.label ?? '').replace('recorded ', '')})` : String(result?.arm_values?.[a]?.label ?? a);
  const funnelRows = (plots.funnel?.[control] || []).map((s, i) => ({ label: s.stage, values: [s.count, plots.funnel?.[arm]?.[i]?.count ?? 0] })).filter(r => r.values.some(v => v > 0) || r.label === 'selected');
  const g9Cats = ['G9_SOLE_VETO_VERIFIED', 'G9_MULTI_VETO_VERIFIED', 'G9_WOULD_PASS_AFTER_EARLIER_VETO', 'G9_PASS', 'G9_UNKNOWN_OTHER_GATES'];
  const noopCats = [...new Set(Object.values(plots.noop || {}).flatMap(o => Object.keys(o)))].sort().slice(0, 5);
  const tableMetric = metric;
  const headline = metrics.filter(m => m.dimension === null && m.comparison !== 'PRODUCTION_RECORD' && m.data_status === 'OBSERVED' && (!tableMetric || m.metric_id === tableMetric));
  const unavailable = [...new Map(metrics.filter(m => m.data_status === 'UNAVAILABLE' && m.dimension === null).map(m => [m.metric_id, m])).values()];
  const pct = detail.progress?.total ? Math.round(100 * (detail.progress.completed || 0) / detail.progress.total) : null;
  return <>
    <div className="page-heading run-heading"><div><span className="eyebrow">MATH LAB · REPLAY EXPERIMENT</span><h1>{detail.request?.title}</h1>
      <p><code>{detail.id}</code><span className="inline-separator">·</span><code>{detail.request?.parameter_id}</code><span className="inline-separator">·</span>{detail.request?.namespace}/{detail.request?.policy}<span className="inline-separator">·</span>{when(detail.createdAt)}</p></div>
      <div className="heading-actions"><StatusBadge status={detail.status}/>{comparison !== '—' && <StatusBadge status={comparison}/>}<button className="button secondary" onClick={back}>All experiments</button></div></div>
    {RUNNING.has(detail.status) && <section className="panel progress-card"><span className="stat-label">{detail.progress?.stage || 'queued'}</span><strong><span>{pct === null ? '—' : `${pct}%`}</span><span className="progress-count">{detail.progress?.message}</span></strong>
      <div className="progress-track live"><div style={{ width: `${pct ?? 5}%` }}/></div></section>}
    {detail.message && !RUNNING.has(detail.status) && detail.status !== 'COMPLETE' && <div className="notice warning">{detail.message}</div>}
    <div className="notice ml-watermark"><strong>Replay mechanism evidence.</strong> These results show how the unmodified decision engine responds on recorded ticks. They are not defense rates, SLO outcomes or a recommendation; verified defense (M-S01) and disruption (M-D*) need paired sandbox episodes.</div>
    {result && <section className="run-overview ml-overview">
      <div className="panel run-stat"><span className="stat-label">Recorded ticks</span><strong>{result.population?.snapshots_replayed}</strong><span className="field-hint">baseline reproduced exactly: {result.population?.control_eligible}</span></div>
      <div className="panel run-stat"><span className="stat-label">Matched per arm</span><strong>{Object.values(result.population?.matched_by_arm || {}).join(' · ')}</strong><span className="field-hint">{Object.keys(result.population?.control_exclusions || {}).length ? `excluded: ${JSON.stringify(result.population.control_exclusions)}` : 'no control exclusions'}</span></div>
      <div className="panel run-stat"><span className="stat-label">Replay binary</span><strong><code>{String(detail.manifest?.replay_binary?.git_sha || '—').slice(0, 12)}</code></strong><span className="field-hint">{detail.manifest?.replay_binary?.image_digest ? String(detail.manifest.replay_binary.image_digest).slice(0, 19) : 'local binary (observational)'}</span></div>
      <div className="panel run-stat"><span className="stat-label">Arms</span><strong>{arms.length}</strong><span className="field-hint">{Object.entries(result.arm_values || {}).map(([k, v]: any) => `${k}=${v.label}`).join(' · ')}</span></div>
    </section>}
    {metricIds.length > 0 && <section className="panel ml-pad">
      <div className="ml-chart-head"><div><h2>PL-01 · {catalog(metric)?.metric_name || metric} by parameter value</h2><p>{catalog(metric)?.definition} · <em>{KIND_LABEL[catalog(metric)?.metric_kind || ''] || ''}</em></p></div>
        <select value={metric} onChange={e => setMetric(e.target.value)} aria-label="Metric">{metricIds.map(m => <option key={m} value={m}>{m} · {catalog(m)?.metric_name}</option>)}</select></div>
      <DotWhisker points={toPoints(plots.dose_response?.[metric])} unit={catalog(metric)?.unit || ''} watermark={`REPLAY MECHANISM · ${comparison}`}/>
      {plots.paired?.[`${metric}:diff`] && <><h3 className="ml-subhead">PL-09 · paired difference vs control (same ticks)</h3>
        <DotWhisker points={toPoints(plots.paired[`${metric}:diff`])} unit={`Δ ${catalog(metric)?.unit || ''}`} zeroLine watermark={`PAIRED · ${comparison}`}/></>}
    </section>}
    {funnelRows.length > 0 && <section className="panel ml-pad">
      <div className="ml-chart-head"><div><h2>PL-08 · Gate funnel</h2><p>Enabled (asset, action) pairs and the gate that issued each pair's FIRST veto. Later gates were never evaluated for a vetoed pair.</p></div>
        <select value={arm} onChange={e => setArm(e.target.value)} aria-label="Compared arm">{arms.slice(1).map(a => <option key={a} value={a}>{armLabel(a)}</option>)}</select></div>
      <GroupedBars rows={funnelRows} series={[armLabel(control), armLabel(arm)]}/>
    </section>}
    {detail.request?.parameter_id === 'P-FEA-006' && plots.g9 && <section className="panel ml-pad"><h2>G9 attribution</h2><p className="field-hint">Sole-veto verified = the actual first veto was the CHi ceiling, so every earlier gate actually passed. Earlier-veto categories use a labeled counterfactual diagnostic only.</p>
      <StackedShares rows={arms.map(a => ({ label: armLabel(a), counts: plots.g9?.[a] || {} }))} categories={g9Cats}/></section>}
    {noopCats.length > 0 && <section className="panel ml-pad"><h2>No-op reasons</h2><p className="field-hint">Why an asset-tick ended without a selected move.</p>
      <StackedShares rows={arms.map(a => ({ label: armLabel(a), counts: plots.noop?.[a] || {} }))} categories={noopCats}/></section>}
    {metrics.length > 0 && <section className="panel ml-table-panel"><h2>Table view · {catalog(tableMetric)?.metric_name || 'all metrics'}</h2>
      {unavailable.length > 0 && <p className="field-hint ml-table-note">Unavailable in this experiment (never reported as zero): {unavailable.map(m => `${m.metric_id} ${m.metric_name}`).join(' · ')} — {unavailable[0].reason}</p>}
      <table className="ml-table compact">
      <thead><tr><th>Arm</th><th>Metric</th><th>Comparison</th><th>Estimate</th><th>95% interval</th><th>n</th><th>Num / den</th><th>Kind</th><th>Status</th></tr></thead>
      <tbody>{headline.map((m, i) => <tr key={i}><td>{m.arm_id}<small>{m.effective_value_label}</small></td><td><code>{m.metric_id}</code> {m.metric_name}{m.metric_proposed && <small>proposed id</small>}</td>
        <td>{m.comparison === 'PAIRED_DIFF_VS_CONTROL' ? 'Δ vs control' : 'arm level'}</td><td>{fmt(m.value, 4)}</td><td>{m.ci_low === null ? '—' : `[${fmt(m.ci_low, 4)}, ${fmt(m.ci_high, 4)}]`}</td>
        <td>{m.n ?? '—'}</td><td>{m.numerator === null ? '—' : `${m.numerator} / ${m.denominator}`}</td><td>{KIND_LABEL[m.metric_kind] || m.metric_kind}</td><td>{m.data_status === 'OBSERVED' ? m.comparison_status.toLowerCase() : <span title={m.reason || ''}>{m.data_status.toLowerCase()}</span>}</td></tr>)}</tbody></table></section>}
    {detail.artifacts.length > 0 && <section className="panel artifacts-panel"><div className="panel-heading"><Icon name="download"/><div><h2>Evidence</h2><p>Raw rows join back to the replay output by experiment, arm, tick, asset and action.</p></div></div>
      {['evidence.zip', 'report.md', 'Phorvex_Math_Lab_Results.xlsx', 'sweep_results.csv', 'candidate_gate_trace.csv', 'decision_funnel.csv', 'cost_truth.csv', 'experiment_manifest.json', 'replay.jsonl']
        .filter(a => detail.artifacts.includes(a)).map(a => <a key={a} className="artifact-link" href={`/api/math/experiments/${encodeURIComponent(detail.id)}/artifacts/${a}`}><span className="file-icon"><Icon name="file"/></span><span><strong>{a}</strong><small>{a === 'evidence.zip' ? 'Everything below plus plots and inspections' : 'Download'}</small></span><Icon name="download" size={18}/></a>)}
      <p className="field-hint ml-table-note">Promotion: a production change to a protected parameter needs paired sandbox evidence and a separately reviewed change request. This lab has no production write path.</p></section>}
  </>;
}

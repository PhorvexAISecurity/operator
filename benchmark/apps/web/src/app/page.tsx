'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { MathLab, type MathView } from './mathlab';
import BenchmarkRequestDetails from '@/components/BenchmarkRequestDetails';
import VersionDetails from '@/components/VersionDetails';
import ObjectiveDetails from '@/components/ObjectiveDetails';
import { REQUEST_MAX_CHARACTERS } from '@/lib/limits';
import { appRecords, progressMessage, readiness, readinessCounts, readinessReason, splitBenchmarkRequest, versionsDiffer } from '@/lib/presentation';
import {
  api, ApiError, activeStatuses, appLabel, display, modelId, modelLabel, namespace,
  safeExternalUrl, versionLabel, type Artifact, type Case, type Event, type Meta, type Mode, type Plan, type Run,
} from '@/lib/api';

function Icon({ name, size = 20 }: { name: string; size?: number }) {
  const paths: Record<string, React.ReactNode> = {
    lab: <><path d="M9 3h6M10 3v7l-5 8a2 2 0 0 0 2 3h10a2 2 0 0 0 2-3l-5-8V3"/><path d="M8 15h8"/></>,
    chart: <><path d="M3 20h18M6 16v-5M11 16V6M16 16v-8M21 16v-3"/></>,
    arrow: <><path d="M5 12h14m-6-6 6 6-6 6"/></>,
    play: <path d="m8 5 11 7-11 7V5Z"/>,
    history: <><path d="M3 11a9 9 0 1 1 2.6 7M3 4v7h7M12 7v5l3 2"/></>,
    layers: <><path d="m12 3 9 5-9 5-9-5 9-5ZM3 12l9 5 9-5M3 16l9 5 9-5"/></>,
    serial: <><rect x="3" y="8" width="4" height="8" rx="1"/><rect x="10" y="8" width="4" height="8" rx="1"/><rect x="17" y="8" width="4" height="8" rx="1"/><path d="M7 12h3m4 0h3"/></>,
    parallel: <><path d="M5 4v16m14-16v16M5 6h14M5 12h14M5 18h14"/><path d="m16 3 3 3-3 3m0 0 3 3-3 3m0 0 3 3-3 3"/></>,
    download: <><path d="M12 3v12m-5-5 5 5 5-5M4 16v4h16v-4"/></>,
    external: <><path d="M14 3h7v7m0-7-10 10M10 3H4a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h16a1 1 0 0 0 1-1v-6"/></>,
    check: <path d="m5 12 4 4L19 6"/>,
    shield: <><path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/></>,
    stop: <rect x="6" y="6" width="12" height="12" rx="2"/>,
    logout: <><path d="M9 4H4v16h5M9 12h12m-4-4 4 4-4 4"/></>,
    refresh: <><path d="M20 8a8 8 0 0 0-14-3L3 8m0-5v5h5M4 16a8 8 0 0 0 14 3l3-3m0 5v-5h-5"/></>,
    key: <><circle cx="8" cy="8" r="5"/><path d="m12 12 9 9m-3-3 3-3m-6 0 3-3"/></>,
    file: <><path d="M14 3H5v18h14V8l-5-5Zm0 0v5h5M8 12h8m-8 4h8"/></>,
  };
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">{paths[name] || paths.lab}</svg>;
}

const statusLabels: Record<string, string> = {
  queued: 'Queued', running: 'Running', starting: 'Preparing', capturing: 'Capturing',
  completed: 'Run finished', complete: 'Run finished', succeeded: 'Run finished',
  failed: 'Run failed', error: 'Error', aborted: 'Aborted', cancelled: 'Cancelled',
  cancelling: 'Stopping', cancel_requested: 'Stopping', blocked: 'Blocked',
  unavailable: 'Unavailable', unknown: 'Unknown', pending: 'Pending', skipped: 'Not executed',
  observed: 'Observed', confirmed: 'Confirmed', emitted: 'Emitted', refused: 'Refused',
  defended: 'Defense confirmed', selected: 'Selected', admitted: 'Admitted',
  ready: 'Ready', partial: 'Partial evidence', gap: 'Evidence gap',
  incomplete: 'Incomplete evidence', interrupted: 'Interrupted', 'original-record': 'Original result record',
};
const evidenceHelp: Record<string, string> = {
  evidence: 'Retained observations and supporting records; this is not a defense verdict.',
  complete: 'Evidence coverage is reported complete; this alone does not confirm a defense.',
  partial: 'Some evidence was retained, but required coverage is missing.',
  gap: 'A required observation is missing or uncertain; no defense pass is inferred.',
  incomplete: 'Observation or capture did not finish the required scope or window.',
  'original-record': 'The raw decision and outcome record returned by the Console; not independent proof of a defense.',
};
function Badge({ status = 'unknown', evidence = false }: { status?: string; evidence?: boolean }) {
  const key = status.toLowerCase();
  const tone = activeStatuses.has(key) ? 'active' : ['failed', 'error', 'aborted', 'blocked', 'refused', 'interrupted'].includes(key) ? 'danger' : ['incomplete', 'partial', 'gap'].includes(key) ? 'warning' : ['unavailable', 'unknown', 'skipped'].includes(key) ? 'muted' : ['completed', 'complete', 'confirmed', 'defended', 'observed', 'succeeded'].includes(key) ? 'good' : 'neutral';
  return <span className={`badge ${tone}`} title={evidence ? evidenceHelp[key] : undefined}>{activeStatuses.has(key) && <i/>}{evidence && ['complete', 'evidence'].includes(key) ? 'Evidence' : statusLabels[key] || status}</span>;
}
function date(value?: string) {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(parsed);
}
function errorText(error: unknown) { return error instanceof Error ? error.message : 'Could not connect to the service.'; }
function duration(seconds: number) {
  if (!Number.isFinite(seconds) || seconds < 0) return '—';
  const total = Math.round(seconds);
  const h = Math.floor(total / 3600), m = Math.floor((total % 3600) / 60), s = total % 60;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}
// Honest ETA: linear extrapolation from the observed completion rate. Only shown while
// the run is active and at least one case has finished; it is an estimate, not a promise.
function estimateRemaining(run: Run, completed: number, total: number): number | null {
  const start = run.startedAt || run.createdAt;
  if (!start || completed <= 0 || completed >= total) return null;
  const elapsed = (Date.now() - new Date(start).getTime()) / 1000;
  if (!Number.isFinite(elapsed) || elapsed <= 0) return null;
  return (elapsed / completed) * (total - completed);
}
function artifacts(run: Run): Artifact[] {
  if (Array.isArray(run.artifacts)) return run.artifacts;
  if (!run.artifacts) return [];
  return Object.entries(run.artifacts).map(([key, value]) => typeof value === 'string' ? { name: key, filename: value } : { name: key, ...(value && typeof value === 'object' ? value : {}) });
}
function EvidenceLegend() {
  return <div className="table-legend">
    <p>Evidence describes retained observations. A defense verdict requires the recorded outcome and its evidence scope.</p>
    <details><summary>Evidence labels and records</summary><dl>
      <dt>Evidence</dt><dd>Retained observations and supporting records. A complete evidence label describes coverage, not a defended pass.</dd>
      <dt>Partial evidence</dt><dd>Some evidence was retained, but required coverage is missing.</dd>
      <dt>Evidence gap</dt><dd>A required observation is missing or uncertain; no defense pass is inferred.</dd>
      <dt>Incomplete evidence</dt><dd>Observation or capture did not finish the required scope or window.</dd>
      <dt>Original result record</dt><dd>The raw decision and outcome record from the Console. This preserves what the Console reported; it is not independent proof of a defense.</dd>
      <dt>Evidence coverage / Evidence record</dt><dd>Coverage shows retained observation counts; the evidence record shows captured observations and supporting metadata.</dd>
    </dl></details>
  </div>;
}
function CaseTable({ cases, plan = false }: { cases: Case[]; plan?: boolean }) {
  return <div className="table-scroll"><table className="case-table"><thead><tr>
    <th>Application / attack</th><th>{plan ? 'Readiness' : 'Status / outcome'}</th><th>Expected actuator</th>{!plan && <th>Recorded actuator</th>}<th>{plan ? 'Limitation' : 'Evidence / notes'}</th>
  </tr></thead><tbody>{cases.map((item, index) => <tr key={`${item.namespace}/${item.id}/${index}`}>
    <td><span className="namespace" dir="ltr">{item.namespace}</span><strong dir="ltr">{item.name || item.id}</strong><span className="case-id" dir="ltr">{item.id}</span></td>
    <td><Badge status={plan ? readiness(item) : item.status || (typeof item.outcome === 'string' ? item.outcome : 'pending')}/>
      {plan && readinessReason(item) && <span className="readiness-reason" dir="ltr">{readinessReason(item)}</span>}
      {!plan && <span className="original-outcome" dir="ltr">{item.outcome ? display(item.outcome) : 'Outcome: unavailable'}</span>}
      {!plan && <span className="actuation-flag" dir="ltr">actuated: {typeof item.actuated === 'boolean' ? String(item.actuated) : 'unknown'}</span>}
    </td>
    <td><code>{display(item.expectedActuator)}</code></td>
    {!plan && <td><code>{display(item.observedActuator || item.action)}</code></td>}
    <td className="evidence-cell"><span dir="ltr">{item.error || (item.errors?.length ? item.errors.map(display).join(' · ') : '') || (item.benchmarkBlocked ? display(item.benchmarkBlockReason) : '') || item.reason || item.limitations?.join(' · ') || (!plan ? (item.resultId ? `Result: ${item.resultId}` : 'Waiting for an observed record') : '—')}</span>
      {!plan && item.evidenceStatus && <div><Badge status={item.evidenceStatus} evidence/></div>}
      {!plan && Boolean(item.evidenceKind || item.result?.evidenceKind) && <span className="original-outcome" dir="ltr">{(item.evidenceKind || item.result?.evidenceKind) === 'original-record' ? 'Original result record (Console)' : display(item.evidenceKind || item.result?.evidenceKind)}</span>}
      {!plan && item.evidenceCounts && <details><summary>Evidence coverage</summary><p>Counts of retained observations; inspect gaps before interpreting an outcome.</p><pre dir="ltr">{JSON.stringify(item.evidenceCounts, null, 2)}</pre></details>}
      {!plan && item.evidence != null && <details><summary>Evidence record</summary><p>Captured observations and supporting metadata for this case.</p><pre dir="ltr">{JSON.stringify(item.evidence, null, 2)}</pre></details>}
      {!plan && item.result && <details><summary>Original result record</summary><p>Raw decision and outcome record from the Console, preserved as returned.</p><pre dir="ltr">{JSON.stringify(item.result, null, 2)}</pre></details>}
      {!plan && item.outcome && typeof item.outcome === 'object' && <details><summary>Recorded outcome</summary><pre dir="ltr">{JSON.stringify(item.outcome, null, 2)}</pre></details>}
    </td>
  </tr>)}</tbody></table>{cases.length === 0 && <div className="empty-inline">No case records have been retained for this run yet.</div>}</div>;
}

export default function Dashboard() {
  const [auth, setAuth] = useState<'checking' | 'in' | 'out'>('checking');
  const [password, setPassword] = useState('');
  const [meta, setMeta] = useState<Meta | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const [run, setRun] = useState<Run | null>(null);
  const [events, setEvents] = useState<Event[]>([]);
  const [view, setView] = useState<'new' | 'history' | 'run' | MathView>('new');
  const [mode, setMode] = useState<Mode>('serial');
  const [model, setModel] = useState('');
  const [request, setRequest] = useState('');
  const requestTooLong = request.length > REQUEST_MAX_CHARACTERS;
  const [context, setContext] = useState('');
  const [selectedApps, setSelectedApps] = useState<string[]>([]);
  const [plan, setPlan] = useState<Plan | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);
  const runId = useRef<string | null>(null);
  const initialApps = useRef(false);
  const errorCount = useRef(0);
  const pollDelay = useRef(12_000);

  const handleError = useCallback((cause: unknown) => {
    if (cause instanceof ApiError && cause.status === 401) { setAuth('out'); setMeta(null); setRuns([]); setRun(null); setPlan(null); setEvents([]); runId.current = null; }
    setError(errorText(cause));
  }, []);

  useEffect(() => {
    let alive = true;
    api<{ authenticated: boolean }>('/auth/session').then(session => { if (alive) setAuth(session.authenticated ? 'in' : 'out'); }).catch(cause => { if (alive) { setAuth('out'); if (!(cause instanceof ApiError && cause.status === 401)) setError(errorText(cause)); } });
    return () => { alive = false; };
  }, []);

  const refresh = useCallback(async () => {
    const [metadata, history] = await Promise.all([api<Meta>('/meta', {}, 75_000), api<{ runs: Run[] }>('/runs')]);
    setMeta(metadata); setRuns(history.runs || []);
    pollDelay.current = (history.runs || []).some(item => activeStatuses.has(item.status.toLowerCase())) ? 4_000 : 12_000;
    setModel(previous => previous || (metadata.models?.[0] ? modelId(metadata.models[0]) : ''));
    if (!initialApps.current) { setSelectedApps((metadata.applications || []).map(namespace)); initialApps.current = true; }
    if (runId.current) {
      const id = runId.current;
      const [detail, log] = await Promise.all([api<Run>(`/runs/${encodeURIComponent(id)}`), api<{ events: Event[] }>(`/runs/${encodeURIComponent(id)}/events`)]);
      if (runId.current === id) { setRun(detail); setEvents((log.events || []).slice(-80)); }
    }
    setUpdatedAt(new Date().toISOString()); errorCount.current = 0;
  }, []);

  useEffect(() => {
    if (auth !== 'in') return;
    let alive = true; let polling = false; let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      if (!alive || polling) return;
      polling = true;
      if (!document.hidden) {
        try { await refresh(); } catch (cause) { if (alive) { errorCount.current++; handleError(cause); } }
      }
      polling = false;
      if (alive) timer = setTimeout(poll, Math.min(30_000, pollDelay.current * Math.max(1, errorCount.current)));
    }
    void poll();
    const visible = () => { if (!document.hidden) { clearTimeout(timer); void poll(); } };
    document.addEventListener('visibilitychange', visible);
    return () => { alive = false; clearTimeout(timer); document.removeEventListener('visibilitychange', visible); };
  }, [auth, handleError, refresh]);

  async function login(event: React.FormEvent) {
    event.preventDefault(); setBusy('login'); setError('');
    try { await api('/auth/login', { method: 'POST', body: JSON.stringify({ password }) }); setPassword(''); setAuth('in'); }
    catch (cause) { handleError(cause); } finally { setBusy(null); }
  }
  async function logout() {
    setBusy('logout');
    try { await api('/auth/logout', { method: 'POST' }); setAuth('out'); setMeta(null); setRuns([]); setRun(null); setPlan(null); setEvents([]); setError(''); runId.current = null; initialApps.current = false; }
    catch (cause) { handleError(cause); } finally { setBusy(null); }
  }
  function clearPlan() { setPlan(null); setError(''); }
  function runAgain(source: Run) {
    if (!meta || busy) return;
    const allowedModels = (meta.models || []).map(modelId);
    setRequest(source.request); setContext(source.context ?? ''); setMode(source.mode);
    setModel(allowedModels.includes(source.model) ? source.model : allowedModels[0] || '');
    setSelectedApps([...(source.applications || [])]);
    clearPlan(); setView('new');
  }
  async function makePlan(event: React.FormEvent) {
    event.preventDefault();
    if (requestTooLong) return;
    setBusy('plan'); setError(''); setPlan(null);
    try { setPlan(await api<Plan>('/plans', { method: 'POST', body: JSON.stringify({ mode, model, request: request.trim(), context: context.trim(), applications: selectedApps }) }, 165_000)); }
    catch (cause) { handleError(cause); } finally { setBusy(null); }
  }
  async function launch() {
    if (!plan || busy) return;
    if (meta?.executionBlockedReason) return;
    setBusy('launch'); setError('');
    try {
      const created = await api<Run>('/runs', { method: 'POST', body: JSON.stringify({ planId: plan.id }) });
      runId.current = created.id; setRun(created); setEvents([]); setView('run'); setPlan(null); await refresh();
    } catch (cause) { handleError(cause); } finally { setBusy(null); }
  }
  async function selectRun(id: string) {
    runId.current = id; setView('run'); setRun(null); setEvents([]); setError(''); setBusy('detail');
    try { await refresh(); } catch (cause) { handleError(cause); } finally { setBusy(null); }
  }
  async function cancel() {
    if (!run || busy) return;
    setBusy('cancel'); setError('');
    try { await api(`/runs/${encodeURIComponent(run.id)}/cancel`, { method: 'POST' }); await refresh(); }
    catch (cause) { handleError(cause); } finally { setBusy(null); }
  }

  if (auth !== 'in') return <main className="login-page"><div className="login-decoration"><div className="orb orb-one"/><div className="orb orb-two"/><div className="login-brand" dir="ltr"><span className="brand-mark"><Icon name="lab" size={26}/></span>Phorvex<span>BENCHMARK LAB</span></div></div>
    <section className="login-card"><span className="eyebrow">PHORVEX / BENCHMARK LAB</span><h1>Real evidence.<br/>Clear decisions.</h1><p>Run Live attacks, inspect defense decisions and download raw benchmark evidence.</p>
      {auth === 'checking' ? <div className="loading-line"><span className="spinner"/>Checking your session…</div> : <form onSubmit={login}><label htmlFor="password">Dashboard password</label><div className="password-field"><Icon name="key"/><input id="password" type="password" autoComplete="current-password" required maxLength={256} value={password} onChange={event => setPassword(event.target.value)} placeholder="Password"/></div>{error && <div role="alert" className="notice error">{error}</div>}<button className="button primary full" disabled={!!busy || !password}>{busy === 'login' ? <span className="spinner"/> : <Icon name="arrow"/>}Sign in to the lab</button></form>}
      <span className="login-foot">Secure cluster access and retained run evidence</span>
    </section></main>;

  const active = runs.find(item => activeStatuses.has(item.status.toLowerCase()));
  const grafanaUrl = safeExternalUrl(run?.grafanaUrl || meta?.grafanaUrl);
  const visibleArtifacts = run ? artifacts(run).filter(item => typeof item === 'string' || item.available !== false) : [];
  // Use only the API's campaign counters; retained row counts are a different measure.
  const completed = run?.progress?.completed ?? 0;
  const total = run?.progress?.total ?? 0;
  const planRequest = splitBenchmarkRequest(plan?.request);
  const runRequest = splitBenchmarkRequest(run?.request);

  return <div className="app-shell"><aside className="sidebar"><a className="brand" href="/" dir="ltr"><span className="brand-mark"><Icon name="lab" size={24}/></span><span>Phorvex<small>BENCHMARK LAB</small></span></a>
    <nav aria-label="Main navigation"><span className="nav-label">Laboratory</span><button className={view === 'new' ? 'nav-item selected' : 'nav-item'} onClick={() => { setView('new'); setError(''); }}><Icon name="lab"/>New benchmark</button><button className={view === 'history' ? 'nav-item selected' : 'nav-item'} onClick={() => { setView('history'); setError(''); }}><Icon name="history"/>Run history<span className="nav-count">{runs.length}</span></button>{runId.current && <button className={view === 'run' ? 'nav-item selected' : 'nav-item'} onClick={() => setView('run')}><Icon name="layers"/>Selected run</button>}
      <span className="nav-label">Math Lab</span>
      <button className={view === 'math-params' ? 'nav-item selected' : 'nav-item'} onClick={() => { setView('math-params'); setError(''); }}><Icon name="chart"/>Parameters</button>
      <button className={view === 'math-new' ? 'nav-item selected' : 'nav-item'} onClick={() => { setView('math-new'); setError(''); }}><Icon name="shield"/>New experiment</button>
      <button className={view === 'math-runs' || view === 'math-run' ? 'nav-item selected' : 'nav-item'} onClick={() => { setView('math-runs'); setError(''); }}><Icon name="layers"/>Experiments</button></nav>
    <div className="sidebar-bottom"><div className="scope-note"><Icon name="shield"/><div>Connected cluster<small>Live catalogue · raw evidence</small></div></div><button className="nav-item logout" disabled={!!busy} onClick={logout}><Icon name="logout"/>Sign out</button></div>
  </aside><div className="workspace"><header className="topbar"><div className="breadcrumb"><span>Laboratory</span><span className="slash">/</span><strong>{{ new: 'New benchmark', history: 'Run history', run: 'Run details', 'math-params': 'Math Lab · Parameters', 'math-new': 'Math Lab · New experiment', 'math-runs': 'Math Lab · Experiments', 'math-run': 'Math Lab · Experiment' }[view]}</strong></div><div className="topbar-right"><span className="version-pill"><span className="dot"/>Current version <code>{versionLabel(meta?.version)}</code></span><button className="icon-button" title="Refresh status" aria-label="Refresh status" onClick={() => { setError(''); void refresh().catch(handleError); }}><Icon name="refresh" size={17}/></button></div></header>
    <main className="main-content">{error && <div className="notice error" role="alert"><strong>Needs attention</strong><span dir="ltr">{error}</span><button aria-label="Dismiss message" onClick={() => setError('')}>×</button></div>}
    {meta?.executionBlockedReason && <div className="notice info execution-notice" role="status" id="execution-pause">
      <strong>New runs are paused</strong><p>New runs are paused while an operator reconciles results — history, plans and exports remain available.</p><p dir="ltr"><strong>Operator reason:</strong> {meta.executionBlockedReason}</p>
    </div>}
    {(meta?.errors || []).length > 0 && <div className="notice warning"><strong>Connection and catalogue status</strong><ul>{meta?.errors?.map((item,index) => <li key={index} dir="ltr">{display(item)}</li>)}</ul></div>}
    {view.startsWith('math-') && <MathLab view={view as MathView} setView={setView} Icon={Icon} onError={handleError}/>}
    {view === 'new' && <><div className="page-heading"><div><span className="eyebrow">LIVE SECURITY BENCHMARKS</span><h1>Test with evidence.</h1><p>Run attacks and inspect defense decisions, cost and original outcomes.</p></div><span className="heading-symbol"><Icon name="lab" size={34}/></span></div>
      {active && <div className="notice info"><span><Badge status={active.status}/> A benchmark is active on this cluster.</span><button className="text-button" onClick={() => void selectRun(active.id)}>View run <Icon name="arrow" size={15}/></button></div>}
      <div className="configure-grid"><form className="panel configure-panel" onSubmit={makePlan}><div className="panel-heading"><span className="step-number">1</span><div><h2>Define benchmark</h2><p>Describe the goal and context of your test.</p></div></div><fieldset className="form-fields" disabled={busy === 'plan' || busy === 'launch'}>
        <fieldset className="field-group"><legend>Execution pipeline</legend><div className="mode-options">{(['serial', 'parallel'] as Mode[]).map(value => <button key={value} type="button" aria-pressed={mode === value} className={`mode-card ${mode === value ? 'chosen' : ''}`} onClick={() => { setMode(value); clearPlan(); }}><span className="mode-icon"><Icon name={value}/></span><span><strong>{value === 'serial' ? 'Serial' : 'Parallel'}</strong><em>{value === 'serial' ? 'One attack at a time' : 'Concurrent applications, ordered attacks within each'}</em></span><span className="radio-dot"/></button>)}</div></fieldset>
        <div className="field-group"><label htmlFor="model">Planning model <span>LLM</span></label><select id="model" dir="ltr" required value={model} disabled={!meta || !!busy} onChange={event => { setModel(event.target.value); clearPlan(); }}><option value="" disabled>{meta ? 'Select model' : 'Loading models…'}</option>{(meta?.models || []).map(item => <option key={modelId(item)} value={modelId(item)}>{modelLabel(item)}</option>)}</select></div>
        <div className="field-group"><label htmlFor="request">What would you like to benchmark?</label><textarea dir="ltr" id="request" rows={3} required aria-invalid={requestTooLong} aria-describedby={requestTooLong ? 'request-hint request-counter request-error' : 'request-hint request-counter'} value={request} onChange={event => { setRequest(event.target.value); clearPlan(); }} placeholder="For example: Evaluate the latest version against every Live attack and inspect its actuator decisions."/><span className="field-hint" id="request-counter" aria-live="polite">{request.length.toLocaleString('en-US')} / {REQUEST_MAX_CHARACTERS.toLocaleString('en-US')} characters</span><span className="field-hint" id="request-hint">Describe the test objective and the criteria you want to inspect.</span>{requestTooLong && <div className="notice error" id="request-error" role="alert">Request exceeds {REQUEST_MAX_CHARACTERS.toLocaleString('en-US')} characters. Shorten it before creating a plan. Your text has been kept in full.</div>}</div>
        <div className="field-group"><label htmlFor="context">Context and notes <span>Optional</span></label><textarea dir="ltr" id="context" rows={3} maxLength={16000} value={context} onChange={event => { setContext(event.target.value); clearPlan(); }} placeholder="Configuration, scenarios or context for interpreting the results…"/></div>
        <fieldset className="field-group" aria-describedby="applications-hint"><legend>Target applications</legend><p className="field-hint app-selection-hint">Choose the applications whose Live catalogue entries will be considered.</p><div className="app-options" role="group" aria-label="Target applications">{(meta?.applications || []).map(app => { const ns = namespace(app); const on = selectedApps.includes(ns); return <button type="button" key={ns} role="checkbox" aria-checked={on} className={`app-chip ${on ? 'checked' : ''}`} onClick={() => { setSelectedApps(previous => previous.includes(ns) ? previous.filter(item => item !== ns) : [...previous, ns]); clearPlan(); }}><span className="chip-check"><Icon name="check" size={12}/></span><span dir="ltr">{appLabel(app)}</span></button>; })}</div>{!meta && <span className="field-hint">Loading connected applications…</span>}{meta && <span className="field-hint" id="applications-hint">{(meta.applications || []).length === 0 ? 'No applications are available.' : selectedApps.length ? `${selectedApps.length} of ${meta.applications.length} applications selected. Every Live entry for them is considered, including blocked cases.` : 'Select at least one application to create a plan.'}</span>}</fieldset>
        <div className="form-footer"><span>Review the plan before starting the run.</span><button className="button primary" disabled={!!busy || !meta || !model || !request.trim() || requestTooLong || !selectedApps.length}>{busy === 'plan' ? <span className="spinner"/> : <Icon name="arrow" size={18}/>} {busy === 'plan' ? 'Creating plan…' : 'Create benchmark plan'}</button></div>
      </fieldset></form><aside className="context-column"><div className="evidence-card"><span className="eyebrow">FROM ATTACK TO EVIDENCE</span><h2>Every result.<br/>A traceable path.</h2><div className="evidence-path"><div><span>01</span><p>Live attack<small>From each application's Live catalogue</small></p></div><div><span>02</span><p>Decision and action<small>Selection, dispatch and observed outcome</small></p></div><div><span>03</span><p>Reviewable evidence<small>Raw Excel exports and Grafana observations</small></p></div></div></div>
        <div className="panel export-info"><Icon name="file" size={24}/><h3>Two exports. One retained run.</h3><p>Measured cost compared with expected cost</p><code>Cost Measured vs Expected</code><p>Per-tick decisions and action gates</p><code>Tick Action Gates</code><span className="field-hint">Missing data and measurement limitations are explicit in the report.</span></div>
      </aside></div>
      {plan && <section className="panel plan-panel">
        <div className="panel-heading benchmark-heading"><span className="step-number">2</span><div className="benchmark-heading-text"><span className="eyebrow">PLAN REVIEW</span><h2 dir="ltr">{planRequest.title}</h2><BenchmarkRequestDetails key={plan.id} description={planRequest.description} summary={plan.summary} context={plan.context}/><section className="planning-version" aria-label="Deployed version at planning"><span className="stat-label">Deployed version at planning</span><VersionDetails version={plan.version} compact/></section></div></div>
        <div className="table-legend readiness-legend"><p className="readiness-counts" dir="ltr">{readinessCounts(plan.cases)}</p><p><strong>Ready:</strong> armed and compatible, with no benchmark block. <strong>Blocked:</strong> not armed, not compatible, or excluded for a known producer defect. Blocked cases stay visible and are never counted as defended passes. <strong>Unknown:</strong> readiness flags were not recorded.</p></div>
        {(plan.limitations || []).length > 0 && <div className="notice warning"><strong>Plan limitations</strong><ul>{plan.limitations?.map((item, index) => <li key={index} dir="ltr">{item}</li>)}</ul></div>}
        <CaseTable cases={plan.cases} plan/>
        <div className="plan-footer"><span dir="ltr">Live run on {plan.applications.join(', ')} · {plan.mode === 'serial' ? 'Serial' : 'Parallel'}</span><button className="button primary" disabled={!!busy || !!active || !plan.cases.length || !!meta?.executionBlockedReason} aria-describedby={meta?.executionBlockedReason ? 'execution-pause' : undefined} onClick={() => void launch()}>{busy === 'launch' ? <span className="spinner"/> : <Icon name="play" size={16}/>} {meta?.executionBlockedReason ? 'New runs paused' : 'Start benchmark'}</button></div>
      </section>}
    </>}
    {view === 'history' && <><div className="page-heading"><div><span className="eyebrow">RUN HISTORY</span><h1>Retained runs</h1><p>Review the version, status and exports for each benchmark.</p></div><button className="button primary" onClick={() => setView('new')}><Icon name="lab" size={18}/>New benchmark</button></div><section className="panel history-panel">{runs.length === 0 ? <div className="empty-state"><Icon name="history" size={40}/><h2>No runs have been retained yet.</h2><p>Define your first benchmark to start retaining evidence here.</p><button className="button secondary" onClick={() => setView('new')}>Define benchmark</button></div> : runs.map((item, index) => <div key={item.id} className="history-entry">
      <button className="history-row" onClick={() => void selectRun(item.id)}><span className="history-icon"><Icon name={item.mode === 'parallel' ? 'parallel' : 'serial'}/></span><span className="history-title"><strong dir="ltr">{splitBenchmarkRequest(item.request).title}</strong><small><span dir="ltr">{item.id}</span> · {date(item.startedAt || item.createdAt)}</small><span className="history-version"><span className="version-field-label">Tested version</span><VersionDetails version={item.version} compact/></span><ObjectiveDetails summary={item.objectiveSummary} compact/>{runs[index + 1] && versionsDiffer(item.version, runs[index + 1].version) && <span className="version-change">Version changed since previous run</span>}</span><span className="history-meta"><code>{item.model}</code><span>{item.mode === 'parallel' ? 'Parallel' : 'Serial'}</span></span><Badge status={item.status}/><Icon name="arrow" size={18}/></button>
      <button type="button" className="button secondary history-rerun" disabled={!meta || !!busy} onClick={() => runAgain(item)}><Icon name="refresh" size={15}/>Run again</button>
    </div>)}</section></>}
    {view === 'run' && (run ? <><div className="page-heading run-heading"><div><span className="eyebrow">BENCHMARK RUN</span><h1 dir="ltr">{runRequest.title}</h1><BenchmarkRequestDetails key={run.id} description={runRequest.description} summary={run.summary} context={run.context}/><p className="run-identity" dir="ltr"><code>{run.id}</code><span className="inline-separator">·</span>{date(run.startedAt || run.createdAt)}</p></div><div className="heading-actions"><Badge status={run.status}/><button type="button" className="button secondary" disabled={!meta || !!busy} onClick={() => runAgain(run)}><Icon name="refresh" size={15}/>Run again</button>{activeStatuses.has(run.status.toLowerCase()) && <button className="button danger-outline" disabled={!!busy} onClick={() => void cancel()}><Icon name="stop" size={15}/>{busy === 'cancel' ? 'Requesting stop…' : 'Stop run'}</button>}</div></div>
      {(() => {
        const percent = total > 0 ? Math.max(0, Math.min(100, Math.floor(completed / total * 100))) : 0;
        const live = activeStatuses.has(run.status.toLowerCase());
        const remaining = ['running', 'capturing'].includes(run.status.toLowerCase()) ? estimateRemaining(run, completed, total) : null;
        const apps = appRecords(run);
        return <section className="run-overview"><div className="panel progress-card"><span className="stat-label">Case completion (reported by service)</span>
          <strong><span>{run.progress ? <>{percent}<small>%</small></> : '—'}</span><span className="progress-count" dir="ltr">{run.progress ? `${completed} / ${total} cases completed` : 'Progress not reported'}</span></strong>
          <div className={`progress-track${live ? ' live' : ''}`} role="progressbar" aria-label="Case completion" aria-valuemin={0} aria-valuemax={100} aria-valuenow={run.progress ? percent : undefined} aria-valuetext={run.progress ? `${completed} of ${total} cases completed` : 'Progress not reported'}><div style={{width: `${percent}%`}}/></div>
          <span className="field-hint">{remaining != null ? `Estimated time remaining: ${duration(remaining)}` : progressMessage(run)}</span>
          {apps.length > 0 && <><span className="field-hint">Retained case records by application (includes blocked records)</span><div className="app-progress">{apps.map(([ns, count]) => <span key={ns} className="app-progress-chip" dir="ltr"><span className="namespace">{ns}</span>{count} {count === 1 ? 'record' : 'records'}</span>)}</div></>}
          <span className="field-hint">A finished run alone does not confirm a defense.</span></div>
        <div className="panel run-stat"><span className="stat-label">Pipeline / model</span><strong>{run.mode === 'parallel' ? 'Parallel' : 'Serial'}</strong><code>{run.model}</code></div>
        <section className="panel run-stat tested-version-card" aria-label="Tested version"><span className="stat-label">Tested version</span><VersionDetails version={run.version}/><span className="field-hint">{run.finishedAt ? `Finished: ${date(run.finishedAt)}` : 'Waiting for the run to finish'}</span></section></section>;
      })()}
      <ObjectiveDetails summary={run.objectiveSummary}/>
      <div className="results-toolbar"><div><h2>Attacks and retained decisions</h2><p>Actuator selection, actuation and confirmed effect are retained separately.</p></div>{grafanaUrl && <a className="button secondary" href={grafanaUrl} target="_blank" rel="noopener noreferrer"><Icon name="external" size={16}/>View in Grafana</a>}</div><section className="panel"><EvidenceLegend/><CaseTable cases={run.cases || []}/></section>
      <div className="run-bottom-grid"><section className="panel artifacts-panel"><div className="panel-heading"><Icon name="download"/><div><h2>Benchmark files</h2><p>Download exports in the raw Excel templates</p></div></div>{visibleArtifacts.length ? visibleArtifacts.map((artifact, index) => { const name = typeof artifact === 'string' ? artifact : artifact.name; return <a key={`${name}/${index}`} className="artifact-link" href={`/api/runs/${encodeURIComponent(run.id)}/artifacts/${encodeURIComponent(name)}`}><span className="file-icon"><Icon name="file"/></span><span><strong>{typeof artifact === 'string' ? artifact : artifact.label || artifact.filename || name}</strong><small>Export from this run</small></span><Icon name="download" size={18}/></a>; }) : <div className="empty-inline">Files become available after evidence is retained and processed.</div>}</section>
        <section className="panel events-panel"><div className="panel-heading"><Icon name="layers"/><div><h2>Run events</h2><p>Latest retained updates</p></div></div><div className="event-list">{events.length ? events.map((event,index) => <div className={`event-row ${event.level}`} key={`${event.time}/${index}`}><time>{date(event.time)}</time><span dir="ltr">{event.message}</span></div>) : <div className="empty-inline">Waiting for events…</div>}</div></section></div>
      {(run.errors || []).length > 0 && <section className="notice warning"><strong>Retained limitations and errors</strong><ul>{run.errors?.map((item,index) => <li key={index} dir="ltr">{display(item)}</li>)}</ul></section>}
    </> : <div className="empty-state"><span className="spinner"/><p>Loading run details…</p></div>)}
    <footer className="page-footer"><span dir="ltr">PHORVEX BENCHMARK LAB</span><span>{updatedAt ? `Last status update: ${date(updatedAt)}` : 'Loading service status'}</span></footer>
    </main></div></div>;
}

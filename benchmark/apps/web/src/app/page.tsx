'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  api, ApiError, activeStatuses, appLabel, display, modelId, modelLabel, namespace,
  safeExternalUrl, versionLabel, type Artifact, type Case, type Event, type Meta, type Mode, type Plan, type Run,
} from '@/lib/api';

function Icon({ name, size = 20 }: { name: string; size?: number }) {
  const paths: Record<string, React.ReactNode> = {
    lab: <><path d="M9 3h6M10 3v7l-5 8a2 2 0 0 0 2 3h10a2 2 0 0 0 2-3l-5-8V3"/><path d="M8 15h8"/></>,
    arrow: <><path d="M19 12H5M11 6l-6 6 6 6"/></>,
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
  queued: 'در صف', running: 'در حال اجرا', starting: 'آماده‌سازی', capturing: 'ثبت شواهد',
  completed: 'اجرا پایان یافت', complete: 'اجرا پایان یافت', succeeded: 'اجرا پایان یافت',
  failed: 'خطای اجرا', error: 'خطا', aborted: 'متوقف‌شده', cancelled: 'لغوشده',
  cancelling: 'در حال توقف', cancel_requested: 'در حال توقف', blocked: 'مسدود',
  unavailable: 'ناموجود', unknown: 'نامشخص', pending: 'در انتظار', skipped: 'اجرا نشده',
  observed: 'مشاهده‌شده', confirmed: 'تأییدشده', emitted: 'ارسال‌شده', refused: 'ردشده',
  defended: 'دفاع تأییدشده', selected: 'انتخاب‌شده', admitted: 'پذیرفته‌شده',
  ready: 'آمادهٔ اجرا', partial: 'شواهد ناقص', gap: 'شکاف شواهد',
  incomplete: 'اجرا با شواهد ناقص', interrupted: 'اجرای قطع‌شده', 'original-record': 'رکورد اصلی',
};
function Badge({ status = 'unknown' }: { status?: string }) {
  const key = status.toLowerCase();
  const tone = activeStatuses.has(key) ? 'active' : ['failed', 'error', 'aborted', 'blocked', 'refused', 'interrupted'].includes(key) ? 'danger' : ['incomplete', 'partial', 'gap'].includes(key) ? 'warning' : ['unavailable', 'unknown', 'skipped'].includes(key) ? 'muted' : ['completed', 'complete', 'confirmed', 'defended', 'observed', 'succeeded'].includes(key) ? 'good' : 'neutral';
  return <span className={`badge ${tone}`}>{activeStatuses.has(key) && <i/>}{statusLabels[key] || status}</span>;
}
function date(value?: string) {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : new Intl.DateTimeFormat('fa-IR', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(parsed);
}
function errorText(error: unknown) { return error instanceof Error ? error.message : 'ارتباط با سرویس برقرار نشد.'; }
function artifacts(run: Run): Artifact[] {
  if (Array.isArray(run.artifacts)) return run.artifacts;
  if (!run.artifacts) return [];
  return Object.entries(run.artifacts).map(([key, value]) => typeof value === 'string' ? { name: key, filename: value } : { name: key, ...(value && typeof value === 'object' ? value : {}) });
}
function CaseTable({ cases, plan = false }: { cases: Case[]; plan?: boolean }) {
  return <div className="table-scroll"><table className="case-table"><thead><tr>
    <th>برنامه / حمله</th><th>{plan ? 'آمادگی' : 'وضعیت / نتیجه'}</th><th>Actuator مورد انتظار</th>{!plan && <th>Actuator مشاهده‌شده</th>}<th>{plan ? 'محدودیت' : 'شواهد / توضیح'}</th>
  </tr></thead><tbody>{cases.map((item, index) => <tr key={`${item.namespace}/${item.id}/${index}`}>
    <td><span className="namespace" dir="ltr">{item.namespace}</span><strong dir="auto">{item.name || item.id}</strong><span className="case-id" dir="ltr">{item.id}</span></td>
    <td><Badge status={plan ? item.benchmarkBlocked || item.armed === false || item.compatible === false ? 'blocked' : item.armed === true && item.compatible === true ? 'ready' : 'unknown' : item.status || (typeof item.outcome === 'string' ? item.outcome : 'pending')}/>
      {!plan && <span className="original-outcome" dir="ltr">{item.outcome ? display(item.outcome) : 'Outcome: unavailable'}</span>}
      {!plan && <span className="actuation-flag" dir="ltr">actuated: {typeof item.actuated === 'boolean' ? String(item.actuated) : 'unknown'}</span>}
    </td>
    <td><code>{display(item.expectedActuator)}</code></td>
    {!plan && <td><code>{display(item.observedActuator || item.action)}</code></td>}
    <td className="evidence-cell"><span dir="auto">{item.error || (item.errors?.length ? item.errors.map(display).join(' · ') : '') || (item.benchmarkBlocked ? display(item.benchmarkBlockReason) : '') || item.reason || item.limitations?.join(' · ') || (!plan ? (item.resultId ? `Result: ${item.resultId}` : 'در انتظار رکورد مشاهده') : '—')}</span>
      {!plan && item.evidenceStatus && <div><Badge status={item.evidenceStatus}/></div>}
      {!plan && Boolean(item.evidenceKind || item.result?.evidenceKind) && <span className="original-outcome" dir="ltr">{display(item.evidenceKind || item.result?.evidenceKind)}</span>}
      {!plan && item.evidenceCounts && <details><summary>پوشش شواهد</summary><pre dir="ltr">{JSON.stringify(item.evidenceCounts, null, 2)}</pre></details>}
      {!plan && item.evidence != null && <details><summary>رکورد شواهد</summary><pre dir="ltr">{JSON.stringify(item.evidence, null, 2)}</pre></details>}
      {!plan && item.result && <details><summary>رکورد اصلی نتیجه</summary><pre dir="ltr">{JSON.stringify(item.result, null, 2)}</pre></details>}
      {!plan && item.outcome && typeof item.outcome === 'object' && <details><summary>نتیجه ثبت‌شده</summary><pre dir="ltr">{JSON.stringify(item.outcome, null, 2)}</pre></details>}
    </td>
  </tr>)}</tbody></table>{cases.length === 0 && <div className="empty-inline">هنوز رکوردی برای این اجرا ثبت نشده است.</div>}</div>;
}

export default function Dashboard() {
  const [auth, setAuth] = useState<'checking' | 'in' | 'out'>('checking');
  const [password, setPassword] = useState('');
  const [meta, setMeta] = useState<Meta | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const [run, setRun] = useState<Run | null>(null);
  const [events, setEvents] = useState<Event[]>([]);
  const [view, setView] = useState<'new' | 'history' | 'run'>('new');
  const [mode, setMode] = useState<Mode>('serial');
  const [model, setModel] = useState('');
  const [request, setRequest] = useState('');
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
  async function makePlan(event: React.FormEvent) {
    event.preventDefault(); setBusy('plan'); setError(''); setPlan(null);
    try { setPlan(await api<Plan>('/plans', { method: 'POST', body: JSON.stringify({ mode, model, request: request.trim(), context: context.trim(), applications: selectedApps }) }, 165_000)); }
    catch (cause) { handleError(cause); } finally { setBusy(null); }
  }
  async function launch() {
    if (!plan || busy) return;
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
    <section className="login-card"><span className="eyebrow">PHORVEX / BENCHMARK LAB</span><h1>شواهد واقعی،<br/>تصمیم روشن.</h1><p>اجرای حمله‌های Live، بررسی تصمیم‌های دفاعی و دریافت داده‌های خام بنچمارک.</p>
      {auth === 'checking' ? <div className="loading-line"><span className="spinner"/>بررسی نشست…</div> : <form onSubmit={login}><label htmlFor="password">رمز ورود داشبورد</label><div className="password-field"><Icon name="key"/><input id="password" type="password" autoComplete="current-password" required maxLength={256} value={password} onChange={event => setPassword(event.target.value)} placeholder="رمز ورود"/></div>{error && <div role="alert" className="notice error">{error}</div>}<button className="button primary full" disabled={!!busy || !password}>{busy === 'login' ? <span className="spinner"/> : <Icon name="arrow"/>}ورود به آزمایشگاه</button></form>}
      <span className="login-foot">اتصال امن به خوشه و شواهد ثبت‌شدهٔ اجرا</span>
    </section></main>;

  const active = runs.find(item => activeStatuses.has(item.status.toLowerCase()));
  const grafanaUrl = safeExternalUrl(run?.grafanaUrl || meta?.grafanaUrl);
  const visibleArtifacts = run ? artifacts(run).filter(item => typeof item === 'string' || item.available !== false) : [];
  const completed = run?.progress?.completed || 0;
  const total = run?.progress?.total || run?.cases?.length || 0;

  return <div className="app-shell"><aside className="sidebar"><a className="brand" href="/" dir="ltr"><span className="brand-mark"><Icon name="lab" size={24}/></span><span>Phorvex<small>BENCHMARK LAB</small></span></a>
    <nav aria-label="منوی اصلی"><span className="nav-label">آزمایشگاه</span><button className={view === 'new' ? 'nav-item selected' : 'nav-item'} onClick={() => { setView('new'); setError(''); }}><Icon name="lab"/>بنچمارک جدید</button><button className={view === 'history' ? 'nav-item selected' : 'nav-item'} onClick={() => { setView('history'); setError(''); }}><Icon name="history"/>تاریخچه اجراها<span className="nav-count">{runs.length}</span></button>{runId.current && <button className={view === 'run' ? 'nav-item selected' : 'nav-item'} onClick={() => setView('run')}><Icon name="layers"/>جزئیات اجرای انتخابی</button>}</nav>
    <div className="sidebar-bottom"><div className="scope-note"><Icon name="shield"/><div>خوشهٔ متصل<small>Live catalogue · raw evidence</small></div></div><button className="nav-item logout" disabled={!!busy} onClick={logout}><Icon name="logout"/>خروج</button></div>
  </aside><div className="workspace"><header className="topbar"><div className="breadcrumb"><span>آزمایشگاه</span><span className="slash">/</span><strong>{view === 'new' ? 'بنچمارک جدید' : view === 'history' ? 'تاریخچه اجراها' : 'جزئیات اجرا'}</strong></div><div className="topbar-right"><span className="version-pill"><span className="dot"/>نسخه جاری <code>{versionLabel(meta?.version)}</code></span><button className="icon-button" title="تازه‌سازی وضعیت" aria-label="تازه‌سازی وضعیت" onClick={() => { setError(''); void refresh().catch(handleError); }}><Icon name="refresh" size={17}/></button></div></header>
    <main className="main-content">{error && <div className="notice error" role="alert"><strong>نیاز به بررسی</strong><span dir="auto">{error}</span><button aria-label="بستن پیام" onClick={() => setError('')}>×</button></div>}
    {(meta?.errors || []).length > 0 && <div className="notice warning"><strong>وضعیت اتصال و کاتالوگ</strong><ul>{meta?.errors?.map((item,index) => <li key={index} dir="auto">{display(item)}</li>)}</ul></div>}
    {view === 'new' && <><div className="page-heading"><div><span className="eyebrow">LIVE SECURITY BENCHMARKS</span><h1>آزمایش، با شواهد.</h1><p>حمله‌ها را اجرا کنید؛ تصمیم دفاعی، هزینه و نتیجه را دقیق بررسی کنید.</p></div><span className="heading-symbol"><Icon name="lab" size={34}/></span></div>
      {active && <div className="notice info"><span><Badge status={active.status}/> یک بنچمارک فعال در خوشه وجود دارد.</span><button className="text-button" onClick={() => void selectRun(active.id)}>مشاهده اجرا <Icon name="arrow" size={15}/></button></div>}
      <div className="configure-grid"><form className="panel configure-panel" onSubmit={makePlan}><div className="panel-heading"><span className="step-number">۱</span><div><h2>تعریف بنچمارک</h2><p>هدف و زمینهٔ آزمون را مشخص کنید.</p></div></div><fieldset className="form-fields" disabled={busy === 'plan' || busy === 'launch'}>
        <fieldset className="field-group"><legend>روش اجرای پایپ‌لاین</legend><div className="mode-options">{(['serial', 'parallel'] as Mode[]).map(value => <button key={value} type="button" aria-pressed={mode === value} className={`mode-card ${mode === value ? 'chosen' : ''}`} onClick={() => { setMode(value); clearPlan(); }}><span className="mode-icon"><Icon name={value}/></span><span><strong>{value === 'serial' ? 'سریال' : 'موازی'} <small dir="ltr">{value === 'serial' ? 'Serial' : 'Parallel'}</small></strong><em>{value === 'serial' ? 'حمله‌ها یکی پس از دیگری' : 'برنامه‌ها هم‌زمان؛ ترتیب حمله در هر برنامه'}</em></span><span className="radio-dot"/></button>)}</div></fieldset>
        <div className="field-group"><label htmlFor="model">مدل برنامه‌ریز <span>LLM</span></label><select id="model" dir="ltr" required value={model} disabled={!meta || !!busy} onChange={event => { setModel(event.target.value); clearPlan(); }}><option value="" disabled>{meta ? 'Select model' : 'Loading models…'}</option>{(meta?.models || []).map(item => <option key={modelId(item)} value={modelId(item)}>{modelLabel(item)}</option>)}</select></div>
        <div className="field-group"><label htmlFor="request">چه بنچمارکی نیاز دارید؟</label><textarea id="request" rows={3} required maxLength={8000} value={request} onChange={event => { setRequest(event.target.value); clearPlan(); }} placeholder="مثلاً: عملکرد آخرین نسخه در برابر تمام حمله‌های Live و انتخاب Actuator مناسب را بررسی کن."/><span className="field-hint">هدف آزمون و معیارهایی که می‌خواهید بررسی شوند.</span></div>
        <div className="field-group"><label htmlFor="context">زمینه و توضیحات <span>اختیاری</span></label><textarea id="context" rows={3} maxLength={16000} value={context} onChange={event => { setContext(event.target.value); clearPlan(); }} placeholder="تنظیمات، سناریوی مورد نظر یا توضیحاتی برای تفسیر نتایج…"/></div>
        <fieldset className="field-group"><legend>برنامه‌های هدف <span className="field-hint">تمام حمله‌های کاتالوگ برای هر چهار برنامه بررسی می‌شوند.</span></legend><div className="app-options">{(meta?.applications || []).map(app => <span key={namespace(app)} className="app-chip checked"><span className="chip-check"><Icon name="check" size={12}/></span><span dir="ltr">{appLabel(app)}</span></span>)}</div>{!meta && <span className="field-hint">دریافت برنامه‌های متصل…</span>}</fieldset>
        <div className="form-footer"><span>طرح اجرا پیش از شروع نمایش داده می‌شود.</span><button className="button primary" disabled={!!busy || !meta || !model || !request.trim() || !selectedApps.length}>{busy === 'plan' ? <span className="spinner"/> : <Icon name="arrow" size={18}/>} {busy === 'plan' ? 'ساخت طرح…' : 'ساخت طرح بنچمارک'}</button></div>
      </fieldset></form><aside className="context-column"><div className="evidence-card"><span className="eyebrow">FROM ATTACK TO EVIDENCE</span><h2>هر نتیجه،<br/>یک مسیر قابل بررسی.</h2><div className="evidence-path"><div><span>01</span><p>حملهٔ واقعی<small>از کاتالوگ Live برنامه‌ها</small></p></div><div><span>02</span><p>تصمیم و عمل<small>انتخاب، dispatch و مشاهدهٔ نتیجه</small></p></div><div><span>03</span><p>خروجی قابل بررسی<small>Excel خام و شواهد در Grafana</small></p></div></div></div>
        <div className="panel export-info"><Icon name="file" size={24}/><h3>دو خروجی، یک اجرای ثبت‌شده</h3><p>هزینهٔ اندازه‌گیری‌شده در برابر هزینهٔ مورد انتظار</p><code>Cost Measured vs Expected</code><p>تصمیم‌ها و گیت‌های هر Tick / Action</p><code>Tick Action Gates</code><span className="field-hint">دادهٔ ناموجود و محدودیت اندازه‌گیری در گزارش مشخص می‌شود.</span></div>
      </aside></div>
      {plan && <section className="panel plan-panel"><div className="panel-heading"><span className="step-number">۲</span><div><h2>طرح آمادهٔ اجرا</h2><p>{plan.summary}</p></div><span className="badge neutral">{plan.cases.length} حمله</span></div>{(plan.limitations || []).length > 0 && <div className="notice warning"><strong>محدودیت‌های طرح</strong><ul>{plan.limitations?.map((item, index) => <li key={index} dir="auto">{item}</li>)}</ul></div>}<CaseTable cases={plan.cases} plan/><div className="plan-footer"><span>اجرای Live روی {plan.applications.join('، ')} · {plan.mode === 'serial' ? 'سریال' : 'موازی'}</span><button className="button primary" disabled={!!busy || !!active || !plan.cases.length} onClick={() => void launch()}>{busy === 'launch' ? <span className="spinner"/> : <Icon name="play" size={16}/>}شروع بنچمارک</button></div></section>}
    </>}
    {view === 'history' && <><div className="page-heading"><div><span className="eyebrow">RUN HISTORY</span><h1>اجراهای ثبت‌شده</h1><p>نسخه، وضعیت و خروجی هر بنچمارک را از اینجا بررسی کنید.</p></div><button className="button primary" onClick={() => setView('new')}><Icon name="lab" size={18}/>بنچمارک جدید</button></div><section className="panel history-panel">{runs.length === 0 ? <div className="empty-state"><Icon name="history" size={40}/><h2>هنوز اجرایی ثبت نشده است.</h2><p>اولین بنچمارک را تعریف کنید تا شواهد آن اینجا ثبت شود.</p><button className="button secondary" onClick={() => setView('new')}>تعریف بنچمارک</button></div> : runs.map(item => <button key={item.id} className="history-row" onClick={() => void selectRun(item.id)}><span className="history-icon"><Icon name={item.mode === 'parallel' ? 'parallel' : 'serial'}/></span><span className="history-title"><strong>{item.request || 'بنچمارک Live'}</strong><small><span dir="ltr">{item.id}</span> · {date(item.startedAt || item.createdAt)}</small></span><span className="history-meta"><code>{item.model}</code><span>{item.mode === 'parallel' ? 'موازی' : 'سریال'}</span></span><Badge status={item.status}/><Icon name="arrow" size={18}/></button>)}</section></>}
    {view === 'run' && (run ? <><div className="page-heading run-heading"><div><span className="eyebrow">BENCHMARK RUN</span><h1>{run.request || 'بنچمارک Live'}</h1><p><code>{run.id}</code><span className="inline-separator">·</span>{date(run.startedAt || run.createdAt)}</p></div><div className="heading-actions"><Badge status={run.status}/>{activeStatuses.has(run.status.toLowerCase()) && <button className="button danger-outline" disabled={!!busy} onClick={() => void cancel()}><Icon name="stop" size={15}/>{busy === 'cancel' ? 'در حال درخواست توقف…' : 'توقف اجرا'}</button>}</div></div>
      <section className="run-overview"><div className="panel progress-card"><span className="stat-label">پیشرفت حمله‌ها</span><strong><span>{completed}</span><small> / {total}</small></strong><div className="progress-track" role="progressbar" aria-valuemin={0} aria-valuemax={total || 1} aria-valuenow={Math.min(completed,total)}><div style={{width: `${total ? Math.min(100, completed / total * 100) : 0}%`}}/></div><span className="field-hint">پایان اجرا، به‌تنهایی تأیید دفاع نیست.</span></div><div className="panel run-stat"><span className="stat-label">پایپ‌لاین / مدل</span><strong>{run.mode === 'parallel' ? 'موازی' : 'سریال'}</strong><code>{run.model}</code></div><div className="panel run-stat"><span className="stat-label">نسخهٔ ثبت‌شده</span><strong dir="ltr">{versionLabel(run.version)}</strong><span className="field-hint">{run.finishedAt ? `پایان: ${date(run.finishedAt)}` : 'در انتظار پایان اجرا'}</span></div></section>
      <div className="results-toolbar"><div><h2>حمله‌ها و تصمیم‌های مشاهده‌شده</h2><p>انتخاب Actuator، اجرای عمل و تأیید اثر در شواهد جداگانه ثبت می‌شوند.</p></div>{grafanaUrl && <a className="button secondary" href={grafanaUrl} target="_blank" rel="noopener noreferrer"><Icon name="external" size={16}/>مشاهده در Grafana</a>}</div><section className="panel"><CaseTable cases={run.cases || []}/></section>
      <div className="run-bottom-grid"><section className="panel artifacts-panel"><div className="panel-heading"><Icon name="download"/><div><h2>فایل‌های بنچمارک</h2><p>دریافت خروجی با قالب‌های خام Excel</p></div></div>{visibleArtifacts.length ? visibleArtifacts.map((artifact, index) => { const name = typeof artifact === 'string' ? artifact : artifact.name; return <a key={`${name}/${index}`} className="artifact-link" href={`/api/runs/${encodeURIComponent(run.id)}/artifacts/${encodeURIComponent(name)}`}><span className="file-icon"><Icon name="file"/></span><span><strong>{typeof artifact === 'string' ? artifact : artifact.label || artifact.filename || name}</strong><small>خروجی این اجرا</small></span><Icon name="download" size={18}/></a>; }) : <div className="empty-inline">فایل‌ها پس از ثبت و پردازش شواهد در دسترس قرار می‌گیرند.</div>}</section>
        <section className="panel events-panel"><div className="panel-heading"><Icon name="layers"/><div><h2>رویدادهای اجرا</h2><p>آخرین وضعیت‌های ثبت‌شده</p></div></div><div className="event-list">{events.length ? events.map((event,index) => <div className={`event-row ${event.level}`} key={`${event.time}/${index}`}><time>{date(event.time)}</time><span dir="auto">{event.message}</span></div>) : <div className="empty-inline">در انتظار رویداد…</div>}</div></section></div>
      {(run.errors || []).length > 0 && <section className="notice warning"><strong>محدودیت‌ها و خطاهای ثبت‌شده</strong><ul>{run.errors?.map((item,index) => <li key={index} dir="auto">{display(item)}</li>)}</ul></section>}
    </> : <div className="empty-state"><span className="spinner"/><p>دریافت جزئیات اجرا…</p></div>)}
    <footer className="page-footer"><span dir="ltr">PHORVEX BENCHMARK LAB</span><span>{updatedAt ? `آخرین دریافت وضعیت: ${date(updatedAt)}` : 'در حال دریافت وضعیت سرویس'}</span></footer>
    </main></div></div>;
}

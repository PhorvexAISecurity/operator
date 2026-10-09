'use client';

import { useState } from 'react';

// Small, dependency-free SVG charts for the Math Lab. One y-axis per chart, hairline grid,
// thin marks, a hover tooltip on every mark, and a legend whenever there are two series.
// Categorical colors are the validated reference order (slots 1-5) and follow the entity,
// never its rank. Every chart is paired with a table view by its caller.

export const SERIES = ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4'];
const INK = '#172f35';
const MUTED = '#718287';
const GRID = '#e3e9eb';

export interface Point { key: string; label: string; value: number | null; low?: number | null; high?: number | null; n?: number | null; control?: boolean; note?: string }

function niceTicks(min: number, max: number, count = 4): number[] {
  if (!(isFinite(min) && isFinite(max))) return [];
  if (min === max) { const pad = Math.abs(min) || 1; min -= pad / 2; max += pad / 2; }
  const step0 = (max - min) / count;
  const mag = Math.pow(10, Math.floor(Math.log10(step0)));
  const step = [1, 2, 2.5, 5, 10].map(m => m * mag).find(s => s >= step0) || step0;
  const start = Math.floor(min / step + 1e-9) * step;
  const end = Math.ceil(max / step - 1e-9) * step;
  const out: number[] = [];
  for (let v = start; v <= end + step * 1e-9; v += step) out.push(Number(v.toPrecision(12)));
  return out;
}
export function fmt(v: number | null | undefined, digits = 3): string {
  if (v === null || v === undefined || !isFinite(v)) return '—';
  if (v !== 0 && (Math.abs(v) >= 1e4 || Math.abs(v) < 1e-3)) return v.toExponential(2);
  return Number(v.toPrecision(digits)).toLocaleString('en-US', { maximumFractionDigits: 6 });
}

function Tooltip({ x, y, children }: { x: number; y: number; children: React.ReactNode }) {
  return <div className="viz-tooltip" style={{ left: x, top: y }} role="status">{children}</div>;
}

// Dot + interval per category (PL-01 dose-response, PL-09 paired difference).
export function DotWhisker({ points, unit, zeroLine = false, watermark }: { points: Point[]; unit: string; zeroLine?: boolean; watermark: string }) {
  const [hover, setHover] = useState<{ i: number; x: number; y: number } | null>(null);
  const W = 920, H = 300, L = 64, R = 16, T = 26, B = 54;
  const shown = points.filter(p => p.value !== null);
  if (!shown.length) return <div className="viz-empty">No observed values for this metric.</div>;
  const lows = shown.map(p => p.low ?? p.value as number), highs = shown.map(p => p.high ?? p.value as number);
  let lo = Math.min(...lows, zeroLine ? 0 : Infinity), hi = Math.max(...highs, zeroLine ? 0 : -Infinity);
  if (!zeroLine && lo >= 0 && lo / (hi || 1) < .5) lo = 0;
  const ticks = niceTicks(lo, hi);
  const y0 = ticks[0] ?? lo, y1 = ticks[ticks.length - 1] ?? hi;
  const sy = (v: number) => T + (H - T - B) * (1 - (v - y0) / ((y1 - y0) || 1));
  const band = (W - L - R) / points.length;
  const sx = (i: number) => L + band * (i + .5);
  return <div className="viz" onPointerLeave={() => setHover(null)}>
    <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`${watermark} chart`}>
      {ticks.map(t => <g key={t}><line x1={L} x2={W - R} y1={sy(t)} y2={sy(t)} stroke={GRID} strokeWidth={1}/><text x={L - 8} y={sy(t) + 4} textAnchor="end" fontSize={11} fill={MUTED}>{fmt(t)}</text></g>)}
      {zeroLine && <line x1={L} x2={W - R} y1={sy(0)} y2={sy(0)} stroke={INK} strokeWidth={1}/>}
      <text x={W - R} y={12} textAnchor="end" fontSize={10} fill={MUTED} letterSpacing={.6}>{watermark}</text>
      <text x={12} y={(T + H - B) / 2} fontSize={11} fill={MUTED} transform={`rotate(-90 12 ${(T + H - B) / 2})`} textAnchor="middle">{unit}</text>
      {points.map((p, i) => {
        if (p.value === null) return <text key={p.key} x={sx(i)} y={(T + H - B) / 2} textAnchor="middle" fontSize={11} fill={MUTED}>n/a</text>;
        const color = p.control ? INK : SERIES[0];
        return <g key={p.key} tabIndex={0} onFocus={() => setHover({ i, x: sx(i), y: sy(p.value as number) })} onPointerEnter={() => setHover({ i, x: sx(i), y: sy(p.value as number) })}>
          <rect x={sx(i) - Math.max(12, band / 2 - 4)} y={T} width={Math.max(24, band - 8)} height={H - T - B} fill="transparent"/>
          {p.low != null && p.high != null && <line x1={sx(i)} x2={sx(i)} y1={sy(p.low)} y2={sy(p.high)} stroke={color} strokeWidth={2} strokeLinecap="round"/>}
          <circle cx={sx(i)} cy={sy(p.value as number)} r={5} fill={color} stroke="#fff" strokeWidth={2}/>
          <text x={sx(i)} y={H - B + 18} textAnchor="middle" fontSize={11} fill={INK}>{p.label.length > 16 ? p.label.slice(0, 15) + '…' : p.label}</text>
          <text x={sx(i)} y={H - B + 33} textAnchor="middle" fontSize={10} fill={MUTED}>n={p.n ?? '—'}</text>
        </g>;
      })}
    </svg>
    {hover && (() => { const p = points[hover.i]; return <Tooltip x={(hover.x / W) * 100} y={(hover.y / H) * 100}><strong>{fmt(p.value, 4)}</strong>{p.low != null && <span>95% [{fmt(p.low, 4)}, {fmt(p.high, 4)}]</span>}<span>{p.label}{p.control ? ' · control' : ''} · n={p.n ?? '—'}</span>{p.note && <span>{p.note}</span>}</Tooltip>; })()}
    <div className="viz-legend"><span><i className="key dot" style={{ background: INK }}/>Recorded control</span><span><i className="key dot" style={{ background: SERIES[0] }}/>Replayed arm</span><span><i className="key whisker"/>95% interval</span></div>
  </div>;
}

// Horizontal bars, one or two series (PL-08 gate funnel: control vs selected arm).
export function GroupedBars({ rows, series }: { rows: { label: string; values: number[] }[]; series: string[] }) {
  const [hover, setHover] = useState<{ r: number; s: number; y: number } | null>(null);
  const W = 920, L = 210, R = 70, row = 14 * series.length + 14;
  const H = rows.length * row + 8;
  const max = Math.max(1, ...rows.flatMap(r => r.values));
  const sx = (v: number) => (W - L - R) * (v / max);
  const color = (s: number) => series.length === 1 ? SERIES[0] : (s === 0 ? '#9fb0b4' : SERIES[0]);
  return <div className="viz" onPointerLeave={() => setHover(null)}>
    <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Gate funnel">
      <line x1={L} x2={L} y1={0} y2={H} stroke={GRID}/>
      {rows.map((r, i) => <g key={r.label}>
        <text x={L - 8} y={i * row + row / 2 + 4} textAnchor="end" fontSize={11} fill={INK}>{r.label}</text>
        {r.values.map((v, s) => { const y = i * row + 6 + s * 14; return <g key={s} tabIndex={0} onFocus={() => setHover({ r: i, s, y })} onPointerEnter={() => setHover({ r: i, s, y })}>
          <rect x={L} y={y - 4} width={W - L} height={18} fill="transparent"/>
          {v > 0 && <rect x={L} y={y} width={Math.max(2, sx(v))} height={11} rx={2} fill={color(s)}/>}
          <text x={L + sx(v) + 6} y={y + 9} fontSize={10} fill={MUTED}>{v.toLocaleString('en-US')}</text></g>; })}
      </g>)}
    </svg>
    {hover && <Tooltip x={((L + sx(rows[hover.r].values[hover.s])) / W) * 100} y={(hover.y / H) * 100}><strong>{rows[hover.r].values[hover.s].toLocaleString('en-US')}</strong><span>{rows[hover.r].label} · {series[hover.s]}</span></Tooltip>}
    {series.length > 1 && <div className="viz-legend">{series.map((name, s) => <span key={name}><i className="key bar" style={{ background: color(s) }}/>{name}</span>)}</div>}
  </div>;
}

// 100% stacked bars per arm for a small fixed category set (G9 categories, no-op reasons).
export function StackedShares({ rows, categories }: { rows: { label: string; counts: Record<string, number> }[]; categories: string[] }) {
  const [hover, setHover] = useState<{ r: number; c: string; x: number; y: number } | null>(null);
  const W = 920, L = 150, R = 16, rowH = 28, H = rows.length * rowH + 6;
  const cats = categories.slice(0, SERIES.length);
  return <div className="viz" onPointerLeave={() => setHover(null)}>
    <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Category shares by arm">
      {rows.map((r, i) => { const total = cats.reduce((s, c) => s + (r.counts[c] || 0), 0) || 1; let x = L; const y = i * rowH + 8;
        return <g key={r.label}><text x={L - 8} y={y + 12} textAnchor="end" fontSize={11} fill={INK}>{r.label.length > 15 ? r.label.slice(0, 14) + '…' : r.label}</text>
          {cats.map((c, ci) => { const w = (W - L - R) * (r.counts[c] || 0) / total; const x0 = x; x += w; if (w <= 0) return null;
            return <g key={c} tabIndex={0} onFocus={() => setHover({ r: i, c, x: x0 + w / 2, y })} onPointerEnter={() => setHover({ r: i, c, x: x0 + w / 2, y })}>
              <rect x={x0} y={y} width={Math.max(0, w - 2)} height={16} fill={SERIES[ci]} rx={ci === 0 ? 3 : 0}/></g>; })}</g>; })}
    </svg>
    {hover && (() => { const r = rows[hover.r]; const total = cats.reduce((s, c) => s + (r.counts[c] || 0), 0); const v = r.counts[hover.c] || 0;
      return <Tooltip x={(hover.x / W) * 100} y={(hover.y / H) * 100}><strong>{v.toLocaleString('en-US')} ({total ? Math.round(100 * v / total) : 0}%)</strong><span>{hover.c} · {r.label}</span></Tooltip>; })()}
    <div className="viz-legend">{cats.map((c, ci) => <span key={c}><i className="key bar" style={{ background: SERIES[ci] }}/>{c}</span>)}</div>
  </div>;
}

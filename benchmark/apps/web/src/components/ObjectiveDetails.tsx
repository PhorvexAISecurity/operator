import type { ObjectiveSummary } from '@/lib/api';

function modeLabel(mode: string | null) {
  switch (mode) {
    case 'legacy-runtime-lambda-v1': return 'Legacy (runtime lambda)';
    case 'fixed-disruption-aversion-v1': return 'Fixed Beta (disruption aversion)';
    case 'independent-cost-preferences-v1': return 'Independent cost preferences';
    case null: return 'Not recorded';
    default: return 'Other objective';
  }
}
function decisions(count: number) { return `${count.toLocaleString('en-US')} ${count === 1 ? 'decision' : 'decisions'}`; }
function modeDescription(mode: string | null) {
  return <>{modeLabel(mode)}{mode !== null && <> · <code>{mode}</code></>}</>;
}

export default function ObjectiveDetails({ summary, compact = false }: { summary?: ObjectiveSummary; compact?: boolean }) {
  const waiting = summary?.state === 'pending' ? 'Calculated after the run finishes'
    : summary?.state === 'calculating' ? 'Calculating objective summary…' : undefined;
  if (waiting) {
    if (compact) return <span className="history-objective" dir="ltr"><span className="version-field-label">Objective mode: </span>{waiting}</span>;
    return <section className="panel objective-details" aria-label="Run objective" dir="ltr">
      <div className="objective-field" role="region" aria-label="Objective mode"><span className="stat-label">Objective mode</span><span>{waiting}</span></div>
      <div className="objective-field" role="region" aria-label="Effective cost coefficient"><span className="stat-label">Effective cost coefficient</span><span>{waiting}</span></div>
    </section>;
  }
  const modes = summary?.modes || [];
  const recorded = modes.filter(mode => mode.objectiveMode !== null);
  const mixed = Boolean(summary?.mixedModes) || recorded.length > 1;
  const hasAdditionalModes = Boolean(summary?.unlistedModeCount);
  const partial = Boolean(summary?.skippedRecordCount);
  if (compact) return <span className="history-objective" dir="ltr">
    <span className="version-field-label">Objective mode: </span>
    {mixed ? 'Mixed' : recorded.length ? modeLabel(recorded[0].objectiveMode) : hasAdditionalModes ? 'Additional modes recorded' : 'Not recorded'}
    {hasAdditionalModes && recorded.length > 0 && ' · additional modes'}
    {recorded.length > 0 && modes.some(mode => mode.objectiveMode === null) && ' · some not recorded'}
    {partial && ' · partial summary'}
  </span>;

  return <section className="panel objective-details" aria-label="Run objective" dir="ltr">
    <div className="objective-field" role="region" aria-label="Objective mode">
      <span className="stat-label">Objective mode</span>
      {mixed && <strong className="objective-mixed">Mixed objective modes</strong>}
      {modes.length ? <ul>{modes.map((mode, index) => <li key={index}>
        {modeDescription(mode.objectiveMode)} <span className="objective-count">· {decisions(mode.count)}</span>
      </li>)}</ul> : <span>{hasAdditionalModes ? 'Additional modes recorded' : 'Not recorded'}</span>}
      {hasAdditionalModes && <p className="field-hint">Additional objective modes: {decisions(summary!.unlistedModeCount)}. Summary display limit reached.</p>}
    </div>
    <div className="objective-field" role="region" aria-label="Effective cost coefficient">
      <span className="stat-label">Effective cost coefficient</span>
      {summary?.coefficients.length ? <ul>{summary.coefficients.map((group, index) => <li key={index}>
        <span className="objective-coefficient">{group.min === null || group.max === null ? 'Not recorded' : group.min === group.max ? String(group.min) : `${group.min}–${group.max} (min–max)`}</span>
        <span className="objective-count"> · {decisions(group.count)}</span>
        <span className="objective-source">Source: <code>{group.source ?? 'Not recorded'}</code></span>
        {(mixed || group.objectiveMode === null) && <span className="objective-source">Objective mode: {modeDescription(group.objectiveMode)}</span>}
      </li>)}</ul> : <span>{summary?.unlistedCoefficientCount ? 'Additional coefficient groups recorded' : 'Not recorded'}</span>}
      {Boolean(summary?.unlistedCoefficientCount) && <p className="field-hint">Additional coefficient groups: {decisions(summary!.unlistedCoefficientCount)}. Summary display limit reached.</p>}
    </div>
    <p className="field-hint objective-coverage">{summary?.decisionCount ? `${decisions(summary.decisionCount)} retained in the run window.` : 'No retained decision traces recorded.'}
      {partial && ` ${summary!.skippedRecordCount.toLocaleString('en-US')} retained records or files could not be summarized; the counts above are partial.`}</p>
  </section>;
}

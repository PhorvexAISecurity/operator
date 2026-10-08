import { activeStatuses, type Case, type Run } from './api';

// Request text is display data; only its first non-empty line supplies the title.
export function splitBenchmarkRequest(request?: string) {
  const lines = (request || '').split(/\r\n?|\n/);
  const first = lines.findIndex(line => line.trim());
  if (first < 0) return { title: 'Live benchmark', description: '' };

  const line = lines[first].trim();
  const heading = /^ {0,3}#{1,6}(?:[ \t]+|$)(.*)$/.exec(lines[first]);
  let title = heading ? heading[1].replace(/(?:^|[ \t]+)#+[ \t]*$/, '').trim() : line;
  const characters = Array.from(title);
  if (!heading && characters.length > 120) {
    const prefix = characters.slice(0, 119).join('');
    const wholeWords = /\s/.test(characters[119]) ? prefix : prefix.replace(/\s+\S*$/, '');
    title = `${wholeWords.trimEnd()}…`;
  }
  return { title: title || 'Live benchmark', description: lines.slice(first + 1).join('\n') };
}

export function readiness(item: Case): 'ready' | 'blocked' | 'unknown' {
  if (item.benchmarkBlocked || item.armed === false || item.compatible === false) return 'blocked';
  return item.armed === true && item.compatible === true ? 'ready' : 'unknown';
}

export function readinessReason(item: Case) {
  const reasons = [];
  if (item.armed === false) reasons.push('Not armed');
  if (item.compatible === false) reasons.push('Not compatible');
  if (item.benchmarkBlocked) reasons.push('Benchmark block; see limitation');
  if (readiness(item) === 'unknown') reasons.push('Readiness flags not recorded');
  return reasons.join(' · ');
}

export function readinessCounts(cases: Case[]) {
  const counts = { ready: 0, blocked: 0, unknown: 0 };
  for (const item of cases) counts[readiness(item)]++;
  return `${counts.ready} ready · ${counts.blocked} blocked${counts.unknown ? ` · ${counts.unknown} unknown` : ''} of ${cases.length}`;
}

// These are retained rows, not per-application completion or defense counts.
export function appRecords(run: Run) {
  const byApp = new Map((run.applications || []).map(app => [app, 0]));
  for (const item of run.cases || []) byApp.set(item.namespace, (byApp.get(item.namespace) || 0) + 1);
  return [...byApp.entries()].sort((a, b) => a[0].localeCompare(b[0]));
}

export function progressMessage(run: Run) {
  const status = run.status.toLowerCase();
  if (status === 'queued') return 'Queued; waiting to start.';
  if (['cancelling', 'cancel_requested'].includes(status)) return 'Stopping new launches; observing accepted cases.';
  if (['starting', 'planning'].includes(status)) return 'Preparing; an estimate appears after cases finish.';
  if (activeStatuses.has(status)) return 'In progress; an estimate appears after cases finish.';
  if (['completed', 'complete', 'succeeded'].includes(status)) return 'Run finished; scheduling and export have ended.';
  if (['cancelled', 'aborted'].includes(status)) return 'Run stopped; progress reflects retained completion.';
  if (['failed', 'error'].includes(status)) return 'Run failed; inspect retained limitations and errors.';
  if (status === 'interrupted') return 'Run interrupted; inspect retained records before reconciliation.';
  if (status === 'blocked') return 'Run blocked; inspect the recorded reason.';
  return 'Progress reflects the last reported case completion.';
}

import { constants, createReadStream } from 'node:fs';
import { chmod, mkdir, open, readdir, readFile, realpath, rename, stat, unlink } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { join, resolve, sep } from 'node:path';
import { setImmediate as yieldEventLoop } from 'node:timers/promises';

const MAX_MODES = 32;
const MAX_COEFFICIENT_GROUPS = 64;
const MAX_LABEL_LENGTH = 256;
const MAX_LINE_BYTES = 8 * 1024 * 1024;
const MAX_CACHED_RUNS = 200;
const MAX_CACHE_BYTES = 512 * 1024;
export const OBJECTIVE_SCHEMA_VERSION = 1;
const TERMINAL_STATUSES = new Set(['completed', 'incomplete', 'failed', 'cancelled', 'interrupted']);
export function isTerminalRun(status: string) { return TERMINAL_STATUSES.has(status); }

type RecordValue = Record<string, unknown>;
export interface ObjectiveSummary {
  state: 'ready' | 'pending' | 'calculating';
  decisionCount: number;
  mixedModes: boolean;
  modes: { objectiveMode: string | null; count: number }[];
  coefficients: { objectiveMode: string | null; source: string | null; min: number | null; max: number | null; count: number }[];
  unlistedModeCount: number;
  unlistedCoefficientCount: number;
  skippedRecordCount: number;
}
export function emptyObjectiveSummary(state: ObjectiveSummary['state'] = 'ready'): ObjectiveSummary {
  return { state, decisionCount: 0, mixedModes: false, modes: [], coefficients: [], unlistedModeCount: 0, unlistedCoefficientCount: 0, skippedRecordCount: 0 };
}
function object(value: unknown): RecordValue | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as RecordValue : undefined;
}
function recordedText(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null;
}
function coefficient(value: unknown): number | null {
  const optional = object(value);
  if (optional) value = optional.present === true ? optional.value : null;
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/** Only the actual trace fields participate; request text and policy seeds are never inputs. */
export class ObjectiveAccumulator {
  readonly summary = emptyObjectiveSummary();
  private readonly modes = new Map<string | null, ObjectiveSummary['modes'][number]>();
  private readonly coefficients = new Map<string, ObjectiveSummary['coefficients'][number]>();
  private firstRecordedMode?: string;
  add(trace: RecordValue) {
    const mode = recordedText(trace.economicsVersion);
    const source = recordedText(trace.costCoefficientSource);
    const value = coefficient(trace.effectiveCostCoefficient);
    this.summary.decisionCount++;
    if (mode !== null) {
      if (this.firstRecordedMode !== undefined && this.firstRecordedMode !== mode) this.summary.mixedModes = true;
      else this.firstRecordedMode = mode;
    }
    const modeGroup = this.modes.get(mode);
    if (modeGroup) modeGroup.count++;
    else if (mode === null || mode.length <= MAX_LABEL_LENGTH && this.modes.size - Number(this.modes.has(null)) < MAX_MODES) {
      const group = { objectiveMode: mode, count: 1 };
      this.modes.set(mode, group); this.summary.modes.push(group);
    } else this.summary.unlistedModeCount++;
    // Keep missing coefficients separate from recorded numeric ranges, including explicit zero.
    const key = JSON.stringify([mode, source, value === null]);
    const group = this.coefficients.get(key);
    if (group) {
      group.count++;
      if (value !== null) { group.min = Math.min(group.min!, value); group.max = Math.max(group.max!, value); }
    } else if ((mode?.length || 0) <= MAX_LABEL_LENGTH && (source?.length || 0) <= MAX_LABEL_LENGTH && this.coefficients.size < MAX_COEFFICIENT_GROUPS) {
      const next = { objectiveMode: mode, source, min: value, max: value, count: 1 };
      this.coefficients.set(key, next); this.summary.coefficients.push(next);
    } else this.summary.unlistedCoefficientCount++;
  }
}

// Preserve sub-millisecond RFC3339 precision for the exporter's inclusive time window.
function instant(value: unknown): number | undefined {
  if (typeof value !== 'string') return undefined;
  const fraction = /\.(\d+)(?=Z$|[+-]\d{2}:\d{2}$)/.exec(value);
  const milliseconds = Date.parse(fraction ? value.replace(fraction[0], '') : value);
  // Python datetime.fromisoformat in the exporter retains microseconds and truncates finer digits.
  return Number.isFinite(milliseconds) ? milliseconds / 1000 + (fraction ? Number('0.' + fraction[1].slice(0, 6)) : 0) : undefined;
}
interface Bounds { startedAt?: string; finishedAt?: string }
export interface ObjectiveRun extends Bounds { id: string; status: string }
interface RetainedFile { path: string; size: number; stamp: string }
interface Snapshot { files: RetainedFile[]; manifest?: RetainedFile; skipped: number; signature: string }

interface ScanJob {
  owner: ObjectiveSummaryReader;
  allowed: () => boolean;
  scan: () => Promise<void>;
  done: Promise<void>;
  finish: () => void;
}
// Shared by every reader in this process, including requests for different runs.
const jobs = new Map<string, ScanJob>();
let scanning = false;
let activeJob: ScanJob | undefined;
let scheduled = false;
class ScanPaused extends Error {}
function scheduleScans(delay = 0) {
  if (scheduled || scanning || !jobs.size) return;
  scheduled = true;
  const timer = setTimeout(() => { scheduled = false; void drainScans(); }, delay);
  timer.unref();
}
async function drainScans() {
  if (scanning) return;
  const next = [...jobs.entries()].find(([, job]) => job.allowed());
  if (!next) { scheduleScans(1000); return; }
  const [key, job] = next;
  scanning = true; activeJob = job;
  let paused = false;
  try { await job.scan(); }
  catch (error) { paused = error instanceof ScanPaused; }
  finally {
    scanning = false; activeJob = undefined;
    if (!paused || job.owner.closed) {
      if (jobs.get(key) === job) jobs.delete(key);
      job.finish();
    }
    scheduleScans(paused ? 1000 : 0);
  }
}

/** Terminal-only, persistent summaries; requests discover metadata and enqueue work, never stream audits. */
export class ObjectiveSummaryReader {
  readonly cacheDirectory: string;
  closed = false;
  private readonly cache = new Map<string, { signature: string; summary: ObjectiveSummary }>();
  constructor(dataDirectory: string, private readonly canScan: () => boolean = () => true) {
    this.cacheDirectory = resolve(dataDirectory, 'objective-summaries');
  }
  async read(directory: string, run: ObjectiveRun, waitMs = 0): Promise<ObjectiveSummary> {
    // This gate precedes all filesystem access, including discovery and persisted cache lookup.
    if (!isTerminalRun(run.status)) return emptyObjectiveSummary('pending');
    if (this.closed) return emptyObjectiveSummary('calculating');
    if (!/^[a-zA-Z0-9_-]{1,100}$/.test(run.id)) throw new Error('Invalid objective cache run ID');
    const deadline = Date.now() + Math.min(Math.max(waitMs, 0), 2000);
    const snapshot = await this.inspect(directory, run);
    const path = join(this.cacheDirectory, run.id + '.json');
    const cached = await this.cached(path, snapshot.signature);
    if (!isTerminalRun(run.status)) return emptyObjectiveSummary('pending');
    if (cached) return cached;
    if (this.closed) return emptyObjectiveSummary('calculating');
    let job = jobs.get(path);
    if (!job) {
      let finish!: () => void;
      const done = new Promise<void>(resolvePromise => { finish = resolvePromise; });
      job = { owner: this, allowed: () => !this.closed && isTerminalRun(run.status) && this.canScan(), done, finish, scan: async () => {
        await this.yield(run);
        const source = await this.inspect(directory, run);
        if (await this.cached(path, source.signature)) return;
        const summary = await this.summarize(source.files, source.manifest, run, source.skipped);
        await this.yield(run);
        // Do not publish a stale snapshot if final files were changed while queued or being read.
        if ((await this.inspect(directory, run)).signature !== source.signature) return;
        await this.persist(path, source.signature, summary);
        this.remember(path, source.signature, summary);
      } };
      jobs.set(path, job);
      scheduleScans();
    }
    const remaining = deadline - Date.now();
    if (waitMs > 0 && remaining > 0) {
      let timer: NodeJS.Timeout | undefined;
      try { await Promise.race([job.done, new Promise<void>(resolvePromise => { timer = setTimeout(resolvePromise, remaining); })]); }
      finally { if (timer) clearTimeout(timer); }
      const completed = await this.cached(path, snapshot.signature);
      if (completed) return completed;
    }
    return emptyObjectiveSummary('calculating');
  }
  async close() {
    this.closed = true;
    const pending: Promise<void>[] = [];
    for (const [key, job] of jobs) if (job.owner === this) {
      if (job !== activeJob) { jobs.delete(key); job.finish(); }
      pending.push(job.done);
    }
    // A running scan observes closed at its next chunk boundary before writing a cache.
    await Promise.all(pending);
  }
  private async yield(run: ObjectiveRun) {
    await yieldEventLoop();
    if (this.closed || !isTerminalRun(run.status) || !this.canScan()) throw new ScanPaused();
  }
  private remember(path: string, signature: string, summary: ObjectiveSummary) {
    this.cache.delete(path); this.cache.set(path, { signature, summary });
    if (this.cache.size > MAX_CACHED_RUNS) this.cache.delete(this.cache.keys().next().value!);
  }
  private async cached(path: string, signature: string): Promise<ObjectiveSummary | undefined> {
    const memory = this.cache.get(path);
    if (memory?.signature === signature) { this.remember(path, signature, memory.summary); return memory.summary; }
    this.cache.delete(path);
    try {
      const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const metadata = await file.stat();
        if (!metadata.isFile() || metadata.size > MAX_CACHE_BYTES) return;
        const value = object(JSON.parse(await file.readFile('utf8')));
        if (value?.schemaVersion !== OBJECTIVE_SCHEMA_VERSION || value.sourceSignature !== signature || !validSummary(value.summary)) return;
        this.remember(path, signature, value.summary); return value.summary;
      } finally { await file.close(); }
    } catch { return; } // Missing, old or corrupt caches are recomputed only in the background.
  }
  private async persist(path: string, signature: string, summary: ObjectiveSummary) {
    await mkdir(this.cacheDirectory, { recursive: true, mode: 0o700 });
    // Reject a substituted cache directory; retained runs are never a write destination.
    const data = await realpath(resolve(this.cacheDirectory, '..'));
    if (await realpath(this.cacheDirectory) !== join(data, 'objective-summaries')) throw new Error('Objective cache directory is outside the data directory');
    await chmod(this.cacheDirectory, 0o700);
    const temporary = path + '.' + randomUUID() + '.tmp';
    try {
      const file = await open(temporary, 'wx', 0o600);
      try { await file.writeFile(JSON.stringify({ schemaVersion: OBJECTIVE_SCHEMA_VERSION, sourceSignature: signature, summary }) + '\n'); }
      finally { await file.close(); }
      if (this.closed || !this.canScan()) throw new ScanPaused();
      await rename(temporary, path);
    } finally { await unlink(temporary).catch(() => {}); }
  }
  private async inspect(directory: string, fallback: Bounds): Promise<Snapshot> {
    const files: RetainedFile[] = [];
    let manifest: RetainedFile | undefined;
    let skipped = 0;
    try {
      const base = await realpath(directory);
      try {
        const path = join(base, 'manifest.json');
        if ((await realpath(path)).startsWith(base + sep)) {
          const metadata = await stat(path);
          if (metadata.isFile() && metadata.size <= 2 * 1024 * 1024) manifest = this.file(path, metadata);
        }
      } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') skipped++; }
      try {
        const raw = await realpath(join(base, 'raw'));
        if (!raw.startsWith(base + sep)) throw new Error('Retained audit directory is outside the run');
        for (const entry of (await readdir(raw, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
          if (!entry.isFile() || !/^audit-.*\.jsonl$/.test(entry.name)) continue;
          const path = join(raw, entry.name);
          files.push(this.file(path, await stat(path)));
        }
      } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') skipped++; }
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') skipped++; }
    const signature = createHash('sha256').update(JSON.stringify([
      fallback.startedAt, fallback.finishedAt, manifest?.stamp, files.map(file => file.stamp), skipped,
    ])).digest('hex');
    return { files, manifest, skipped, signature };
  }
  private file(path: string, metadata: Awaited<ReturnType<typeof stat>>): RetainedFile {
    return { path, size: Number(metadata.size), stamp: JSON.stringify([path, metadata.size, metadata.mtimeMs, metadata.ctimeMs, metadata.ino]) };
  }
  private async summarize(files: RetainedFile[], manifest: RetainedFile | undefined, fallback: ObjectiveRun, skipped: number): Promise<ObjectiveSummary> {
    const accumulator = new ObjectiveAccumulator();
    accumulator.summary.skippedRecordCount = skipped;
    let bounds: Bounds = fallback;
    if (manifest) {
      try {
        const data = object(JSON.parse(await readFile(manifest.path, 'utf8')));
        bounds = { startedAt: typeof data?.startedAt === 'string' ? data.startedAt : fallback.startedAt,
          finishedAt: typeof data?.finishedAt === 'string' ? data.finishedAt : fallback.finishedAt };
      } catch { accumulator.summary.skippedRecordCount++; }
    }
    const lower = instant(bounds.startedAt), upper = instant(bounds.finishedAt);
    const seen = new Set<string>();
    for (const file of files) {
      await this.yield(fallback);
      if (!file.size) continue;
      try {
        // Read the stat'ed snapshot only; a later poll handles bytes appended during this scan.
        let parts: Buffer[] = [], length = 0, oversized = false;
        const consume = () => {
          if (oversized) accumulator.summary.skippedRecordCount++;
          else this.record(Buffer.concat(parts, length).toString('utf8'), lower, upper, seen, accumulator);
          parts = []; length = 0; oversized = false;
        };
        for await (const chunk of createReadStream(file.path, { end: file.size - 1, highWaterMark: 64 * 1024 })) {
          await this.yield(fallback);
          const bytes = chunk as Buffer;
          let start = 0;
          while (start < bytes.length) {
            const newline = bytes.indexOf(10, start);
            const end = newline === -1 ? bytes.length : newline;
            if (!oversized) {
              length += end - start;
              if (length > MAX_LINE_BYTES) { oversized = true; parts = []; }
              else parts.push(bytes.subarray(start, end));
            }
            if (newline === -1) break;
            consume(); start = end + 1;
          }
        }
        if (length || oversized) consume();
      } catch (error) {
        if (error instanceof ScanPaused) throw error;
        accumulator.summary.skippedRecordCount++;
      }
    }
    return accumulator.summary;
  }
  private record(line: string, lower: number | undefined, upper: number | undefined, seen: Set<string>, accumulator: ObjectiveAccumulator) {
    if (!line.trim()) return;
    let record: RecordValue | undefined;
    try { record = object(JSON.parse(line)); } catch { accumulator.summary.skippedRecordCount++; return; }
    const trace = object(record?.decisionTrace);
    if (!trace) return;
    const at = instant(Object.hasOwn(trace, 'timestamp') ? trace.timestamp : record?.time);
    if (at === undefined) { accumulator.summary.skippedRecordCount++; return; }
    if (lower !== undefined && at < lower || upper !== undefined && at > upper) return;
    // Match exporter.row_identity: repeated SSE captures count once, across files too.
    const identity = [trace.policyUID, trace.tickID, trace.assetUID, trace.decisionID];
    if (!identity.every(value => typeof value === 'string' && value.length > 0)) { accumulator.summary.skippedRecordCount++; return; }
    const key = JSON.stringify(identity);
    if (seen.has(key)) return;
    seen.add(key); accumulator.add(trace);
  }
}

function validSummary(value: unknown): value is ObjectiveSummary {
  const summary = object(value);
  const count = (value: unknown) => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
  const label = (value: unknown) => value === null || typeof value === 'string' && value.length <= MAX_LABEL_LENGTH;
  const number = (value: unknown) => value === null || typeof value === 'number' && Number.isFinite(value);
  return Boolean(summary && summary.state === 'ready' && typeof summary.mixedModes === 'boolean'
    && ['decisionCount', 'unlistedModeCount', 'unlistedCoefficientCount', 'skippedRecordCount'].every(key => count(summary[key]))
    && Array.isArray(summary.modes) && summary.modes.length <= MAX_MODES + 1
    && summary.modes.every(value => { const mode = object(value); return mode && label(mode.objectiveMode) && count(mode.count); })
    && Array.isArray(summary.coefficients) && summary.coefficients.length <= MAX_COEFFICIENT_GROUPS
    && summary.coefficients.every(value => { const group = object(value); return group && label(group.objectiveMode) && label(group.source) && number(group.min) && number(group.max) && count(group.count); }));
}

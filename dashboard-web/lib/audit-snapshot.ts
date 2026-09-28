import type { Lens } from "@/lib/api";

export interface SnapshotDecision {
  kind?: string;
  namespace?: string;
  pod?: string;
  time?: string;
  decisionTrace?: { assetUID?: string };
}

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

export function auditTimeMillis(value: unknown): number | null {
  if (typeof value !== "string" || !RFC3339.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

// A valid timestamp beats an unknown or invalid one. Equal millisecond values
// retain stream arrival order; JavaScript Date does not represent nanoseconds.
export function auditTimeAtLeast(candidate: unknown, previous: unknown): boolean {
  const next = auditTimeMillis(candidate);
  const current = auditTimeMillis(previous);
  return current === null || (next !== null && next >= current);
}

// Shared default retention. Aggregate panels summarise a handful of hot workloads, so 80
// rows is ample there; Discovered needs one row per scanned Pod and overrides it.
export const DEFAULT_SNAPSHOT_LIMIT = 80;

// The default keeps one newest row per workload, preserving existing aggregate views.
// Discovered opts into Pod-epoch keys so a reused name cannot hide a valid UID match.
export function recordAuditSnapshot<T extends SnapshotDecision>(records: Map<string, T>, event: T, lens: Lens, preserveEpochs = false, limit: number = DEFAULT_SNAPSHOT_LIMIT): void {
  if (!event.namespace || !event.pod || (lens !== "owner" && event.kind !== "phorvex.decision")) return;
  const uid = preserveEpochs && lens !== "owner" ? event.decisionTrace?.assetUID || "" : "";
  const key = JSON.stringify([event.namespace, event.pod, uid]);
  const previous = records.get(key);
  if (previous && !auditTimeAtLeast(event.time, previous.time)) return;
  records.delete(key);
  records.set(key, event);
  if (records.size > limit) records.delete(records.keys().next().value!);
}

export interface AuditSampleClock {
  set(callback: () => void, ms: number): ReturnType<typeof setTimeout>;
  clear(timer: ReturnType<typeof setTimeout>): void;
}

const browserClock: AuditSampleClock = { set: (callback, ms) => setTimeout(callback, ms), clear: clearTimeout };

// Remote replay can take longer than 2.5s to yield a current-Pod decision.
// Discovered settles 2.5s after its first scan-epoch match, with a 15s absolute
// bound when that match never arrives. Other consumers keep their 2.5s bound.
export function sampleAuditSnapshot<T extends SnapshotDecision>({ lens, signal, preserveEpochs, eligible, subscribe, clock = browserClock, limit }: {
  lens: Lens;
  signal: AbortSignal;
  preserveEpochs: boolean;
  eligible?: (event: T) => boolean;
  subscribe: (onEvent: (event: T) => void, onError: (error: unknown) => void) => () => void;
  clock?: AuditSampleClock;
  // How many distinct workloads the sample retains. Discovered must hold one row per
  // scanned Pod, so it raises this above the shared default.
  limit?: number;
}): Promise<T[]> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) { reject(new DOMException("Aborted", "AbortError")); return; }
    const records = new Map<string, T>();
    let stop = () => {};
    let settled = false;
    let settleTimer: ReturnType<typeof setTimeout> | undefined;
    const cleanup = () => { clock.clear(timer); if (settleTimer !== undefined) clock.clear(settleTimer); signal.removeEventListener("abort", abort); stop(); };
    const finish = () => { if (settled) return; settled = true; cleanup(); resolve(Array.from(records.values())); };
    const fail = (error: unknown) => { if (settled) return; settled = true; cleanup(); reject(error instanceof Error ? error : new Error("Decision stream failed")); };
    const abort = () => fail(new DOMException("Aborted", "AbortError"));
    const timer = clock.set(finish, preserveEpochs ? 15_000 : 2_500);
    signal.addEventListener("abort", abort, { once: true });
    try {
      stop = subscribe((event) => {
        if (settled) return;
        recordAuditSnapshot(records, event, lens, preserveEpochs, limit);
        if (preserveEpochs && settleTimer === undefined && eligible?.(event)) settleTimer = clock.set(finish, 2_500);
      }, fail);
      if (settled) stop(); // A test or transport may settle synchronously while subscribing.
    } catch (error) { fail(error); }
  });
}

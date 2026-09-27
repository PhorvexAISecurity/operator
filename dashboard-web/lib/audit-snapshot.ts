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

// The default keeps one newest row per workload, preserving existing aggregate views.
// Discovered opts into Pod-epoch keys so a reused name cannot hide a valid UID match.
export function recordAuditSnapshot<T extends SnapshotDecision>(records: Map<string, T>, event: T, lens: Lens, preserveEpochs = false, limit = 80): void {
  if (!event.namespace || !event.pod || (lens !== "owner" && event.kind !== "phorvex.decision")) return;
  const uid = preserveEpochs && lens !== "owner" ? event.decisionTrace?.assetUID || "" : "";
  const key = JSON.stringify([event.namespace, event.pod, uid]);
  const previous = records.get(key);
  if (previous && !auditTimeAtLeast(event.time, previous.time)) return;
  records.delete(key);
  records.set(key, event);
  if (records.size > limit) records.delete(records.keys().next().value!);
}

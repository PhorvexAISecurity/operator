import type { Lens } from "@/lib/api";

export interface SnapshotDecision {
  kind?: string;
  namespace?: string;
  pod?: string;
  time?: string;
  decisionTrace?: { assetUID?: string };
}

// The default keeps one newest row per workload, preserving existing aggregate views.
// Discovered opts into Pod-epoch keys so a reused name cannot hide a valid UID match.
export function recordAuditSnapshot<T extends SnapshotDecision>(records: Map<string, T>, event: T, lens: Lens, preserveEpochs = false, limit = 80): void {
  if (!event.namespace || !event.pod || (lens !== "owner" && event.kind !== "phorvex.decision")) return;
  const uid = preserveEpochs && lens !== "owner" ? event.decisionTrace?.assetUID || "" : "";
  const key = JSON.stringify([event.namespace, event.pod, uid]);
  const previous = records.get(key);
  if (previous?.time && event.time && previous.time > event.time) return;
  records.delete(key);
  records.set(key, event);
  if (records.size > limit) records.delete(records.keys().next().value!);
}

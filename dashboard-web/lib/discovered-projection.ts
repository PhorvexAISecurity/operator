import type { GraphNode } from "@/lib/api";

export interface DecisionPodRow {
  namespace?: string;
  pod?: string;
  time?: string;
  stage?: string;
  assetValue?: number;
  blastRadius?: number;
  aiClassified?: boolean;
  decisionTrace?: { assetUID?: string };
}

export interface DiscoveredPod {
  key: string;
  ns: string;
  pod: string;
  uid: string | null;
  stage: string | null;
  asset: number | null;
  blast: number | null;
  ai: boolean;
  evidenceTime: string | null;
  source: "scan" | "decision";
}

const finite = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value);
const stage = (value: unknown): string | null => typeof value === "string" && value.trim() ? value.trim() : null;

// The audit may contain several decisions for one Pod. A name is reusable after rotation;
// only the scanned Pod UID proves that a decision belongs to that graph-node epoch.
export function projectDiscoveredPods(graphNodes: GraphNode[], decisions: DecisionPodRow[]): DiscoveredPod[] {
  const byKey = new Map<string, DecisionPodRow[]>();
  for (const decision of decisions) {
    if (!decision.namespace || !decision.pod) continue;
    const key = `${decision.namespace}/${decision.pod}`;
    byKey.set(key, [...(byKey.get(key) ?? []), decision]);
  }
  const newest = (rows: DecisionPodRow[]) => [...rows].sort((a, b) => (b.time ?? "").localeCompare(a.time ?? ""))[0];
  const scanKeys = new Set(graphNodes.map((node) => node.key));
  const scanned = graphNodes.map((node): DiscoveredPod => {
    const [ns, ...rest] = node.key.split("/");
    const decision = node.uid ? newest((byKey.get(node.key) ?? []).filter((row) => row.decisionTrace?.assetUID === node.uid)) : undefined;
    return {
      key: node.key, ns, pod: rest.join("/"), uid: node.uid || null,
      stage: stage(decision?.stage), asset: finite(decision?.assetValue) ? decision.assetValue : null,
      blast: finite(node.blast) ? node.blast : null, ai: node.ai || !!decision?.aiClassified,
      evidenceTime: decision?.time || null, source: "scan",
    };
  });
  // If a scan fails, retain bounded decision evidence with its time and UID. These
  // rows are labelled as decisions, never presented as verified current scan Pods.
  const auditOnly = Array.from(byKey.entries()).filter(([key]) => !scanKeys.has(key)).map(([key, rows]): DiscoveredPod => {
    const decision = newest(rows);
    return {
      key, ns: decision.namespace!, pod: decision.pod!, uid: decision.decisionTrace?.assetUID || null,
      stage: stage(decision.stage), asset: finite(decision.assetValue) ? decision.assetValue : null,
      blast: finite(decision.blastRadius) ? decision.blastRadius : null, ai: !!decision.aiClassified,
      evidenceTime: decision.time || null, source: "decision",
    };
  });
  return [...scanned, ...auditOnly];
}

export type StageGroup = "recon" | "exploit" | "lateral" | "impact" | "ai" | "other" | "unknown";
export function stageGroup(value: string | null): StageGroup {
  if (!value) return "unknown";
  const name = value.toLowerCase();
  if (name === "recon" || name === "early reconnaissance") return "recon";
  if (name === "exploit" || name === "exploitation") return "exploit";
  if (name === "lateral") return "lateral";
  if (name === "impact" || name === "exfil") return "impact";
  if (["gpu-side-channel", "model-theft", "llm-jacking", "prompt-inject-persist"].includes(name)) return "ai";
  return "other";
}

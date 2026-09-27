import { api, AttackResult, CompatEntry, Lens, VllmAttackAction } from "@/lib/api";

type LiveRoute = { kind: "vllm"; action: VllmAttackAction } | { kind: "voice" } |
  { kind: "litellm"; scenario: "ai2-unbounded-consumption" | "ai2-query-extraction" } |
  { kind: "foothold"; namespace: string; action: "foothold" | "clear" };

const vllmActions = new Set<string>([
  "poison", "kvcache", "endpoint-rotate", "guardrail-rotate", "guardrail-output-v2",
  "request-drain", "kv-migrate-invalidate", "warm-swap", "model-shard-replace",
]);

// Compatibility is server-owned, but still bind the advertised ID to its one allowed endpoint.
export function liveAttackRoute(entry: Pick<CompatEntry, "id" | "endpoint">, namespace: string, clear = false): LiveRoute | null {
  if (entry.endpoint === "/api/workload/attack" && entry.id === "foothold" && namespace)
    return { kind: "foothold", namespace, action: clear ? "clear" : "foothold" };
  if (clear) return null;
  if (entry.endpoint === "/api/vllm/attack" && namespace === "vllm" && vllmActions.has(entry.id))
    return { kind: "vllm", action: entry.id as VllmAttackAction };
  if (entry.endpoint === "/api/voice/live/fire" && namespace === "voice" && entry.id === "ai2-agent-memory-contamination")
    return { kind: "voice" };
  if (entry.endpoint === "/api/litellm/live/fire" && namespace === "litellm" &&
      (entry.id === "ai2-unbounded-consumption" || entry.id === "ai2-query-extraction"))
    return { kind: "litellm", scenario: entry.id };
  return null;
}

export async function dispatchLiveAttack(route: LiveRoute, lens: Lens) {
  switch (route.kind) {
    case "vllm": return api.vllmAttack(route.action, lens);
    case "voice": return api.voiceMemoryFire("ai2-agent-memory-contamination", lens);
    case "litellm": return api.litellmLiveFire(route.scenario, lens);
    case "foothold": return api.workloadAttack(route.namespace, route.action, lens);
  }
}

// Voice and LiteLLM have 900-second server observation windows; leave a bounded margin for publication.
export function liveAttackPollBudgetMs(route: LiveRoute): number {
  return route.kind === "voice" || route.kind === "litellm" ? 960_000 : 150_000;
}

export function liveAttackVerdict(result: AttackResult) {
  const action = result.phorvexAction || result.decisionEvidence?.action || "";
  const noop = result.status !== "running" && action === "noop";
  const statuses = result.decisionEvidence?.actionStatus || [];
  const requested = statuses.filter((candidate) => candidate.action === result.attackId);
  const blocked = (requested.length ? requested : statuses)
    .filter((candidate) => candidate.status !== "selected" && candidate.status !== "eligible")
    .slice(0, 4)
    .map((candidate) => `${candidate.action}: ${candidate.status}${candidate.reason ? ` — ${candidate.reason}` : ""}`);
  return {
    action: noop ? "NOOP" : action || (result.status === "running" ? "pending" : "UNCONFIRMED"),
    reason: result.decisionEvidence?.reason || result.observationError || result.why || "",
    blocked,
    noop,
  };
}

export function liveAttackFollowMessage(id: string, active: boolean, last: AttackResult | null | undefined): string {
  if (!id || last?.status === "done" || last?.status === "partial") return "";
  if (!active) return `No completed exact result was confirmed for ${id} within the bounded follow-up${last?.status === "running" ? "; last read was running" : ""}. Check the record directly; no final outcome is inferred.`;
  if (last?.status === "running") return `Exact result ${id} is still running${last.observationDeadline ? `; observation deadline ${last.observationDeadline}` : ""}. Following this record within the bounded window.`;
  return `Following exact result ${id}…`;
}

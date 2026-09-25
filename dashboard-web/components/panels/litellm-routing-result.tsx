import type { LiteLLMRoutingEvidence, LiteLLMRoutingPodEvidence, TrialOutcome } from "@/lib/api";

const digest = /^[0-9a-f]{64}$/;
const http = /^(?:[1-5][0-9]{2}|NOT_ATTEMPTED|UNVERIFIED)$/;
const publicToken = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,159}$/;
const reviewedAlias = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const secretLikeAlias = /^(?:sk-|pk-|bearer|basic|api[_-]?key|secret|password|token)/i;
const modelRelations = new Set(["REQUEST_ALIAS", "OTHER_REDACTED"]);
const publicReasons = new Set([
  "VALID_ASSISTANT_COMPLETION", "MODEL_NOT_FOUND", "NO_CONNECTED_DB", "AUTH_DENIED",
  "RATE_LIMITED", "PROVIDER_OR_GATEWAY_ERROR", "CONFIGURATION_ERROR",
  "MALFORMED_RESPONSE", "OTHER_REDACTED", "REQUEST_UNAVAILABLE",
]);
const version = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$/;
const count = /^(?:0|[1-9][0-9]{0,6})$/;
const knownStates = new Set(["COMPLETION_SERVED", "UNVERIFIED"]);
const unknownStates = new Set(["MODEL_REJECTED", "UNVERIFIED"]);

function parsePod(evidence: Record<string, string>, prefix: "pod1" | "pod2"): LiteLLMRoutingPodEvidence | null {
  const name = evidence[`${prefix}.name`] || "";
  const uid = evidence[`${prefix}.uid`] || "";
  const imageID = evidence[`${prefix}.imageID`] || "";
  const podVersion = evidence[`${prefix}.version`] || "";
  const known = {
    status: evidence[`${prefix}.known.status`] || "UNVERIFIED",
    state: evidence[`${prefix}.known.state`] || "UNVERIFIED",
    reason: evidence[`${prefix}.known.reason`] || "REQUEST_UNAVAILABLE",
    returnedModel: evidence[`${prefix}.known.returnedModel`] || "",
    returnedModelSHA256: evidence[`${prefix}.known.returnedModelSHA256`] || "",
    modelRelation: evidence[`${prefix}.known.modelRelation`] || "",
    usagePromptCount: evidence[`${prefix}.known.usagePromptCount`] || "",
    usageCompletionCount: evidence[`${prefix}.known.usageCompletionCount`] || "",
  };
  const unknown = {
    status: evidence[`${prefix}.unknown.status`] || "UNVERIFIED",
    state: evidence[`${prefix}.unknown.state`] || "UNVERIFIED",
    reason: evidence[`${prefix}.unknown.reason`] || "UNVERIFIED",
    returnedModel: evidence[`${prefix}.unknown.returnedModel`] || "",
    returnedModelSHA256: evidence[`${prefix}.unknown.returnedModelSHA256`] || "",
    modelRelation: evidence[`${prefix}.unknown.modelRelation`] || "",
  };
  if (!publicToken.test(name) || !publicToken.test(uid) || !publicToken.test(imageID) || !version.test(podVersion) ||
      !http.test(known.status) || !http.test(unknown.status) || !knownStates.has(known.state) || !unknownStates.has(unknown.state) ||
      (known.returnedModel && !reviewedAlias.test(known.returnedModel)) ||
      (unknown.returnedModel && !reviewedAlias.test(unknown.returnedModel)) ||
      (known.usagePromptCount && !count.test(known.usagePromptCount)) ||
      (known.usageCompletionCount && !count.test(known.usageCompletionCount)) ||
      !publicReasons.has(known.reason) || !publicReasons.has(unknown.reason)) return null;
  if (known.state === "COMPLETION_SERVED" && (known.status !== "200" || known.reason !== "VALID_ASSISTANT_COMPLETION" ||
      !digest.test(known.returnedModelSHA256) || !modelRelations.has(known.modelRelation) ||
      !known.usagePromptCount || !known.usageCompletionCount)) return null;
  if (known.reason === "VALID_ASSISTANT_COMPLETION" && known.state !== "COMPLETION_SERVED") return null;
  if (known.state !== "COMPLETION_SERVED" && (known.returnedModel || known.returnedModelSHA256 || known.modelRelation)) return null;
  if (unknown.state === "MODEL_REJECTED" && (!["400", "404"].includes(unknown.status) || unknown.reason !== "MODEL_NOT_FOUND")) return null;
  if (unknown.reason === "MODEL_NOT_FOUND" && unknown.state !== "MODEL_REJECTED") return null;
  if (unknown.reason === "VALID_ASSISTANT_COMPLETION" && (unknown.status !== "200" || unknown.state !== "UNVERIFIED" ||
      !digest.test(unknown.returnedModelSHA256) || !modelRelations.has(unknown.modelRelation))) return null;
  if (unknown.reason !== "VALID_ASSISTANT_COMPLETION" && (unknown.returnedModel || unknown.returnedModelSHA256 || unknown.modelRelation)) return null;
  return { name, uid, imageID, version: podVersion, known, unknown };
}

export function parseLiteLLMRoutingEvidence(evidence: Record<string, string> | undefined): LiteLLMRoutingEvidence | null {
  if (!evidence || evidence.eventMode !== "none" || evidence.securityEvent !== "NOT_REQUIRED" || evidence.brain !== "NOT_EVALUATED" ||
      evidence.actuator !== "NOT_EVALUATED" || evidence.securityOutcome !== "NOT_EVALUATED" ||
      !digest.test(evidence.authorityBeforeSHA256 || "") ||
      evidence.authorityBeforeSHA256 !== evidence.authorityAfterSHA256 ||
      !digest.test(evidence.configSHA256 || "") || !/^[0-4]$/.test(evidence.requestCount || "") ||
      !reviewedAlias.test(evidence.modelAlias || "") || secretLikeAlias.test(evidence.modelAlias)) return null;
  const pod1 = parsePod(evidence, "pod1");
  const pod2 = parsePod(evidence, "pod2");
  if (!pod1 || !pod2 || pod1.uid === pod2.uid ||
      !knownStates.has(evidence.knownModelState) || !unknownStates.has(evidence.unknownModelState) ||
      [pod1.known, pod2.known].some((stage) => stage.modelRelation === "REQUEST_ALIAS" ? stage.returnedModel !== evidence.modelAlias : !!stage.returnedModel) ||
      [pod1.unknown, pod2.unknown].some((stage) => stage.modelRelation === "REQUEST_ALIAS" ? !stage.returnedModel : stage.modelRelation === "OTHER_REDACTED" && !!stage.returnedModel) ||
      (evidence.knownModelState === "COMPLETION_SERVED" && (pod1.known.state !== "COMPLETION_SERVED" || pod2.known.state !== "COMPLETION_SERVED")) ||
      (evidence.unknownModelState === "MODEL_REJECTED" && (pod1.unknown.state !== "MODEL_REJECTED" || pod2.unknown.state !== "MODEL_REJECTED")) ||
      (evidence.knownModelState === "COMPLETION_SERVED" && evidence.unknownModelState === "MODEL_REJECTED" && evidence.requestCount !== "4")) return null;
  return { pod1, pod2, modelAlias: evidence.modelAlias, knownModelState: evidence.knownModelState,
    unknownModelState: evidence.unknownModelState, requestCount: evidence.requestCount,
    authorityBeforeSHA256: evidence.authorityBeforeSHA256, authorityAfterSHA256: evidence.authorityAfterSHA256,
    configSHA256: evidence.configSHA256, eventMode: evidence.eventMode, securityEvent: evidence.securityEvent, brain: evidence.brain,
    actuator: evidence.actuator, securityOutcome: evidence.securityOutcome };
}

function partialPod(evidence: Record<string, string> | undefined, prefix: "pod1" | "pod2") {
  if (!evidence) return null;
  const name = evidence[`${prefix}.name`] || "";
  const uid = evidence[`${prefix}.uid`] || "";
  if (!publicToken.test(name) || !publicToken.test(uid)) return null;
  const versionValue = evidence[`${prefix}.version`] || "";
  const imageValue = evidence[`${prefix}.imageID`] || "";
  const stage = (name: "known" | "unknown") => {
    const status = evidence[`${prefix}.${name}.status`] || "";
    const reason = evidence[`${prefix}.${name}.reason`] || "";
    return { status: http.test(status) ? status : "not recorded", reason: publicReasons.has(reason) ? reason : "not recorded" };
  };
  return { name, uid, version: version.test(versionValue) ? versionValue : "unverified",
    imageID: publicToken.test(imageValue) ? imageValue : "unverified", known: stage("known"), unknown: stage("unknown") };
}

export function LiteLLMRoutingResult({ evidence, outcome }: { evidence: Record<string, string> | undefined; outcome?: TrialOutcome }) {
  const parsed = parseLiteLLMRoutingEvidence(evidence);
  const positive = parsed?.knownModelState === "COMPLETION_SERVED" && parsed.unknownModelState === "MODEL_REJECTED";
  const result = (outcome === "functional-pass" ? positive : !positive) ? parsed : null;
  if (!result) {
    const pods = [partialPod(evidence, "pod1"), partialPod(evidence, "pod2")];
    return <div data-litellm-routing-result="unverified" className="rounded-md border border-warning/30 bg-warning/[0.04] p-3 text-[12px] space-y-2">
      <div className="text-warning">LiteLLM per-Pod inference evidence is incomplete or incompatible. No serving or model-rejection result is accepted.</div>
      {pods.map((pod, index) => pod && <div key={pod.uid} data-litellm-routing-pod={index + 1} className="rounded border border-border p-2 space-y-1">
        <div>Pod {index + 1}: {pod.name} · version {pod.version}</div>
        <div className="break-all text-muted-foreground">UID {pod.uid} · image {pod.imageID}</div>
        <div>Known-model stage unverified: HTTP {pod.known.status} · reason {pod.known.reason}</div>
        <div>Unknown-model stage unverified: HTTP {pod.unknown.status} · reason {pod.unknown.reason}</div>
      </div>)}
      <div>Event, brain, actuator and security results are not inferred from partial application receipts. Raw replies and credentials are not displayed.</div>
    </div>;
  }
  return <div data-litellm-routing-result="typed" className="rounded-md border border-border bg-muted/20 p-3 text-[12px] space-y-2">
    <div className="font-medium text-foreground">LiteLLM authenticated inference routing · direct functional control · {outcome || "unverified outcome"}</div>
    <div>Reviewed configured alias: {result.modelAlias} · known model: {result.knownModelState} · unknown model: {result.unknownModelState} · application POSTs: {result.requestCount} of 4 maximum</div>
    <div className="text-muted-foreground">A known-model completion and an unknown-model rejection are separate observations. An authentication, database, provider or rate-limit error stays unverified; an HTTP error alone does not prove model rejection or absence of an upstream call. Returned model metadata does not attest provider model or weights.</div>
    {[result.pod1, result.pod2].map((pod, index) => <div key={pod.uid} data-litellm-routing-pod={index + 1} className="rounded border border-border p-2 space-y-1">
      <div className="font-medium text-foreground">Pod {index + 1}: {pod.name} · version {pod.version}</div>
      <div className="break-all text-muted-foreground">UID {pod.uid} · image {pod.imageID}</div>
      <div>Configured known model: HTTP {pod.known.status} · {pod.known.state} · reason {pod.known.reason}{pod.known.state === "COMPLETION_SERVED" ? ` · returned model relation ${pod.known.modelRelation} · model SHA-256 ${pod.known.returnedModelSHA256} · usage ${pod.known.usagePromptCount} prompt / ${pod.known.usageCompletionCount} completion tokens` : " · completion unverified"}</div>
      <div>Deliberately unknown model: HTTP {pod.unknown.status} · {pod.unknown.state} · reason {pod.unknown.reason}{pod.unknown.reason === "VALID_ASSISTANT_COMPLETION" ? ` · unexpected completion · returned model relation ${pod.unknown.modelRelation} · model SHA-256 ${pod.unknown.returnedModelSHA256}` : ""}</div>
    </div>)}
    <div className="break-all text-muted-foreground">Pinned config SHA-256 {result.configSHA256} · authority before/after SHA-256 {result.authorityBeforeSHA256}</div>
    <div>Event mode: none · brain, actuator and security outcome: NOT_EVALUATED. This says nothing about scoped-key authorization or hidden provider internals. Prompts, completion bodies and credentials are not displayed.</div>
  </div>;
}

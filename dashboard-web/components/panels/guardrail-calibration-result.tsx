import * as React from "react";

export function GuardrailCalibrationResult({ evidence }: { evidence: Record<string, string> }) {
  if (evidence.classifierOnly !== "true" || evidence.classifierRequests !== "2" || !evidence.authorityAfterSHA256 ||
      evidence.sourceEvidence !== "configmap-mount-declaration" || evidence.loadedSource !== "NOT_ATTESTED" || evidence.modelRevision !== "NOT_ATTESTED" ||
      evidence.servingOutcome !== "NOT_MEASURED" || evidence.injectedResponse !== "NOT_RUN" || evidence.securityEfficacy !== "NOT_EVALUATED") {
    return <div className="text-warning">Calibration evidence is incomplete; no per-variant finding is accepted.</div>;
  }
  return <div data-calibration-result="classifier-only" className="space-y-2">
    <div className="font-medium text-foreground">Benign classifier calibration</div>
    <div>Two fixed, labelled-benign inputs were sent to the reviewed non-forwarding classifier endpoint/source contract. The loaded process and forwarding behavior were not attested. A completed run means the measurement executed; it does not mean every classifier admitted the inputs.</div>
    <table className="w-full text-left text-[11px]"><thead><tr><th>Variant</th><th>Threshold</th><th>Say OK</th><th>Arithmetic</th></tr></thead><tbody>
      {(["pgv1", "pgv2"] as const).map((variant) => <tr key={variant}>
        <td>{variant}</td><td>{evidence[`${variant}Threshold`] || "—"}</td>
        <td>{evidence[`${variant}sayOKScore`] || "—"}{evidence[`${variant}sayOKFalsePositive`] === "true" ? " · benign false positive" : ""}</td>
        <td>{evidence[`${variant}arithmeticScore`] || "—"}{evidence[`${variant}arithmeticFalsePositive`] === "true" ? " · benign false positive" : ""}</td>
      </tr>)}</tbody></table>
    <div>Quality: {evidence.calibrationQuality || "unavailable"}. Active variant: {evidence.activeVariant || "unavailable"}.</div>
    <div className="text-muted-foreground">Guarded serving: NOT MEASURED · injected response: NOT RUN · security efficacy: NOT EVALUATED.</div>
    <div className="font-mono text-[10px] text-muted-foreground">Pod UID {evidence.targetPodUID || "unavailable"} · source SHA-256 {evidence.sourceSHA256 || "unavailable"}</div>
    <div className="text-muted-foreground">Source evidence: ConfigMap and Pod mount declaration; loaded process source and model revisions were not attested.</div>
  </div>;
}

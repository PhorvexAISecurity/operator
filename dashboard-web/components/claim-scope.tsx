import type { ClaimScope } from "@/lib/api";

export function ClaimScopeNote({ claim }: { claim?: ClaimScope }) {
  const detectors = claim?.detectorSetKnown
    ? (claim.detectorSet.length ? claim.detectorSet.join(", ") : "none configured")
    : "unavailable for this record";
  return <div className="text-[10px] leading-relaxed text-muted-foreground break-words">
    {claim?.note || "Modeled coverage of the detector-visible, reversible projection; security effect unconfirmed and recall unknown."}
    {" "}Trusted detector set: {detectors}. Build: {claim?.brainImage || "unavailable"}; source: {claim?.gitSHA || "unavailable"}.
  </div>;
}

import type { NATSConfigurationResult } from "@/lib/api";

export function NATSConfigurationClarity({ result }: { result: NATSConfigurationResult }) {
  const expected = result.brainMode === "NO_SIGNAL" && result.securityEfficacy === "NOT_EVALUATED";
  return <div>
    stimulus: {result.brainMode === "NO_SIGNAL" ? "no SecurityEvent injected" : "unknown (unexpected stimulus metadata)"}
    <> · brain/actuator: {expected ? "not evaluated" : "unknown (unexpected metadata)"} · defense efficacy: {result.securityEfficacy === "NOT_EVALUATED" ? "not evaluated" : "unknown (unexpected metadata)"}</>
  </div>;
}

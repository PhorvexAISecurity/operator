import type { TrialOutcome } from "@/lib/api";

export type TrialOutcomeDisplay = {
  label: string;
  variant: "danger" | "real" | "neutral" | "pending" | "modeled";
};

// Unknown and missing values come from mixed-version or legacy console data.
// They are unverified, never silently reinterpreted as skipped or successful.
export function trialOutcomeDisplay(outcome?: TrialOutcome | string): TrialOutcomeDisplay {
  switch (outcome) {
    case "functional-pass": return { label: "functional pass", variant: "real" };
    case "functional-fail": return { label: "functional fail", variant: "danger" };
    case "security-landed": return { label: "attack landed", variant: "danger" };
    case "security-disrupted": return { label: "attack disrupted", variant: "real" };
    case "test-failed": return { label: "test failed", variant: "danger" };
    case "inconclusive": return { label: "inconclusive", variant: "pending" };
    case "unverified": return { label: "unverified", variant: "modeled" };
    case "negative-control": return { label: "negative control", variant: "neutral" };
    case "skipped": return { label: "skipped", variant: "neutral" };
    default: return { label: "unverified", variant: "modeled" };
  }
}

export function isSecurityOutcome(outcome?: string): boolean {
  return outcome === "security-landed" || outcome === "security-disrupted";
}

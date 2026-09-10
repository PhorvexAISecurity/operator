import type { OwnerEvent } from "./api";

// Old cached server payloads may contain success prose. Only the current
// conservative projection carries one of these outcome classes.
export function ownerNarrative(e: OwnerEvent): string {
  switch (e.outcomeEvidence) {
    case "emitted-unconfirmed":
    case "not-emitted":
    case "not-attempted":
    case "selected":
    case "dry-run":
    case "unknown":
      return e.why;
    default:
      return "Action outcome unknown. Completion and security effect are not confirmed.";
  }
}

import { Lens } from "@/lib/api";

export const LIVE_SELECTION_EVENT = "phorvex-live-selection";

export interface LiveSelection {
  kind: "attack" | "run";
  id: string;
  lens: Lens;
  context: string;
}

export interface LiveSelectionClear {
  kind: "clear";
  lens: Lens;
  context: string;
}

export type LiveSelectionEvent = LiveSelection | LiveSelectionClear;

const validId = (id: unknown): id is string => typeof id === "string" && id.length > 0 && id.length <= 256 && /^[A-Za-z0-9._:@/+\-]+$/.test(id);

const storageKey = (lens: Lens, context: string) => `phorvex-live-selection:${lens}:${context}`;

export function selectLiveRecord(selection: LiveSelection) {
  if (typeof window === "undefined" || selection.lens === "owner" || !validId(selection.id) || !selection.context || !["attack", "run"].includes(selection.kind)) return;
  try {
    window.sessionStorage.setItem(storageKey(selection.lens, selection.context), JSON.stringify(selection));
  } catch {
    // The in-page event still keeps mounted panels aligned when storage is unavailable.
  }
  window.dispatchEvent(new CustomEvent<LiveSelectionEvent>(LIVE_SELECTION_EVENT, { detail: selection }));
}

export function clearLiveSelection(lens: Lens, context: string) {
  if (typeof window === "undefined" || lens === "owner" || !context) return;
  try { window.sessionStorage.removeItem(storageKey(lens, context)); } catch {}
  window.dispatchEvent(new CustomEvent<LiveSelectionEvent>(LIVE_SELECTION_EVENT, { detail: { kind: "clear", lens, context } }));
}

export function readLiveSelection(lens: Lens, context: string): LiveSelection | null {
  if (typeof window === "undefined" || lens === "owner" || !context) return null;
  try {
    const value = JSON.parse(window.sessionStorage.getItem(storageKey(lens, context)) || "null") as LiveSelection | null;
    return value?.lens === lens && value.context === context && validId(value.id) && (value.kind === "attack" || value.kind === "run") ? value : null;
  } catch {
    return null;
  }
}

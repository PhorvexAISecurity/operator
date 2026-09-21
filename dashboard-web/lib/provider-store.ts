"use client";
/*
 * Global selected-target store — the ONE place the dashboard tracks WHICH provider/cluster the user
 * is viewing (AWS EKS vs vCluster). Every scoped panel (workloads, Live Ops, run-history, scan) reads
 * it so a vCluster selection shows ONLY vCluster data. Backed by localStorage so the choice persists.
 */
import * as React from "react";

export interface SelectedTarget {
  context: string; // kubeconfig context — passed to /api/scan, /api/live, /api/workloads
  provider: string; // "AWS EKS" | "vCluster" | … — used to filter run-history
  label: string; // human label for the header chip
}

const KEY_CTX = "phorvex-context";
const KEY_PROV = "phorvex-provider";
const KEY_LABEL = "phorvex-target-label";
const EMPTY: SelectedTarget = { context: "", provider: "", label: "" };

const listeners = new Set<() => void>();
let cache: SelectedTarget = readLS();

function readLS(): SelectedTarget {
  if (typeof window === "undefined") return EMPTY;
  try {
    return {
      context: localStorage.getItem(KEY_CTX) || "",
      provider: localStorage.getItem(KEY_PROV) || "",
      label: localStorage.getItem(KEY_LABEL) || "",
    };
  } catch { return EMPTY; }
}

export function getSelectedTarget(): SelectedTarget {
  return cache;
}

export function setSelectedTarget(t: SelectedTarget) {
  if (typeof window !== "undefined") {
    try {
      localStorage.setItem(KEY_CTX, t.context || "");
      localStorage.setItem(KEY_PROV, t.provider || "");
      localStorage.setItem(KEY_LABEL, t.label || "");
    } catch {}
  }
  cache = { context: t.context || "", provider: t.provider || "", label: t.label || "" };
  listeners.forEach((l) => l());
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

// useSelectedTarget re-renders the component whenever the selected provider changes (anywhere).
export function useSelectedTarget(): SelectedTarget {
  return React.useSyncExternalStore(subscribe, getSelectedTarget, () => EMPTY);
}

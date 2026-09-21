import type { Lens } from "@/lib/api";

export type QueryChange = {
  identity: string;
  providerToken: string;
  lens: Lens;
  context?: string;
  runId?: string;
  resources: string[];
  kind: "mutation" | "completion";
};

export type QueryEventProvider = { identity: string; token: string };
export type AuthLostDetail = { providerToken: string };
let currentProvider: QueryEventProvider | null = null;

export function setQueryEventProvider(provider: QueryEventProvider | null) {
  currentProvider = provider;
}

export function clearQueryEventProvider(provider: QueryEventProvider) {
  if (isCurrentQueryEventProvider(provider)) currentProvider = null;
}

export function captureQueryEventProvider(): QueryEventProvider | null {
  return currentProvider;
}

export function isCurrentQueryEventProvider(provider: QueryEventProvider | null) {
  return !!provider && provider.token === currentProvider?.token && provider.identity === currentProvider.identity;
}

export function emitQueryChange(detail: QueryChange) {
  if (typeof window !== "undefined" && detail.identity && detail.providerToken && isCurrentQueryEventProvider({ identity: detail.identity, token: detail.providerToken })) {
    window.dispatchEvent(new CustomEvent<QueryChange>("phorvex-query-changed", { detail }));
  }
}

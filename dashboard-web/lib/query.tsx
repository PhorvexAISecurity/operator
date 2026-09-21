"use client";

import * as React from "react";
import { QueryClient, QueryClientProvider, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  API_BASE, ApiError, CatalogItem, ClusterTarget, Lens, ReportMeta, RunEvidence, ScanResult, Session, WorkloadNS, api, liveStream,
} from "@/lib/api";
import { clearQueryEventProvider, QueryChange, setQueryEventProvider } from "@/lib/query-events";
import { createScopedUIStore, ScopedUIProvider } from "@/lib/use-scoped-ui-state";

const QUERY_GC = 5 * 60_000;
const sessionContext = React.createContext<{ identity: string; providerToken: string; ready: boolean; session: Session } | null>(null);

function retryRead(failures: number, error: unknown) {
  if (error instanceof DOMException && error.name === "AbortError") return false;
  if (error instanceof ApiError && error.status >= 400 && error.status < 500) return false;
  return failures < 2;
}

export function sessionIdentity(session: Session) {
  // This contains only server-verified grant descriptors, never credentials.
  return JSON.stringify([session.issuer, session.subject, session.source, [...session.roles].sort(), [...session.tenants].sort(), [...session.targets].sort(), session.canRead, session.canEdit, session.grantsConfigured, session.auditClearAvailable]);
}

export function SessionQueryBoundary({ session, providerToken, ready, children }: { session: Session; providerToken: string; ready: boolean; children: React.ReactNode }) {
  const identity = sessionIdentity(session);
  const provider = React.useMemo(() => ({ identity, token: providerToken }), [identity, providerToken]);
  const uiStore = React.useMemo(() => createScopedUIStore(), [identity, providerToken]);
  const [client] = React.useState(() => new QueryClient({
    defaultOptions: {
      // Session verification owns focus refresh. Query focus refresh must not race ahead using the
      // previously verified identity.
      queries: { staleTime: 0, gcTime: QUERY_GC, retry: retryRead, refetchOnWindowFocus: false },
      mutations: { retry: false },
    },
  }));

  const lifecycleRevision = React.useRef(0);
  React.useLayoutEffect(() => {
    const revision = ++lifecycleRevision.current;
    setQueryEventProvider(provider);
    return () => {
      queueMicrotask(() => {
        if (lifecycleRevision.current !== revision) return;
        clearQueryEventProvider(provider);
        client.clear();
      });
    };
  }, [client, provider]);
  React.useEffect(() => {
    if (!ready) {
      void client.cancelQueries();
      return;
    }
    void client.invalidateQueries({ refetchType: "active", predicate: (query) => query.state.isInvalidated || query.isStale() });
  }, [client, ready]);
  return <QueryClientProvider client={client}><sessionContext.Provider value={{ identity, providerToken, ready, session }}><ScopedUIProvider value={uiStore}>{children}</ScopedUIProvider></sessionContext.Provider></QueryClientProvider>;
}

export function useQueryScope(lens: Lens) {
  const value = React.useContext(sessionContext);
  if (!value) throw new Error("Query hooks require a verified session boundary");
  return { identity: value.identity, providerToken: value.providerToken, ready: value.ready, session: value.session, backend: API_BASE || "same-origin", lens } as const;
}

export const queryKeys = {
  family: (scope: ReturnType<typeof useQueryScope>, resource: string) => ["phorvex", scope.backend, scope.identity, scope.lens, resource] as const,
  targets: (scope: ReturnType<typeof useQueryScope>) => [...queryKeys.family(scope, "targets")] as const,
  workloads: (scope: ReturnType<typeof useQueryScope>, context: string) => [...queryKeys.family(scope, "workloads"), { context }] as const,
  catalog: (scope: ReturnType<typeof useQueryScope>) => [...queryKeys.family(scope, "catalog")] as const,
  reports: (scope: ReturnType<typeof useQueryScope>) => [...queryKeys.family(scope, "reports")] as const,
  report: (scope: ReturnType<typeof useQueryScope>, id: string) => [...queryKeys.family(scope, "report"), { id }] as const,
  runEvidence: (scope: ReturnType<typeof useQueryScope>, id: string) => [...queryKeys.family(scope, "run-evidence"), { id }] as const,
  page: (scope: ReturnType<typeof useQueryScope>, resource: string, network: unknown, cursor?: string) => [...queryKeys.family(scope, resource), network, { cursor: cursor || "latest" }] as const,
  exact: (scope: ReturnType<typeof useQueryScope>, resource: string, context: string, id: string) => [...queryKeys.family(scope, resource), { context, id }] as const,
  read: (scope: ReturnType<typeof useQueryScope>, resource: string, parameters: unknown) => [...queryKeys.family(scope, resource), parameters] as const,
  scan: (scope: ReturnType<typeof useQueryScope>, context: string, namespace: string) => [...queryKeys.family(scope, "scan"), { context, namespace }] as const,
};

/** Shared boundary for authenticated GETs. Keys must contain every wire parameter. */
export function useApiRead<T>({ lens, resource, parameters = null, fetcher, staleTime = 30_000, enabled = true, refetchInterval }: {
  lens: Lens; resource: string; parameters?: unknown; fetcher: (signal: AbortSignal) => Promise<T>;
  staleTime?: number; enabled?: boolean; refetchInterval?: number | false;
}) {
  const scope = useQueryScope(lens);
  const query = useQuery<T>({
    queryKey: queryKeys.read(scope, resource, parameters), queryFn: ({ signal }) => fetcher(signal),
    enabled: scope.ready && enabled, staleTime, gcTime: QUERY_GC, refetchOnWindowFocus: false, refetchInterval,
  });
  return { ...query, data: enabled ? authorizedData(query.data, query.error) : undefined };
}

/** A scan is an expensive read/exec: one exact identity+lens+context+namespace snapshot until explicit refetch. */
export function useScanSnapshot(lens: Lens, context: string, namespace: string, autoFetch = true) {
  const scope = useQueryScope(lens);
  const query = useQuery<ScanResult>({
    queryKey: queryKeys.scan(scope, context, namespace),
    queryFn: ({ signal }) => api.scan(namespace, lens, context, signal),
    enabled: scope.ready && autoFetch && lens !== "owner", staleTime: Infinity, gcTime: QUERY_GC,
    refetchOnMount: false, refetchOnWindowFocus: false, retry: false,
  });
  const refetch = React.useCallback((options?: Parameters<typeof query.refetch>[0]) => {
    if (!scope.ready || lens === "owner") return Promise.resolve({ ...query, data: undefined } as Awaited<ReturnType<typeof query.refetch>>);
    return query.refetch(options);
  }, [lens, query, scope.ready]);
  return { ...query, refetch, data: authorizedData(query.data, query.error) };
}

// A single 2.5s bounded sample is shared by exact identity+lens+context+tenant for 30s.
// `_settleMs` remains accepted for source compatibility; varying callers cannot race one key
// with different sampling semantics.
export function useAuditSnapshot(lens: Lens, context: string, tenant = "", _settleMs = 2500, enabled = true) {
  const query = useApiRead<any[]>({
    lens, resource: "audit-snapshot", parameters: { context, tenant, tail: 80 }, staleTime: 30_000, enabled,
    fetcher: (signal) => new Promise((resolve, reject) => {
      const records = new Map<string, any>();
      let stop = () => {};
      let settled = false;
      const cleanup = () => { clearTimeout(timer); signal.removeEventListener("abort", abort); stop(); };
      const finish = () => { if (settled) return; settled = true; cleanup(); resolve(Array.from(records.values())); };
      const timer = setTimeout(finish, 2500);
      const abort = () => { if (settled) return; settled = true; cleanup(); reject(new DOMException("Aborted", "AbortError")); };
      const fail = (error: unknown) => { if (settled) return; settled = true; cleanup(); reject(error instanceof Error ? error : new Error("Decision stream failed")); };
      signal.addEventListener("abort", abort, { once: true });
      try { stop = liveStream(lens, (event) => { if (event.pod) records.set(`${event.namespace}/${event.pod}`, event); }, tenant || undefined, 80, context, fail); }
      catch (error) { fail(error); }
    }),
  });
  // EventSource does not expose its HTTP status. A failed sample could be a denial, so never
  // retain rows from an earlier successful sample behind a generic stream error.
  return { ...query, data: query.error ? undefined : query.data };
}

export function useTargets(lens: Lens) {
  const scope = useQueryScope(lens);
  const query = useQuery<{ targets: ClusterTarget[] }>({ queryKey: queryKeys.targets(scope), queryFn: ({ signal }) => api.targets(lens, signal), enabled: scope.ready, staleTime: 30_000 });
  const data = authorizedData(query.data, query.error);
  return { ...query, data: data ? { ...data, targets: data.targets ?? [] } : undefined };
}

function authorizedData<T>(data: T | undefined, error: unknown): T | undefined {
  return error instanceof ApiError && (error.status === 401 || error.status === 403) ? undefined : data;
}

export function useWorkloads(context: string, lens: Lens, enabled = true) {
  const scope = useQueryScope(lens);
  const query = useQuery<{ context: string; namespaces: WorkloadNS[] }>({ queryKey: queryKeys.workloads(scope, context), queryFn: ({ signal }) => api.workloads(context, lens, signal), enabled: scope.ready && enabled && !!context, staleTime: 10_000 });
  const data = enabled && !!context ? authorizedData(query.data, query.error) : undefined;
  return { ...query, data: data ? { ...data, namespaces: data.namespaces ?? [] } : undefined };
}

export function useCatalog(lens: Lens) {
  const scope = useQueryScope(lens);
  const query = useQuery<{ items: CatalogItem[] }>({ queryKey: queryKeys.catalog(scope), queryFn: ({ signal }) => api.catalog(lens, signal), enabled: scope.ready, staleTime: 60_000 });
  const data = authorizedData(query.data, query.error);
  return { ...query, data: data ? { ...data, items: data.items ?? [] } : undefined };
}

export function useReports(lens: Lens) {
  const scope = useQueryScope(lens);
  const query = useQuery<{ reports: ReportMeta[] }>({ queryKey: queryKeys.reports(scope), queryFn: ({ signal }) => api.reports(lens, signal), enabled: scope.ready, staleTime: 20_000 });
  const data = authorizedData(query.data, query.error);
  return { ...query, data: data ? { ...data, reports: data.reports ?? [] } : undefined };
}

export function useReport(id: string, lens: Lens) {
  const scope = useQueryScope(lens);
  const query = useQuery({ queryKey: queryKeys.report(scope, id), queryFn: ({ signal }) => api.report(id, lens, signal), enabled: scope.ready && !!id, staleTime: 20_000 });
  return { ...query, data: id ? authorizedData(query.data, query.error) : undefined };
}

export function useRunEvidence(id: string, lens: Lens) {
  const scope = useQueryScope(lens);
  const query = useQuery<RunEvidence>({ queryKey: queryKeys.runEvidence(scope, id), queryFn: ({ signal }) => api.runEvidence(id, lens, signal), enabled: scope.ready && !!id, staleTime: 10_000 });
  return { ...query, data: id ? authorizedData(query.data, query.error) : undefined };
}

export function useExactRecord<T>({ resource, context, id, lens, enabled, fetcher, active }: {
  resource: string; context: string; id: string; lens: Lens; enabled: boolean;
  fetcher: (signal: AbortSignal) => Promise<T | null>; active: (record: T) => boolean;
}) {
  const scope = useQueryScope(lens);
  const query = useQuery<T | null>({
    queryKey: queryKeys.exact(scope, resource, context, id),
    queryFn: ({ signal }) => fetcher(signal), enabled: scope.ready && enabled && !!id, staleTime: 0, gcTime: 5 * 60_000,
    refetchOnWindowFocus: false,
    refetchInterval: (query) => query.state.data === null || (query.state.data !== undefined && active(query.state.data)) ? 4_000 : false,
  });
  return { ...query, data: enabled && !!id ? authorizedData(query.data, query.error) : undefined, error: enabled && !!id ? query.error : null };
}

export function useScopedInvalidationBridge() {
  const client = useQueryClient();
  const scopeValue = React.useContext(sessionContext);
  React.useEffect(() => {
    if (!scopeValue) return;
    const onChanged = (event: Event) => {
      const detail = (event as CustomEvent<QueryChange>).detail;
      if (!detail || detail.identity !== scopeValue.identity || detail.providerToken !== scopeValue.providerToken) return;
      const resources = detail.resources;
      resources.forEach((resource) => {
        void client.invalidateQueries({
          predicate: (query) => {
            const tail = query.queryKey[query.queryKey.length - 1] as { cursor?: string } | undefined;
            const network = query.queryKey[5] as { context?: string; tenant?: string; namespace?: string } | undefined;
            const isCursorPage = !!tail && Object.prototype.hasOwnProperty.call(tail, "cursor");
            const exact = query.queryKey[5] as { context?: string; id?: string } | undefined;
            const contextScoped = new Set(["workloads", "runs", "runs-summary", "cost", "uptime", "workload-attacks", "compatibility", "audit-snapshot"]);
            const actualContext = network?.context ?? "";
            const contextMatches = resource === "workloads"
              ? actualContext === (detail.context ?? "")
              : resource === "runs"
                ? actualContext === (detail.context ?? "")
                : resource === "run-status"
                  ? (!detail.context || exact?.context?.split("\u0000")[0] === detail.context) && (!detail.runId || exact?.id === detail.runId)
                  : resource === "run-evidence"
                    ? !detail.runId || exact?.id === detail.runId
                    : contextScoped.has(resource) && detail.context && network?.context
                    ? network.context === detail.context
                    : contextScoped.has(resource)
                      ? actualContext === (detail.context ?? "")
                      : resource === "owner-events" && network?.tenant
                        ? false
                        : true;
            return query.queryKey[0] === "phorvex" && query.queryKey[2] === scopeValue.identity && query.queryKey[4] === resource && query.queryKey[3] === detail.lens && contextMatches && (!isCursorPage || tail.cursor === "latest");
          },
          refetchType: scopeValue.ready ? "active" : "none",
        });
      });
    };
    window.addEventListener("phorvex-query-changed", onChanged);
    return () => window.removeEventListener("phorvex-query-changed", onChanged);
  }, [client, scopeValue]);
}

"use client";
import * as React from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Lens, PageMeta } from "@/lib/api";
import { queryKeys, useQueryScope } from "@/lib/query";
import { useScopedUIState } from "@/lib/use-scoped-ui-state";

const EMPTY_ITEMS: never[] = [];
export interface ServerPageResult<T, M = undefined> { items: T[]; page?: PageMeta; meta?: M }
interface Options<T, M> {
  resource: "runs" | "attack-results" | "attack-monitoring" | "availability-arms";
  key: string; network: Record<string, string | number | undefined>; lens: Lens; pageSize: number;
  fetchPage: (cursor: string | undefined, signal: AbortSignal) => Promise<ServerPageResult<T, M>>;
  legacyFilter?: (item: T) => boolean; pollMs?: number;
}

export function useServerPage<T, M = undefined>({ resource, key, network, lens, pageSize, fetchPage, legacyFilter, pollMs }: Options<T, M>) {
  const scope = useQueryScope(lens);
  const client = useQueryClient();
  const [nav, setNav] = useScopedUIState<{ key: string; page: number; cursors: (string | undefined)[]; root?: string }>(`pager\u0000${resource}\u0000${key}`, { key, page: 0, cursors: [undefined] });
  const current = nav.key === key ? nav : { key, page: 0, cursors: [undefined] };
  React.useEffect(() => {
    setNav((value) => value.key === key ? value : { key, page: 0, cursors: [undefined] });
  }, [key]);
  const page = current.page;
  const [latestGeneration, setLatestGeneration] = useScopedUIState(`pager-generation\u0000${resource}\u0000${key}`, 0);
  const networkIdentity = semanticNetworkIdentity(network);
  const stableNetwork = React.useMemo(() => networkFromIdentity(networkIdentity), [networkIdentity]);
  const legacyKey = React.useMemo(() => [...queryKeys.page(scope, resource, { resource, ...stableNetwork, limit: pageSize }, "legacy-snapshot"), key] as const, [key, pageSize, resource, scope.backend, scope.identity, scope.lens, stableNetwork]);
  const failureKey = React.useMemo(() => [...legacyKey, "failure"] as const, [legacyKey]);
  const legacySnapshot = client.getQueryData<{ key: string; value: ServerPageResult<T, M>; updatedAt: number }>(legacyKey);
  const [, setSnapshotFailureRevision] = React.useState(0);
  const snapshotFailure = client.getQueryData<{ key: string; message: string }>(failureKey);
  const setSnapshotFailure = React.useCallback((value: { key: string; message: string }) => {
    if (value.message) client.setQueryData(failureKey, value);
    else client.removeQueries({ queryKey: failureKey, exact: true });
    setSnapshotFailureRevision((revision) => revision + 1);
  }, [client, failureKey]);
  const retryGeneration = React.useRef(0);
  const retryController = React.useRef<AbortController>();
  const snapshotError = snapshotFailure?.key === key ? snapshotFailure.message : "";
  const cursor = current.cursors[page];
  const frozen = page > 0 || !!current.root;
  const frozenLegacy = frozen && legacySnapshot?.key === key;
  const expiredLegacy = frozen && current.root === "legacy" && !frozenLegacy;
  const query = useQuery({
    queryKey: queryKeys.page(scope, resource, { resource, ...network, limit: pageSize, generation: frozen ? 0 : latestGeneration }, frozenLegacy ? `legacy:${page}` : cursor),
    queryFn: ({ signal }) => fetchPage(cursor, signal),
    enabled: scope.ready && !frozenLegacy && !expiredLegacy,
    staleTime: frozen ? Infinity : Math.max(1_000, pollMs || 10_000),
    gcTime: 5 * 60_000,
    refetchOnWindowFocus: false,
    refetchOnReconnect: !frozen,
    refetchOnMount: !frozen,
    refetchInterval: !frozen && pollMs ? pollMs : false,
  });

  const queryData = authorizedPageData(query.data, query.error);
  const authorizationFailure = isAuthorizationFailure(query.error);
  const raw = !snapshotError && !authorizationFailure && !expiredLegacy ? (frozenLegacy ? legacySnapshot.value : queryData) : undefined;
  const legacy = !!raw && !raw.page;
  const all = React.useMemo(() => legacy && legacyFilter ? raw!.items.filter(legacyFilter) : raw?.items || EMPTY_ITEMS as T[], [legacy, legacyFilter, raw]);
  const resolvedPage = legacy ? Math.min(page, Math.max(0, Math.ceil(all.length / pageSize) - 1)) : page;
  React.useEffect(() => { if (legacy && resolvedPage !== page) setNav((value) => value.key === key ? { ...value, page: resolvedPage } : value); }, [key, legacy, page, resolvedPage]);
  const items = legacy ? all.slice(resolvedPage * pageSize, (resolvedPage + 1) * pageSize) : all;
  const pageMeta = raw?.page || (raw ? { limit: pageSize, total: all.length, nextCursor: (resolvedPage + 1) * pageSize < all.length ? "legacy" : undefined } : undefined);

  const next = React.useCallback(() => {
    if (!pageMeta?.nextCursor) return;
    if (legacy && raw) client.setQueryData(legacyKey, { key, value: raw, updatedAt: frozenLegacy ? legacySnapshot.updatedAt : query.dataUpdatedAt });
    setNav((value) => {
      const base = value.key === key ? value : { key, page: 0, cursors: [undefined] };
      const cursors = [...base.cursors];
      let root = base.root || (legacy ? "legacy" : undefined);
      if (!legacy) {
        if (base.page === 0 && pageMeta.currentCursor) { cursors[0] = pageMeta.currentCursor; root = pageMeta.currentCursor; }
        cursors[base.page + 1] = pageMeta.nextCursor;
      }
      return { ...base, cursors, root, page: base.page + 1 };
    });
  }, [client, frozenLegacy, key, legacy, legacyKey, legacySnapshot, pageMeta, query.dataUpdatedAt, raw]);
  const previous = React.useCallback(() => setNav((value) => value.key === key ? { ...value, page: Math.max(0, value.page - 1) } : value), [key]);
  const latest = React.useCallback(() => {
    retryGeneration.current++;
    retryController.current?.abort();
    retryController.current = undefined;
    setNav({ key, page: 0, cursors: [undefined] });
    client.removeQueries({ queryKey: legacyKey, exact: true });
    client.removeQueries({ queryKey: failureKey, exact: true });
    setSnapshotFailure({ key, message: "" });
    setLatestGeneration((n) => n + 1);
  }, [client, failureKey, key, legacyKey, setLatestGeneration, setNav]);
  React.useLayoutEffect(() => {
    retryGeneration.current++;
    retryController.current?.abort();
    retryController.current = undefined;
    return () => {
      retryGeneration.current++;
      retryController.current?.abort();
      retryController.current = undefined;
    };
  }, [key, scope.identity, scope.providerToken, scope.ready]);
  const retry = React.useCallback(() => {
    if (!scope.ready) return;
    if (expiredLegacy) { latest(); return; }
    if (!frozenLegacy) { void query.refetch(); return; }
    retryController.current?.abort();
    const controller = new AbortController();
    retryController.current = controller;
    const generation = ++retryGeneration.current;
    void fetchPage(undefined, controller.signal).then(() => {
      if (generation !== retryGeneration.current || controller.signal.aborted) return;
      setSnapshotFailure({ key, message: "" });
    }).catch((error) => {
      if (generation !== retryGeneration.current || controller.signal.aborted) return;
      setSnapshotFailure({ key, message: String((error as Error).message || error) });
    }).finally(() => {
      if (generation === retryGeneration.current && retryController.current === controller) retryController.current = undefined;
    });
  }, [expiredLegacy, fetchPage, frozenLegacy, key, latest, query, scope.ready, setSnapshotFailure]);

  return {
    items, meta: raw?.meta, pageMeta, page: resolvedPage,
    loading: !expiredLegacy && !frozenLegacy && (query.isPending || (query.isFetching && !raw)), refreshing: !frozenLegacy && query.isFetching && !!raw,
    error: expiredLegacy ? "This frozen legacy snapshot expired. Choose Latest or Retry to load current membership." : snapshotError || (query.error ? String((query.error as Error).message || query.error) : ""),
    legacy, hasNext: !!pageMeta?.nextCursor, hasSnapshot: frozen, updatedAt: frozenLegacy ? legacySnapshot.updatedAt : query.dataUpdatedAt,
    next, previous, latest, retry,
  };
}

type NetworkIdentityEntry = readonly [string, readonly ["undefined"] | readonly ["string", string] | readonly ["number", number]];

function semanticNetworkIdentity(network: Record<string, string | number | undefined>) {
  return JSON.stringify(Object.keys(network).sort().map((name): NetworkIdentityEntry => {
    const value = network[name];
    if (value === undefined) return [name, ["undefined"]];
    return typeof value === "number" ? [name, ["number", value]] : [name, ["string", value]];
  }));
}

function networkFromIdentity(identity: string): Record<string, string | number | undefined> {
  return Object.fromEntries((JSON.parse(identity) as NetworkIdentityEntry[]).map(([name, encoded]) => [name, encoded[0] === "undefined" ? undefined : encoded[1]]));
}

function authorizedPageData<T>(data: T | undefined, error: unknown) {
  return isAuthorizationFailure(error) ? undefined : data;
}

function isAuthorizationFailure(error: unknown) {
  return error instanceof Error && "status" in error && ((error as Error & { status: number }).status === 401 || (error as Error & { status: number }).status === 403);
}

"use client";
import * as React from "react";

// Presentation state only (never response data). A small LRU keeps warm-tab choices for this page
// lifetime without persistent sensitive storage or an ever-growing per-scope map.
const MAX_SCOPES = 64;

export interface ScopedUIStore {
  read<T>(key: string, fallback: T): T;
  write<T>(key: string, value: T): void;
  subscribe(key: string, listener: () => void): () => void;
}

export function createScopedUIStore(): ScopedUIStore {
  const values = new Map<string, unknown>();
  const listeners = new Map<string, Set<() => void>>();
  return {
    read: (key, fallback) => values.has(key) ? values.get(key) as typeof fallback : fallback,
    write: (key, value) => {
      values.delete(key);
      values.set(key, value);
      while (values.size > MAX_SCOPES) values.delete(values.keys().next().value as string);
      listeners.get(key)?.forEach((listener) => listener());
    },
    subscribe: (key, listener) => {
      const set = listeners.get(key) || new Set<() => void>();
      set.add(listener); listeners.set(key, set);
      return () => { set.delete(listener); if (!set.size) listeners.delete(key); };
    },
  };
}

const scopedUIContext = React.createContext<ScopedUIStore | null>(null);
export const ScopedUIProvider = scopedUIContext.Provider;

export function useScopedUIState<T>(key: string, initial: T) {
  const store = React.useContext(scopedUIContext);
  if (!store) throw new Error("Scoped UI state requires a session provider");
  const fallbackRef = React.useRef<{ key: string; value: T }>({ key, value: initial });
  if (fallbackRef.current.key !== key) fallbackRef.current = { key, value: initial };
  const subscribe = React.useCallback((listener: () => void) => store.subscribe(key, listener), [key, store]);
  const getSnapshot = React.useCallback(() => store.read(key, fallbackRef.current.value), [key, store]);
  const value = React.useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
  const setScoped = React.useCallback((next: React.SetStateAction<T>) => {
    const current = store.read(key, fallbackRef.current.value);
    const resolved = typeof next === "function" ? (next as (old: T) => T)(current) : next;
    store.write(key, resolved);
  }, [key, store]);
  return [value, setScoped] as const;
}

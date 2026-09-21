"use client";

import * as React from "react";

export function useLocalPage<T>(items: readonly T[], pageSize: number, resetKey: string) {
  const [pageState, setPageState] = React.useState({ key: resetKey, page: 0 });
  const pageCount = Math.max(1, Math.ceil(items.length / pageSize));
  const page = pageState.key === resetKey ? Math.min(pageState.page, pageCount - 1) : 0;
  React.useLayoutEffect(() => {
    setPageState((current) => current.key === resetKey && current.page === page
      ? current
      : { key: resetKey, page });
  }, [page, resetKey]);
  const setPage = React.useCallback<React.Dispatch<React.SetStateAction<number>>>((next) => {
    setPageState((current) => {
      const currentPage = current.key === resetKey ? Math.min(current.page, pageCount - 1) : 0;
      const requested = typeof next === "function" ? next(currentPage) : next;
      return { key: resetKey, page: Math.max(0, Math.min(requested, pageCount - 1)) };
    });
  }, [pageCount, resetKey]);

  const start = page * pageSize;
  return {
    page,
    setPage,
    pageItems: items.slice(start, start + pageSize),
    start,
    end: Math.min(start + pageSize, items.length),
    hasNext: page + 1 < pageCount,
  };
}

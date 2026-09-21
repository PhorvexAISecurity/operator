"use client";
import { Button } from "@/components/ui/primitives";

export interface PaginationBarProps {
  page: number;
  pageSize: number;
  total?: number;
  hasNext: boolean;
  onPrevious: () => void;
  onNext: () => void;
  onLatest?: () => void;
  showLatest?: boolean;
  loading?: boolean;
}

export function PaginationBar({ page, pageSize, total, hasNext, onPrevious, onNext, onLatest, showLatest, loading }: PaginationBarProps) {
  const start = total === undefined ? undefined : total === 0 ? 0 : page * pageSize + 1;
  const end = total === undefined ? undefined : Math.min(total, (page + 1) * pageSize);
  return (
    <nav aria-label="History pages" className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
      <span aria-live="polite">{total === undefined ? "Page range unavailable" : `Showing ${start}–${end} of ${total}`}</span>
      <Button size="sm" variant="outline" onClick={onPrevious} disabled={loading || page === 0} aria-label="Previous page">Previous</Button>
      <Button size="sm" variant="outline" onClick={onNext} disabled={loading || !hasNext} aria-label="Next page">Next</Button>
      {onLatest && (showLatest ?? page > 0) && <Button size="sm" variant="outline" onClick={onLatest} disabled={loading}>Latest</Button>}
    </nav>
  );
}

export function DataFreshness({ updatedAt, refreshing, failed }: { updatedAt: number; refreshing: boolean; failed: boolean }) {
  if (!updatedAt) return null;
  return <div className={failed ? "text-[11px] text-warning" : "text-[11px] text-muted-foreground"}>
    Updated {new Date(updatedAt).toLocaleTimeString()}{refreshing ? " · refreshing…" : failed ? " · refresh failed" : ""}
  </div>;
}

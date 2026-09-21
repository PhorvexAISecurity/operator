"use client";
import * as React from "react";
import { cn } from "@/lib/utils";
import { Card, CardContent, Badge } from "./primitives";
import { Lock, Loader2, AlertTriangle, Inbox, ChevronDown } from "lucide-react";

/* Segmented tabs (in-panel) */
export function Segmented<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string; count?: number }[]; value: T; onChange: (t: T) => void }) {
  return (
    <div role="group" aria-label="Panel views" className="inline-flex max-w-full flex-wrap items-center gap-1 rounded-lg border border-border bg-panel/60 p-1">
      {tabs.map((t) => (
        <button type="button" key={t.id} aria-pressed={value === t.id} onClick={() => onChange(t.id)}
          className={cn("flex max-w-full items-center gap-1.5 whitespace-normal rounded-md px-3 py-1.5 text-left text-[12px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
            value === t.id ? "bg-elevated text-foreground ring-1 ring-border" : "text-muted-foreground hover:text-foreground")}>
          {t.label}{typeof t.count === "number" && <span className="rounded bg-muted/60 px-1.5 text-[10px] tabular text-muted-foreground">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

/* Keep the common path compact while leaving specialist views one obvious click away. */
export function GroupedSegmented<T extends string>({
  primary, secondary, value, onChange, moreLabel = "More details",
}: {
  primary: { id: T; label: string; count?: number }[];
  secondary: { id: T; label: string; count?: number }[];
  value: T;
  onChange: (t: T) => void;
  moreLabel?: string;
}) {
  const secondaryActive = secondary.some((tab) => tab.id === value);
  const [expanded, setExpanded] = React.useState(secondaryActive);
  React.useEffect(() => {
    if (secondaryActive) setExpanded(true);
  }, [secondaryActive]);
  const activeSecondary = secondary.find((tab) => tab.id === value);
  const regionId = React.useId();

  return (
    <div className="space-y-2">
      <div className="flex max-w-full flex-wrap items-start gap-2">
        <Segmented tabs={primary} value={value} onChange={(next) => { setExpanded(false); onChange(next); }} />
        {secondary.length > 0 && (
          <button
            type="button"
            aria-expanded={expanded}
            aria-controls={regionId}
            onClick={() => setExpanded((open) => !open)}
            className={cn(
              "flex items-center gap-1.5 rounded-lg border border-border bg-panel/60 px-3 py-2 text-left text-[12px] font-medium transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
              secondaryActive ? "text-foreground ring-1 ring-border" : "text-muted-foreground",
            )}
          >
            <span>{moreLabel}{activeSecondary ? ` · ${activeSecondary.label}` : ""}</span>
            <ChevronDown className={cn("h-3.5 w-3.5 shrink-0 transition-transform", expanded && "rotate-180")} />
          </button>
        )}
      </div>
      {expanded && secondary.length > 0 && (
        <div id={regionId} aria-label={`${moreLabel} views`}>
          <Segmented tabs={secondary} value={value} onChange={onChange} />
        </div>
      )}
    </div>
  );
}

/* Input */
export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input ref={ref} className={cn("h-9 w-full rounded-md border border-input bg-elevated/40 px-3 text-sm text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring", className)} {...props} />
  )
);
Input.displayName = "Input";

/* Table shells */
export function Table({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className="overflow-x-auto"><table className={cn("w-full text-sm", className)}>{children}</table></div>;
}
export function THead({ children }: { children: React.ReactNode }) {
  return <thead><tr className="border-b border-border text-left text-[11px] uppercase tracking-wider text-muted-foreground">{children}</tr></thead>;
}
export function TH({ children, className }: { children: React.ReactNode; className?: string }) {
  return <th className={cn("px-4 py-2.5 font-medium", className)}>{children}</th>;
}
export function TR({ children, className, onClick }: { children: React.ReactNode; className?: string; onClick?: () => void }) {
  return <tr onClick={onClick} className={cn("border-b border-border/50 transition-colors hover:bg-elevated/40", onClick && "cursor-pointer", className)}>{children}</tr>;
}
export function TD({ children, className }: { children: React.ReactNode; className?: string }) {
  return <td className={cn("px-4 py-2.5", className)}>{children}</td>;
}

/* Dialog (modal) */
export function Dialog({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: string; children: React.ReactNode }) {
  const titleId = React.useId();
  const dialogRef = React.useRef<HTMLDivElement>(null);
  const onCloseRef = React.useRef(onClose);
  React.useEffect(() => { onCloseRef.current = onClose; }, [onClose]);
  React.useEffect(() => {
    if (!open) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const dialog = dialogRef.current;
    const focusable = () => Array.from(dialog?.querySelectorAll<HTMLElement>('button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])') || []).filter((item) => item.getClientRects().length > 0);
    (focusable()[0] || dialog)?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") { event.preventDefault(); onCloseRef.current(); return; }
      if (event.key !== "Tab") return;
      const items = focusable();
      if (items.length === 0) { event.preventDefault(); dialog?.focus(); return; }
      const first = items[0], last = items[items.length - 1];
      const active = document.activeElement;
      if (!dialog?.contains(active)) { event.preventDefault(); (event.shiftKey ? last : first).focus(); }
      else if (event.shiftKey && active === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && active === last) { event.preventDefault(); first.focus(); }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => { window.removeEventListener("keydown", onKeyDown); previous?.focus(); };
  }, [open]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="absolute inset-0 bg-background/70 backdrop-blur-sm" />
      <div ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby={titleId} onClick={(e) => e.stopPropagation()} className="animate-fade-up relative max-h-[80vh] w-full max-w-3xl overflow-hidden rounded-xl border border-border bg-panel shadow-2xl">
        <div className="flex items-center justify-between border-b border-border px-5 py-3">
          <h3 id={titleId} className="text-sm font-semibold">{title}</h3>
          <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded-md px-2 py-1 text-muted-foreground hover:bg-elevated hover:text-foreground">✕</button>
        </div>
        <div className="max-h-[68vh] overflow-y-auto p-5">{children}</div>
      </div>
    </div>
  );
}

/* Systematic states */
export function Loading({ label = "Loading…", rows = 4 }: { label?: string; rows?: number }) {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-[12px] text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" />{label}</div>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {Array.from({ length: rows }).map((_, i) => <div key={i} className="h-28 animate-pulse-soft rounded-lg border border-border bg-panel/50" />)}
      </div>
    </div>
  );
}
export function ErrorBox({ msg }: { msg: string }) {
  const down = msg.includes("BACKEND_UNREACHABLE");
  return (
    <Card className="border-warning/30"><CardContent className="flex items-start gap-3 p-5 text-sm">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
      {down ? (
        <div>
          <div className="font-medium text-foreground">Cannot reach the data service.</div>
          <div className="mt-1 text-muted-foreground">Check your connection and retry this view. If the problem continues, contact your Phorvex administrator.</div>
        </div>
      ) : (
        <div><span className="font-medium text-foreground">Couldn’t load this panel.</span> <span className="text-muted-foreground">{msg}</span></div>
      )}
    </CardContent></Card>
  );
}
export function ReadStatus({ error, hasData, refreshing, updatedAt, onRetry }: { error: unknown; hasData: boolean; refreshing?: boolean; updatedAt?: number; onRetry: () => void }) {
  if (!error && !refreshing) return null;
  const message = error ? String((error as Error).message || error) : "";
  if (error && !hasData) return <div className="space-y-2"><ErrorBox msg={message} /><button type="button" className="text-xs text-primary underline" onClick={onRetry}>Retry</button></div>;
  return <div role={error ? "alert" : "status"} className="rounded-md border border-warning/30 bg-warning/[0.04] px-3 py-2 text-xs text-muted-foreground">
    {error ? "Showing the last authorized snapshot; refresh failed." : "Refreshing this snapshot…"}
    {updatedAt ? ` Updated ${new Date(updatedAt).toLocaleTimeString()}.` : ""}
    {error && <button type="button" className="ml-2 text-primary underline" onClick={onRetry}>Retry</button>}
  </div>;
}
export function Empty({ msg }: { msg: string }) {
  return (
    <Card><CardContent className="flex flex-col items-center gap-2 py-12 text-center text-sm text-muted-foreground">
      <Inbox className="h-5 w-5" />{msg}
    </CardContent></Card>
  );
}
export function Pending({ stage, msg }: { stage: string; msg: string }) {
  return (
    <div className="flex items-center gap-2 rounded-lg border border-warning/25 bg-warning/[0.05] px-4 py-2.5 text-[12px] text-muted-foreground">
      <Lock className="h-3.5 w-3.5 text-warning" /><Badge variant="pending">{stage}</Badge><span>{msg}</span>
    </div>
  );
}

/* small helpers */
export function csvDownload(filename: string, rows: (string | number)[][]) {
  const csv = rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

"use client";
import * as React from "react";
import { cn } from "@/lib/utils";
import { Card, CardContent, Badge } from "./primitives";
import { Lock, Loader2, AlertTriangle, Inbox } from "lucide-react";

/* Segmented tabs (in-panel) */
export function Segmented<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string; count?: number }[]; value: T; onChange: (t: T) => void }) {
  return (
    <div className="inline-flex items-center gap-1 rounded-lg border border-border bg-panel/60 p-1">
      {tabs.map((t) => (
        <button key={t.id} onClick={() => onChange(t.id)}
          className={cn("flex items-center gap-1.5 rounded-md px-3 py-1.5 text-[12px] font-medium transition-colors",
            value === t.id ? "bg-elevated text-foreground ring-1 ring-border" : "text-muted-foreground hover:text-foreground")}>
          {t.label}{typeof t.count === "number" && <span className="rounded bg-muted/60 px-1.5 text-[10px] tabular text-muted-foreground">{t.count}</span>}
        </button>
      ))}
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
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="absolute inset-0 bg-background/70 backdrop-blur-sm" />
      <div onClick={(e) => e.stopPropagation()} className="animate-fade-up relative max-h-[80vh] w-full max-w-3xl overflow-hidden rounded-xl border border-border bg-panel shadow-2xl">
        <div className="flex items-center justify-between border-b border-border px-5 py-3">
          <h3 className="text-sm font-semibold">{title}</h3>
          <button onClick={onClose} className="rounded-md px-2 py-1 text-muted-foreground hover:bg-elevated hover:text-foreground">✕</button>
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
          <div className="font-medium text-foreground">Data backend isn’t running.</div>
          <div className="mt-1 text-muted-foreground">Start the Phorvex console (it serves this app + the data on one port):</div>
          <code className="mt-2 block rounded-md bg-elevated/60 px-3 py-2 font-mono text-[12px] text-foreground/90">phorvex\bin\phorvex-console.exe --root C:\Users\moh87733\Phorvex</code>
          <div className="mt-1.5 text-[11px] text-muted-foreground/70">then refresh. This panel shows real data once the backend is up.</div>
        </div>
      ) : (
        <div><span className="font-medium text-foreground">Couldn’t load this panel.</span> <span className="text-muted-foreground">{msg}</span></div>
      )}
    </CardContent></Card>
  );
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

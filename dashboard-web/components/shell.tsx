"use client";
import * as React from "react";
import { cn } from "@/lib/utils";
import { Lens, api, ClusterTarget, Session } from "@/lib/api";
import { STEPS, StepId, JourneySignals, stepState } from "@/lib/journey";
import { useSelectedTarget, setSelectedTarget } from "@/lib/provider-store";
import { Activity, ShieldCheck, Lock, Check, PlayCircle, Home, ChevronRight, Server, ChevronDown, Sun, Moon } from "lucide-react";
import { useApiRead, useTargets } from "@/lib/query";

const LENS_META: Record<Lens, { label: string; hint: string }> = {
  investor: { label: "Investor", hint: "the moat + the proofs" },
  operator: { label: "Operator", hint: "live defense + run methods" },
  owner: { label: "Customer-Owner", hint: "what changed in my platform (IP-walled)" },
};

// ProviderSelector — the GLOBAL provider/cluster switch. Picking vCluster scopes every scoped view
// (workloads, Live Ops, run-history, scan) to that provider via the shared provider-store.
// ThemeToggle flips the root class the palette hangs off, and remembers the choice. It READS the
// current class on mount rather than assuming a default, so it always agrees with the pre-paint
// boot script in layout.tsx instead of fighting it on first render.
function ThemeToggle() {
  const [light, setLight] = React.useState(false);
  React.useEffect(() => { setLight(document.documentElement.classList.contains("light")); }, []);
  const flip = () => {
    const next = !light;
    const c = document.documentElement.classList;
    c.add(next ? "light" : "dark");
    c.remove(next ? "dark" : "light");
    try { localStorage.setItem("phorvex-theme", next ? "light" : "dark"); } catch {}
    setLight(next);
  };
  return (
    <button onClick={flip} aria-label={light ? "Switch to dark theme" : "Switch to light theme"}
      title={light ? "Switch to dark theme" : "Switch to light theme"}
      className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-border bg-elevated/40 text-muted-foreground transition-colors hover:text-foreground">
      {light ? <Moon className="h-3.5 w-3.5" /> : <Sun className="h-3.5 w-3.5" />}
    </button>
  );
}

// SessionBadge states, in one place, who the server says you are and what it granted — so an
// unavailable panel reads as "your grant does not cover this" rather than as a broken console.
function SessionBadge({ session, error }: { session: Session | null; error: string }) {
  if (error) {
    return (
      <span className="hidden min-w-0 max-w-64 items-center gap-1 text-[10px] text-warning 2xl:flex" title={error}>
        <Lock className="h-3 w-3 shrink-0" /> <span className="truncate">{error}</span>
      </span>
    );
  }
  if (!session) {
    return <span className="hidden text-[10px] text-muted-foreground/70 2xl:flex">resolving session…</span>;
  }
  const scope = session.tenants.includes("*") ? "all tenants" : `${session.tenants.length} tenant(s)`;
  return (
    <span
      className="hidden min-w-0 max-w-64 items-center gap-1 text-[10px] text-muted-foreground/70 2xl:flex"
      title={`${session.grantsConfigured ? "Verified server grant" : "Demo/fixture trust mode (no configured grants)"}: ${session.source === "alb" ? "ALB Cognito" : "bearer"} identity ${session.subject}. ${session.note || "The lens only narrows this view."}`}
    >
      <Lock className="h-3 w-3 shrink-0" /> <span className="truncate">{session.subject} · {session.roles.join("/") || "no role"} · {scope}</span>
    </span>
  );
}

function ProviderSelector({ lens }: { lens: Lens }) {
  const [open, setOpen] = React.useState(false);
  const sel = useSelectedTarget();
  const targetQuery = useTargets(lens);
  const targets = targetQuery.data?.targets || [];
  React.useEffect(() => setOpen(false), [lens]);
  React.useEffect(() => {
    if (!sel.context && targets.length) {
        const def = targets.find((t) => t.runnable && /eks|arn:aws/i.test(t.context || t.id)) ?? targets.find((t) => t.runnable) ?? targets[0];
        if (def) setSelectedTarget({ context: def.context || "", provider: def.provider, label: def.label });
    }
  }, [sel.context, targetQuery.data]);
  const current = sel.context ? targets.find((t) => t.context === sel.context) : undefined;
  const currentLabel = current?.label || (!sel.context ? sel.label : "") || (sel.context ? "Scope unavailable" : "Select provider");
  return (
    <div className="relative min-w-0">
      <button onClick={() => setOpen((v) => !v)}
        className="flex min-w-0 max-w-[10rem] items-center gap-2 rounded-lg border border-border bg-panel/60 px-3 py-1.5 text-[12px] transition-colors hover:bg-elevated lg:max-w-[14rem]"
        title={`Provider/cluster scope: ${currentLabel}. Every view shows only this provider's data.`}>
        <Server className="h-3.5 w-3.5 shrink-0 text-primary" />
        <span className="min-w-0 truncate font-medium text-foreground">{currentLabel}</span>
        <ChevronDown className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute left-0 z-50 mt-1 w-[min(18rem,calc(100vw-1.5rem))] rounded-lg border border-border bg-background/95 p-1 shadow-xl backdrop-blur-xl md:left-auto md:right-0">
            <div className="px-2 py-1 text-[10px] uppercase tracking-wide text-muted-foreground">Scope all views to</div>
            {targets.map((t) => (
              <button key={t.id} disabled={!t.runnable}
                onClick={() => { if (t.runnable) { setSelectedTarget({ context: t.context || "", provider: t.provider, label: t.label }); setOpen(false); } }}
                className={cn("flex w-full items-center justify-between gap-2 rounded-md px-2 py-1.5 text-left text-[12px] transition-colors",
                  t.context === sel.context ? "bg-primary/10 text-foreground" : "text-muted-foreground hover:bg-elevated hover:text-foreground", !t.runnable && "opacity-40")}>
                <span className="flex min-w-0 items-center gap-2"><Server className="h-3.5 w-3.5 shrink-0" /> <span className="truncate font-medium">{t.label}</span></span>
                {t.context === sel.context ? <Check className="h-3.5 w-3.5 text-primary" /> : !t.runnable ? <Lock className="h-3 w-3" /> : null}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

export function Shell({
  lens, setLens, session, sessionError, active, go, signals, onDemo, children,
}: {
  lens: Lens; setLens: (l: Lens) => void;
  session: Session | null; sessionError: string;
  active: StepId; go: (s: StepId) => void;
  signals: JourneySignals; onDemo: () => void;
  children: React.ReactNode;
}) {
  // [M-136] The lens selector offers only the roles the SERVER granted this identity. It is a
  // presentation control: picking a lens narrows the view and can never widen the grant, and the
  // server re-checks every request whatever is selected here.
  const grantedLenses = (Object.keys(LENS_META) as Lens[]).filter((l) => !session || session.roles.includes(l));
  return (
    <div className="flex min-h-screen flex-col">
      {/* header */}
      <header className="sticky top-0 z-30 flex h-24 flex-wrap items-center justify-between gap-x-2 border-b border-border bg-background/80 px-3 py-2 backdrop-blur-xl sm:gap-x-3 sm:px-4 md:h-16 md:flex-nowrap md:py-0 lg:px-6">
        <button onClick={() => go("landing")} className="flex shrink-0 items-center gap-2.5">
          <div className="grid h-8 w-8 place-items-center rounded-md bg-primary/15 ring-1 ring-primary/30">
            <Activity className="h-4 w-4 text-primary" strokeWidth={2.5} />
          </div>
          <div className="hidden leading-none text-left sm:block">
            <div className="text-[15px] font-semibold tracking-tight">Phorvex</div>
            <div className="mt-0.5 text-[10px] uppercase tracking-[0.18em] text-muted-foreground">Console</div>
          </div>
        </button>
        <div className="order-3 flex min-w-0 basis-full items-center gap-2 text-[12px] text-muted-foreground md:order-none md:flex-1 md:basis-auto md:justify-center">
          <ShieldCheck className="hidden h-4 w-4 shrink-0 text-success sm:block" />
          <span className="shrink-0">scoped to</span>
          <ProviderSelector lens={lens} />
        </div>
        <div className="flex min-w-0 shrink-0 items-center gap-1 sm:gap-2 xl:gap-3">
          <button onClick={onDemo} className="hidden items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-[12px] text-muted-foreground transition-colors hover:bg-elevated hover:text-foreground lg:flex">
            <PlayCircle className="h-3.5 w-3.5 text-primary" /> Guided demo
          </button>
          <div className="flex min-w-0 items-center gap-1 sm:gap-2">
            <ThemeToggle />
            <SessionBadge session={session} error={sessionError} />
            <select aria-label="View role" value={lens} onChange={(e) => setLens(e.target.value as Lens)} className="min-w-0 max-w-[8.5rem] rounded-lg border border-border bg-panel px-2 py-1.5 text-sm sm:max-w-[155px] xl:hidden">
              {grantedLenses.map((l) => <option key={l} value={l}>{LENS_META[l].label}</option>)}
            </select>
            <div className="hidden items-center gap-1 rounded-lg border border-border bg-panel/60 p-1 xl:flex">
              {grantedLenses.map((l) => (
                <button key={l} onClick={() => setLens(l)} title={LENS_META[l].hint}
                  className={cn("rounded-md px-3 py-1.5 text-[12px] font-medium transition-all", lens === l ? "bg-primary text-primary-foreground shadow-sm" : "text-muted-foreground hover:text-foreground")}>
                  {LENS_META[l].label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </header>

      {signals.diagnosticsError && (
        <div role="status" className="mx-auto max-w-[1400px] px-4 py-2 text-sm text-warning">
          Navigation data unavailable: {signals.diagnosticsError}
        </div>
      )}

      {/* journey bar (the navigation) */}
      <div className="sticky top-24 z-20 border-b border-border bg-panel/40 backdrop-blur-md md:top-16">
        <div className="mx-auto flex max-w-[1400px] items-center gap-1 overflow-x-auto px-4 py-2.5">
          <button onClick={() => go("landing")} title="Overview"
            className={cn("flex shrink-0 items-center gap-1.5 rounded-md px-2.5 py-1.5 text-[12px] transition-colors", active === "landing" ? "bg-elevated text-foreground" : "text-muted-foreground hover:text-foreground")}>
            <Home className="h-3.5 w-3.5" />
          </button>
          {STEPS.map((s, i) => {
            const st = stepState(s.id, signals, active);
            const on = active === s.id;
            return (
              <React.Fragment key={s.id}>
                {i > 0 && <ChevronRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground/40" />}
                <button onClick={() => go(s.id)} disabled={st === "locked"}
                  className={cn("group flex shrink-0 items-center gap-2 rounded-md px-2.5 py-1.5 text-[12px] transition-all",
                    on ? "bg-primary/15 text-foreground ring-1 ring-primary/40" : st === "locked" ? "text-muted-foreground/40" : "text-muted-foreground hover:bg-elevated hover:text-foreground",
                    s.id === "protect" && !on && "ring-1 ring-primary/20")}>
                  <StateDot state={st} n={s.n} />
                  <span className="font-medium">{s.label}</span>
                  {s.id === "protect" && <span className="hidden rounded bg-primary/15 px-1.5 text-[9px] uppercase tracking-wide text-primary lg:inline">run methods</span>}
                </button>
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* step canvas */}
      <main className="relative flex-1 overflow-y-auto">
        <div className="bg-grid pointer-events-none absolute inset-0 h-56" />
        <div className="relative mx-auto max-w-[1400px] px-4 py-7 sm:px-6">{children}</div>
      </main>
      <VersionBadge lens={lens} />
    </div>
  );
}

// VersionBadge — a tiny, unobtrusive bottom-left readout of the LIVE deployed versions, so you can
// confirm at a glance which build is running and whether a roll landed (refreshes every 30s).
function VersionBadge({ lens }: { lens: Lens }) {
  const read = useApiRead({ lens, resource: "version", fetcher: (signal) => api.version(lens, signal), staleTime: 30_000, refetchInterval: 30_000 });
  const v = read.data;
  if (!v) return null;
  return (
    <div className="pointer-events-none fixed bottom-1 left-2 z-40 select-none font-mono text-[9px] leading-[1.35] text-muted-foreground/40">
      <div>operator <span className="text-muted-foreground/70">{v.operator || "—"}</span></div>
      <div>console&nbsp; <span className="text-muted-foreground/70">{v.console}</span></div>
    </div>
  );
}

function StateDot({ state, n }: { state: string; n: number }) {
  if (state === "done") return <span className="grid h-4 w-4 place-items-center rounded-full bg-success/20 text-success"><Check className="h-2.5 w-2.5" strokeWidth={3} /></span>;
  if (state === "active") return <span className="grid h-4 w-4 place-items-center rounded-full bg-primary text-primary-foreground text-[9px] font-bold">{n}</span>;
  if (state === "locked") return <span className="grid h-4 w-4 place-items-center rounded-full bg-muted/40 text-muted-foreground/50"><Lock className="h-2.5 w-2.5" /></span>;
  return <span className="grid h-4 w-4 place-items-center rounded-full border border-border text-[9px] text-muted-foreground">{n}</span>;
}

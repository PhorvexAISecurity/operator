"use client";
import * as React from "react";
import { Lens, Session, api, isUnauthenticated } from "@/lib/api";
import { StepId, useJourneySignals, readStep, goStep } from "@/lib/journey";
import { Shell } from "@/components/shell";
import { Landing } from "@/components/steps/landing";
import { ConnectStep } from "@/components/steps/connect";
import { ScanStep } from "@/components/steps/scan";
import { DiscoveredStep } from "@/components/steps/discovered";
import { AttackLab } from "@/components/steps/attacklab";
import { ProtectStep } from "@/components/steps/protect";
import { ProveStep } from "@/components/steps/prove";
import { ReportStep } from "@/components/steps/report";
import { BenchStep } from "@/components/steps/bench";
import { DemoOverlay } from "@/components/demo/overlay";
import { SessionQueryBoundary, sessionIdentity, useScopedInvalidationBridge } from "@/lib/query";
import type { AuthLostDetail } from "@/lib/query-events";

type SessionState = { session: Session | null; providerToken: string; loading: boolean; error: string };
const newProviderToken = () => crypto.randomUUID();

export default function Page() {
  const [lens, setLens] = React.useState<Lens>("investor");
  const [sessionState, setSessionState] = React.useState<SessionState>({ session: null, providerToken: "", loading: true, error: "" });
  const generation = React.useRef(0);
  const sessionRequest = React.useRef<AbortController | null>(null);
  const sessionStateRef = React.useRef(sessionState);
  const lensRef = React.useRef(lens);
  sessionStateRef.current = sessionState;
  lensRef.current = lens;

  const resolveSession = React.useCallback(() => {
    if (sessionRequest.current) return;
    const controller = new AbortController();
    sessionRequest.current = controller;
    const current = ++generation.current;
    setSessionState((previous) => ({ ...previous, loading: true, error: "" }));
    api.session(lensRef.current, controller.signal).then((session) => {
      if (current !== generation.current || controller.signal.aborted) return;
      const previous = sessionStateRef.current;
      const sameIdentity = !!previous.session && sessionIdentity(previous.session) === sessionIdentity(session);
      setSessionState({ session, providerToken: sameIdentity ? previous.providerToken : newProviderToken(), loading: false, error: "" });
      if (!session.roles.includes(lensRef.current)) setLens(session.lens);
    }).catch((error) => {
      if (current !== generation.current || controller.signal.aborted) return;
      setSessionState({ session: null, providerToken: "", loading: false, error: isUnauthenticated(error)
        ? "Authentication could not be verified. Sign in again, then retry."
        : String((error as Error).message || error) });
    }).finally(() => {
      if (current === generation.current && sessionRequest.current === controller) sessionRequest.current = null;
    });
  }, []);

  React.useEffect(() => {
    resolveSession();
    const onFocus = () => resolveSession();
    const onVisible = () => { if (document.visibilityState === "visible") resolveSession(); };
    const onAuthLost = (event: Event) => {
      const detail = (event as CustomEvent<AuthLostDetail>).detail;
      if (!detail?.providerToken || detail.providerToken !== sessionStateRef.current.providerToken) return;
      sessionRequest.current?.abort(); sessionRequest.current = null; generation.current++;
      setSessionState({ session: null, providerToken: "", loading: false, error: "Authentication expired. Sign in again, then retry." });
    };
    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("phorvex-auth-lost", onAuthLost);
    return () => { sessionRequest.current?.abort(); sessionRequest.current = null; generation.current++; window.removeEventListener("focus", onFocus); document.removeEventListener("visibilitychange", onVisible); window.removeEventListener("phorvex-auth-lost", onAuthLost); };
  }, [resolveSession]);

  const verification = (
    <main className="grid min-h-screen place-items-center p-6">
      <div className="max-w-lg rounded-lg border border-border bg-panel p-6 text-sm">
        <div className="font-medium">{sessionState.loading ? "Verifying your session…" : "Console data is unavailable"}</div>
        {sessionState.error && <div className="mt-2 text-warning">{sessionState.error}</div>}
        {!sessionState.loading && <button className="mt-4 rounded bg-primary px-3 py-1.5 text-primary-foreground" onClick={resolveSession}>Retry</button>}
      </div>
    </main>
  );
  if (!sessionState.session) return verification;
  return <>
    {sessionState.loading && verification}
    <div hidden={sessionState.loading} aria-hidden={sessionState.loading || undefined}>
      <SessionQueryBoundary key={sessionIdentity(sessionState.session)} session={sessionState.session} providerToken={sessionState.providerToken} ready={!sessionState.loading}>
        <Console lens={lens} setLens={setLens} session={sessionState.session} sessionRefreshing={sessionState.loading} />
      </SessionQueryBoundary>
    </div>
  </>;
}

function Console({ lens, setLens, session, sessionRefreshing }: { lens: Lens; setLens: (lens: Lens) => void; session: Session; sessionRefreshing: boolean }) {
  const [active, setActive] = React.useState<StepId>("landing");
  const [demo, setDemo] = React.useState(false);
  const signals = useJourneySignals(lens);
  useScopedInvalidationBridge();

  React.useEffect(() => {
    setActive(readStep());
    const onNav = () => setActive(readStep());
    window.addEventListener("phorvex-nav", onNav);
    window.addEventListener("popstate", onNav);
    return () => { window.removeEventListener("phorvex-nav", onNav); window.removeEventListener("popstate", onNav); };
  }, []);

  const go = (s: StepId) => { goStep(s); setActive(s); };
  React.useEffect(() => { if (lens === "owner" && (active === "scan" || active === "connect")) go("protect"); /* owner skips internals */ }, [lens]); // eslint-disable-line

  return (
    <>
      <Shell lens={lens} setLens={setLens} session={session} sessionError={sessionRefreshing ? "refreshing verified session…" : ""} active={active} go={go} signals={signals} onDemo={() => { setDemo(true); go("landing"); }}>
        {active === "landing" && <Landing lens={lens} signals={signals} go={go} onDemo={() => { setDemo(true); }} />}
        {active === "connect" && <ConnectStep lens={lens} go={go} />}
        {active === "scan" && <ScanStep lens={lens} go={go} />}
        {active === "discovered" && <DiscoveredStep lens={lens} go={go} />}
        {active === "attacklab" && <AttackLab lens={lens} />}
        {active === "protect" && <ProtectStep lens={lens} go={go} />}
        {active === "prove" && <ProveStep lens={lens} />}
        {active === "report" && <ReportStep lens={lens} />}
        {active === "bench" && <BenchStep lens={lens} />}
      </Shell>
      {demo && <DemoOverlay lens={lens} go={go} onClose={() => setDemo(false)} />}
    </>
  );
}

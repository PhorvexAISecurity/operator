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

export default function Page() {
  const [lens, setLens] = React.useState<Lens>("investor");
  const [active, setActive] = React.useState<StepId>("landing");
  const [demo, setDemo] = React.useState(false);
  const [session, setSession] = React.useState<Session | null>(null);
  const [sessionError, setSessionError] = React.useState("");
  const signals = useJourneySignals(lens);

  // [M-136] Resolve the effective grant once, then land on a lens this identity actually holds.
  // Server enforcement is unchanged by any of this; it only stops the UI from offering a view
  // that will 403 on every panel.
  React.useEffect(() => {
    let live = true;
    api
      .session(lens)
      .then((s) => {
        if (!live) return;
        setSession(s);
        if (!s.roles.includes(lens)) setLens(s.lens);
      })
      .catch((e) => {
        if (!live) return;
        setSessionError(
          isUnauthenticated(e)
            ? "authentication could not be verified — sign in again; if this persists, contact your administrator"
            : String((e as Error).message || e),
        );
      });
    return () => { live = false; };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

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
      <Shell lens={lens} setLens={setLens} session={session} sessionError={sessionError} active={active} go={go} signals={signals} onDemo={() => { setDemo(true); go("landing"); }}>
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

"use client";
import * as React from "react";
import { Lens } from "@/lib/api";
import { StepId, useJourneySignals, readStep, goStep } from "@/lib/journey";
import { Shell } from "@/components/shell";
import { Landing } from "@/components/steps/landing";
import { ConnectStep } from "@/components/steps/connect";
import { ScanStep } from "@/components/steps/scan";
import { DiscoveredStep } from "@/components/steps/discovered";
import { ProtectStep } from "@/components/steps/protect";
import { ProveStep } from "@/components/steps/prove";
import { ReportStep } from "@/components/steps/report";
import { DemoOverlay } from "@/components/demo/overlay";

export default function Page() {
  const [lens, setLens] = React.useState<Lens>("investor");
  const [active, setActive] = React.useState<StepId>("landing");
  const [demo, setDemo] = React.useState(false);
  const signals = useJourneySignals(lens);

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
      <Shell lens={lens} setLens={setLens} active={active} go={go} signals={signals} onDemo={() => { setDemo(true); go("landing"); }}>
        {active === "landing" && <Landing lens={lens} signals={signals} go={go} onDemo={() => { setDemo(true); }} />}
        {active === "connect" && <ConnectStep lens={lens} go={go} />}
        {active === "scan" && <ScanStep lens={lens} go={go} />}
        {active === "discovered" && <DiscoveredStep lens={lens} go={go} />}
        {active === "protect" && <ProtectStep lens={lens} go={go} />}
        {active === "prove" && <ProveStep lens={lens} />}
        {active === "report" && <ReportStep lens={lens} />}
      </Shell>
      {demo && <DemoOverlay lens={lens} go={go} onClose={() => setDemo(false)} />}
    </>
  );
}

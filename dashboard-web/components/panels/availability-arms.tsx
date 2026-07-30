"use client";
import * as React from "react";
import { api, Lens, AvailabilityArms, ArmResult } from "@/lib/api";
import { Card, CardContent, Badge } from "@/components/ui/primitives";
import { Empty } from "@/components/ui/more";
import { Loader2, ShieldCheck, ShieldAlert, ShieldQuestion, Activity } from "lucide-react";
import { cn } from "@/lib/utils";

// AvailabilityArmsPanel — the plain answer to "what does an attack do to my app's availability,
// with no defense vs a blind rotator vs Phorvex?". All three arms were run on the SAME app with the
// SAME attack and measured by the SAME 5s sampler, so the comparison is like-for-like.
export function AvailabilityArmsPanel({ lens, ns = "litellm" }: { lens: Lens; ns?: string }) {
  const [d, setD] = React.useState<AvailabilityArms | null>(null);
  const [err, setErr] = React.useState("");
  React.useEffect(() => {
    let alive = true;
    api.availabilityArms(ns, lens).then((r) => { if (alive) setD(r); }).catch((e) => { if (alive) setErr(String(e.message || e)); });
    return () => { alive = false; };
  }, [lens, ns]);

  if (err) return <div className="text-[12px] text-danger">error: {err}</div>;
  if (!d) return <div className="flex items-center gap-2 text-[12px] text-muted-foreground"><Loader2 className="h-3.5 w-3.5 animate-spin" /> loading…</div>;
  if (!d.available) return <Empty msg={d.note} />;

  const arms = d.arms.filter((a) => a.complete);
  const worstDip = Math.min(...arms.map((a) => a.minPct));

  return (
    <div className="space-y-4">
      <div>
        <div className="flex flex-wrap items-center gap-2 text-[13px] font-medium">
          <Activity className="h-4 w-4 text-primary" />
          What an attack does to <span className="font-mono text-primary">{d.namespace}/{d.deploy}</span>
        </div>
        <p className="mt-1 max-w-[70ch] text-[12px] leading-relaxed text-muted-foreground">
          The same attack, fired three times on this same app — once with the defense switched off, once
          with a blind fixed-interval rotator, and once with Phorvex. Availability for all three comes
          from the same 5-second sampler, so the numbers are directly comparable.
        </p>
      </div>

      {/* the headline: availability alone is not the story */}
      <div className="grid gap-3 md:grid-cols-3">
        {arms.map((a) => <ArmCard key={a.arm} a={a} worstDip={worstDip} />)}
      </div>

      {/* the one sentence that matters */}
      <Card className="border-l-2 border-l-primary">
        <CardContent className="p-4 text-[12px] leading-relaxed">
          <div className="mb-1.5 font-medium text-foreground">How to read this</div>
          <p className="text-muted-foreground">
            <span className="text-danger">No defense</span> scores a perfect 100% availability — precisely
            because nothing was done about the intruder, who kept the pod for the whole window. High
            availability is not safety.{" "}
            <span className="text-warning">The blind timer</span> pays a dip on every cycle whether or not
            anything is wrong ({arms.find((a) => a.arm === "r6blind")?.dipCount ?? "—"} dips in this run),
            and only ever catches an attacker by coincidence.{" "}
            <span className="text-success">Phorvex</span> acted once, on the signal: a single short dip,
            and the attacker was evicted.
          </p>
        </CardContent>
      </Card>

      <div className="text-[11px] text-muted-foreground/70">
        {d.howItRan} Node rate ${d.nodeRatePerHr?.toFixed(4)}/hr (live AWS on-demand) is used for the
        downtime figures.
      </div>
    </div>
  );
}

function ArmCard({ a, worstDip }: { a: ArmResult; worstDip: number }) {
  const tone =
    a.attackerStopped === "yes" ? { ring: "border-l-success", txt: "text-success", Icon: ShieldCheck, chip: "real" as const, label: "attacker evicted" }
      : a.attackerStopped === "no" ? { ring: "border-l-danger", txt: "text-danger", Icon: ShieldAlert, chip: "pending" as const, label: "attacker kept access" }
        : { ring: "border-l-warning", txt: "text-warning", Icon: ShieldQuestion, chip: "modeled" as const, label: "only by coincidence" };

  // availability bar: 0..100
  const pct = Math.max(0, Math.min(100, a.meanPct));
  return (
    <Card className={cn("border-l-2", tone.ring)}>
      <CardContent className="space-y-2.5 p-4">
        <div className="flex items-center gap-2">
          <tone.Icon className={cn("h-4 w-4", tone.txt)} />
          <span className="text-[13px] font-medium text-foreground">{a.label}</span>
        </div>

        <div>
          <div className="flex items-baseline gap-2">
            <span className={cn("tabular font-mono text-[26px] font-semibold leading-none", tone.txt)}>{a.meanPct.toFixed(1)}%</span>
            <span className="text-[11px] text-muted-foreground">average availability</span>
          </div>
          <div className="mt-2 h-1.5 overflow-hidden rounded bg-border/50">
            <div className={cn("h-full rounded", a.attackerStopped === "yes" ? "bg-success" : a.attackerStopped === "no" ? "bg-danger" : "bg-warning")}
                 style={{ width: `${pct}%` }} />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-[11px]">
          <Stat k="worst dip" v={`${a.minPct.toFixed(0)}%`} />
          <Stat k="times it dipped" v={String(a.dipCount)} />
          <Stat k="degraded for" v={`${a.secondsDegraded.toFixed(0)}s`} />
          <Stat k="downtime cost" v={`$${a.downtimeUsd.toFixed(4)}`} />
        </div>

        <div className="flex items-center gap-1.5 border-t border-border/50 pt-2">
          <Badge variant={tone.chip}>{tone.label}</Badge>
        </div>
        <p className="text-[11px] leading-relaxed text-muted-foreground">{a.verdict}</p>
      </CardContent>
    </Card>
  );
}

function Stat({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex items-baseline justify-between gap-2">
      <span className="text-muted-foreground">{k}</span>
      <span className="tabular font-mono text-foreground">{v}</span>
    </div>
  );
}

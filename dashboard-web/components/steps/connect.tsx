"use client";
import * as React from "react";
import { api, Lens, ClusterTarget } from "@/lib/api";
import { setSelectedTarget } from "@/lib/provider-store";
import { StepId } from "@/lib/journey";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { Loading, ErrorBox } from "@/components/ui/more";
import { StepHead } from "./shared";
import { cn } from "@/lib/utils";
import { Server, ArrowRight, Check, Lock } from "lucide-react";

export function ConnectStep({ lens, go }: { lens: Lens; go: (s: StepId) => void }) {
  const [targets, setTargets] = React.useState<ClusterTarget[] | null>(null);
  const [sel, setSel] = React.useState("");
  const [err, setErr] = React.useState("");
  React.useEffect(() => {
    api.targets(lens).then((d) => {
      const ts = d.targets ?? [];
      setTargets(ts);
      // default to the runnable AWS EKS cluster, else the first runnable target — NOT just
      // targets[0] (which may be an unreachable cloud context). Persist its kubeconfig context so
      // the Scan step execs `phorvex --scan --context <that>`.
      const def = ts.find((t) => t.runnable && /eks|arn:aws/i.test(t.context || t.id)) ?? ts.find((t) => t.runnable) ?? ts[0];
      if (def) { setSel(def.id); setSelectedTarget({ context: def.context || "", provider: def.provider, label: def.label }); }
    }).catch((e) => setErr(String(e.message || e)));
  }, [lens]); // eslint-disable-line
  if (err) return <ErrorBox msg={err} />;
  if (!targets) return <Loading label="Reading available environments…" rows={3} />;
  const selT = targets.find((t) => t.id === sel);
  const pick = (t: ClusterTarget) => { if (!t.runnable) return; setSel(t.id); setSelectedTarget({ context: t.context || "", provider: t.provider, label: t.label }); };

  return (
    <div className="animate-fade-up space-y-6">
      <StepHead n={1} title="Connect" sub="Pick the environment Phorvex will defend. AWS EKS runs live now; GPU magnitudes are honestly pending a GPU node pool." />
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        {targets.map((t) => (
          <button key={t.id} onClick={() => pick(t)} disabled={!t.runnable}
            className={cn("rounded-lg border p-4 text-left transition-all", sel === t.id ? "border-primary/50 bg-primary/[0.06]" : "border-border bg-panel/60", !t.runnable && "opacity-60")}>
            <div className="flex items-center justify-between">
              <Server className={cn("h-4 w-4", t.runnable ? "text-primary" : "text-muted-foreground")} />
              {t.runnable ? <Badge variant="real"><Check className="h-2.5 w-2.5" /> runnable</Badge> : <Badge variant="pending"><Lock className="h-2.5 w-2.5" /> pending</Badge>}
            </div>
            <div className="mt-2.5 text-[14px] font-semibold">{t.label}</div>
            {t.context && <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">{t.context}</div>}
            <div className="mt-1.5 text-[11px] leading-snug text-muted-foreground">{t.note}</div>
          </button>
        ))}
      </div>
      <div className="flex items-center gap-3 border-t border-border pt-5">
        <Button onClick={() => go("scan")} disabled={!selT?.runnable}>
          Connect to {selT?.label} <ArrowRight className="h-4 w-4" />
        </Button>
        {!selT?.runnable && <span className="text-[12px] text-warning">{selT?.note}</span>}
      </div>
    </div>
  );
}

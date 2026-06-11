"use client";
import * as React from "react";
import { api, Lens, CoverageTechnique, Posture } from "@/lib/api";
import { Card, CardContent, Badge } from "@/components/ui/primitives";
import { Segmented, Loading, ErrorBox } from "@/components/ui/more";
import { PageHead, SectionLabel } from "./effectiveness";
import { cn } from "@/lib/utils";
import { CheckCircle2, Circle } from "lucide-react";

export function ThreatMatrixPanel({ lens }: { lens: Lens }) {
  const [tech, setTech] = React.useState<CoverageTechnique[] | null>(null);
  const [err, setErr] = React.useState("");
  const [prod, setProd] = React.useState<"all" | "k8s" | "ai">("all");
  React.useEffect(() => { api.threatMatrix(lens).then((d) => setTech(d.techniques ?? [])).catch((e) => setErr(String(e.message || e))); }, [lens]);
  if (err) return <ErrorBox msg={err} />;
  if (!tech) return <Loading label="Building the threat-coverage matrix…" />;

  const filtered = tech.filter((t) => prod === "all" || t.product === prod);
  const covered = filtered.filter((t) => t.covered).length;

  return (
    <div className="animate-fade-up space-y-6">
      <PageHead title="Threat-Coverage Matrix" sub="MITRE ATT&CK techniques exercised by the attack catalog, and which Phorvex has demonstrably disrupted in a real run. AI techniques are mapped structurally; demonstrated coverage on K8s is real, AI is [SP-0-PENDING-P4]." />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Segmented value={prod} onChange={setProd} tabs={[{ id: "all", label: "All techniques", count: tech.length }, { id: "k8s", label: "K8s" }, { id: "ai", label: "AI" }]} />
        <div className="text-[12px] text-muted-foreground"><span className="font-semibold text-success">{covered}</span> / {filtered.length} demonstrably disrupted</div>
      </div>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-3">
        {filtered.map((t) => (
          <Card key={t.technique} className={cn(t.covered && "border-success/20")}>
            <CardContent className="flex items-start gap-2.5 p-3">
              {t.covered ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-success" /> : <Circle className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground/40" />}
              <div className="min-w-0">
                <div className="flex items-center gap-1.5"><span className="font-mono text-[13px]">{t.technique}</span>{t.product === "ai" && <Badge variant="pending">SP-0</Badge>}</div>
                <div className="mt-0.5 truncate text-[11px] text-muted-foreground">{(t.scenarios ?? []).length} scenario{(t.scenarios ?? []).length > 1 ? "s" : ""}: {(t.scenarios ?? []).slice(0, 2).join(", ")}{(t.scenarios ?? []).length > 2 ? "…" : ""}</div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

export function PosturePanel({ lens }: { lens: Lens }) {
  const [p, setP] = React.useState<Posture | null>(null);
  const [err, setErr] = React.useState("");
  React.useEffect(() => { api.posture(lens).then(setP).catch((e) => setErr(String(e.message || e))); }, [lens]);
  if (err) return <ErrorBox msg={err} />;
  if (!p) return <Loading label="Scoring posture…" rows={3} />;

  return (
    <div className="animate-fade-up space-y-6">
      <PageHead title="Security Posture" sub="A composite readiness grade from Phorvex's proven gates. The weighting is disclosed and simple — AI defense is excluded from the grade and shown honestly as pending (never inflated)." />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardContent className="flex flex-col items-center justify-center gap-2 py-10">
            <div className="grid h-24 w-24 place-items-center rounded-full border-2 border-success/40 bg-success/[0.06]">
              <span className="text-5xl font-semibold tracking-tight text-success">{p.grade}</span>
            </div>
            <div className="text-[12px] uppercase tracking-wide text-muted-foreground">K8s readiness · {(p.score * 100).toFixed(0)}%</div>
          </CardContent>
        </Card>
        <Card className="lg:col-span-2">
          <CardContent className="p-5">
            <SectionLabel>Sub-scores</SectionLabel>
            <div className="space-y-2.5">
              {(p.subs ?? []).map((s) => {
                const pending = s.score < 0; // -1 = not-yet-computed / pending (excluded from grade)
                const ai = /AI defense/i.test(s.label);
                return (
                  <div key={s.label} className="flex items-center gap-3" title={(s as any).basis || ""}>
                    <span className="w-44 shrink-0 text-[13px]">{s.label}</span>
                    <div className="h-1.5 flex-1 rounded-full bg-muted/50">
                      {!pending && <div className="h-1.5 rounded-full bg-success" style={{ width: `${Math.max(4, s.score * 100)}%` }} />}
                    </div>
                    {pending ? <Badge variant="pending">{ai ? "SP-0-PENDING-P4" : "not computed"}</Badge> : <span className="w-10 text-right text-[12px] tabular text-success">{(s.score * 100).toFixed(0)}%</span>}
                  </div>
                );
              })}
            </div>
            <div className="mt-3 border-t border-border/60 pt-3 text-[11px] text-muted-foreground">{p.note}</div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

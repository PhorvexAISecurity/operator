"use client";
import * as React from "react";
import { api, Lens, CatalogItem, ClusterTarget } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { Segmented, Input, Dialog, Loading, ErrorBox, Empty } from "@/components/ui/more";
import { PageHead, SectionLabel } from "./effectiveness";
import { cn } from "@/lib/utils";
import { Search, Play, Loader2, ShieldCheck, Cpu, Boxes } from "lucide-react";

const r6Variant = (t: string) => (t.includes("Covers") ? "real" : t.includes("Partial") ? "modeled" : "danger");

export function CatalogPanel({ lens }: { lens: Lens }) {
  const [items, setItems] = React.useState<CatalogItem[] | null>(null);
  const [targets, setTargets] = React.useState<ClusterTarget[]>([]);
  const [target, setTarget] = React.useState("kind");
  const [err, setErr] = React.useState("");
  const [prod, setProd] = React.useState<"all" | "k8s" | "ai" | "structural">("all");
  const [q, setQ] = React.useState("");
  const [sel, setSel] = React.useState<CatalogItem | null>(null);

  React.useEffect(() => {
    api.catalog(lens).then((d) => setItems(d.items ?? [])).catch((e) => setErr(String(e.message || e)));
    api.targets(lens).then((d) => setTargets(d.targets ?? [])).catch(() => {});
  }, [lens]);

  if (err) return <ErrorBox msg={err} />;
  if (!items) return <Loading label="Enumerating the attack catalog from the harness registry…" rows={6} />;

  const filtered = items.filter((it) => (prod === "all" || it.product === prod) && (q === "" || it.name.includes(q) || (it.techniques ?? []).join(" ").includes(q.toUpperCase())));
  const counts = { all: items.length, k8s: items.filter((i) => i.product === "k8s").length, ai: items.filter((i) => i.product === "ai").length, structural: items.filter((i) => i.product === "structural").length };

  return (
    <div className="animate-fade-up space-y-6">
      <PageHead title="Attack Catalog" sub={`The full ${items.length}-scenario adversary suite — enumerated live from the harness registry, each runnable with or without Phorvex. AI scenarios are structurally real; their defense efficacy is [SP-0-PENDING-P4].`} />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Segmented value={prod} onChange={setProd} tabs={[{ id: "all", label: "All", count: counts.all }, { id: "k8s", label: "K8s", count: counts.k8s }, { id: "ai", label: "AI / Inference", count: counts.ai }, { id: "structural", label: "Structural", count: counts.structural }]} />
        <div className="relative w-64">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by name or ATT&CK ID…" className="pl-8" />
        </div>
      </div>
      <div className="flex items-center gap-2 text-[12px] text-muted-foreground">
        <span>Target:</span>
        {targets.map((t) => (
          <button key={t.id} onClick={() => t.runnable && setTarget(t.id)} disabled={!t.runnable} title={t.note}
            className={cn("rounded-md border px-2.5 py-1 transition-colors", target === t.id ? "border-primary/50 bg-primary/[0.06] text-foreground" : "border-border text-muted-foreground", !t.runnable && "opacity-50")}>
            {t.label}{!t.runnable && <span className="ml-1 text-warning">·pending</span>}
          </button>
        ))}
      </div>
      {filtered.length === 0 ? <Empty msg="No scenarios match." /> : (
        <div className="grid grid-cols-1 gap-2.5 lg:grid-cols-2">
          {filtered.map((it) => <ScenarioRow key={it.name} it={it} onOpen={() => setSel(it)} />)}
        </div>
      )}
      <ScenarioDialog item={sel} target={target} lens={lens} onClose={() => setSel(null)} />
    </div>
  );
}

function ScenarioRow({ it, onOpen }: { it: CatalogItem; onOpen: () => void }) {
  const Icon = it.product === "ai" ? Cpu : it.product === "structural" ? Boxes : ShieldCheck;
  return (
    <Card className="cursor-pointer transition-colors hover:border-border/80" onClick={onOpen}>
      <CardContent className="flex items-start gap-3 p-3.5">
        <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", it.product === "ai" ? "text-info" : it.product === "structural" ? "text-warning" : "text-primary")} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-mono text-[13px] text-foreground">{it.name}</span>
            <Badge variant={r6Variant(it.r6Tag) as any}>{it.r6Tag.replace("R6", "")}</Badge>
            {it.hasRun && <Badge variant="accent">ran</Badge>}
            {it.product === "ai" && <Badge variant="pending">SP-0</Badge>}
          </div>
          <div className="mt-1 flex flex-wrap gap-1">
            <span className="text-[10px] uppercase tracking-wide text-muted-foreground/70">{it.category}</span>
            {(it.techniques ?? []).slice(0, 4).map((t) => <span key={t} className="rounded bg-muted/40 px-1.5 text-[10px] font-mono text-muted-foreground">{t}</span>)}
            {(it.caps ?? []).includes("CapGPU") && <span className="rounded bg-info/10 px-1.5 text-[10px] text-info">GPU</span>}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function ScenarioDialog({ item, target, lens, onClose }: { item: CatalogItem | null; target: string; lens: Lens; onClose: () => void }) {
  const [running, setRunning] = React.useState("");
  const [msg, setMsg] = React.useState("");
  if (!item) return null;
  async function run(withPX: boolean) {
    setRunning(withPX ? "px" : "nopx"); setMsg("");
    try { const { id } = await api.startScenario(item!.name, withPX, target, "", lens); setMsg(`Launched ${id} on ${target} — watch Run Attack Agents / Live Operations.`); }
    catch (e: any) { setMsg(String(e.message || e)); }
    finally { setRunning(""); }
  }
  return (
    <Dialog open={!!item} onClose={onClose} title={item.name}>
      <div className="space-y-4">
        <div className="flex flex-wrap gap-2">
          <Badge variant="neutral">{item.category}</Badge>
          <Badge variant={r6Variant(item.r6Tag) as any}>R6 {item.r6Tag.replace("R6", "")}</Badge>
          <Badge variant={item.product === "ai" ? "modeled" : "accent"}>{item.product.toUpperCase()}</Badge>
        </div>
        <div>
          <SectionLabel>ATT&amp;CK techniques</SectionLabel>
          <div className="flex flex-wrap gap-1.5">{(item.techniques ?? []).length === 0 ? <span className="text-[12px] text-muted-foreground">none tagged</span> : (item.techniques ?? []).map((t) => <span key={t} className="rounded bg-muted/40 px-2 py-0.5 text-[12px] font-mono text-foreground/80">{t}</span>)}</div>
        </div>
        {item.product === "ai" && <div className="rounded-md border border-warning/25 bg-warning/[0.05] p-3 text-[12px] text-muted-foreground">AI scenario — the attack surface is real; Phorvex's <span className="text-foreground">defense efficacy is [SP-0-PENDING-P4]</span>, validated on real GPU at P4. No AI effectiveness is implied here.</div>}
        <div className="flex items-center gap-2 border-t border-border pt-4">
          <Button onClick={() => run(true)} disabled={!!running}>{running === "px" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} Run with Phorvex</Button>
          <Button variant="outline" onClick={() => run(false)} disabled={!!running}>{running === "nopx" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} Run without (baseline)</Button>
          <span className="text-[11px] text-muted-foreground">target: {target}</span>
        </div>
        {msg && <div className="text-[12px] text-primary">{msg}</div>}
      </div>
    </Dialog>
  );
}

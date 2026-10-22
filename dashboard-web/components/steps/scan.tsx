"use client";
import * as React from "react";
import { Lens } from "@/lib/api";
import { useSelectedTarget } from "@/lib/provider-store";
import { StepId } from "@/lib/journey";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { ErrorBox, ReadStatus } from "@/components/ui/more";
import { StepHead } from "./shared";
import { cn } from "@/lib/utils";
import { Radar, Check, Loader2, ArrowRight } from "lucide-react";
import { useLocalPage } from "@/lib/use-local-page";
import { PaginationBar } from "@/components/ui/pagination";
import { useScanSnapshot } from "@/lib/query";

const PHASES = [
  { k: "ingest", label: "Ingest cluster snapshot", detail: "nodes · PDBs · image digests · requests" },
  { k: "physics", label: "Derive physics witness", detail: "image-rarity · co-residency · slack · EPSS · MIG" },
  { k: "context", label: "Context / kill-chain", detail: "stage · P(hold) · moved-before-next-stage" },
  { k: "emr", label: "Scarcity (EMR) ablation", detail: "recon-per-dollar invalidation weighting" },
];

export function ScanStep({ lens, go }: { lens: Lens; go: (s: StepId) => void }) {
  const [listQuery, setListQuery] = React.useState("");
  const sel = useSelectedTarget(); // the header's provider scope drives which cluster is scanned
  const ctxLabel = sel.label || sel.context || "current kubeconfig context";
  const scopeKey = `${lens}\u0000${sel.context}`;
  const scanQuery = useScanSnapshot(lens, sel.context, "", false);

  // run() requests a fresh `phorvex --scan` result via /api/scan (not a cached corpus).
  // The PHASES below are the real server-side pipeline this single exec runs; we show them all
  // in-progress during the exec and done on completion — NOT a fake sequential per-phase timer.
  async function run() {
    if (lens === "owner") return;
    await scanQuery.refetch({ cancelRefetch: true });
  }

  const shownScan = scanQuery.data ?? null;
  const shownScanning = scanQuery.isFetching;
  const err = scanQuery.error ? String((scanQuery.error as Error).message || scanQuery.error) : "";
  const witness = shownScan?.witness ?? [];
  const nodes = shownScan?.nodeList ?? [];
  const normalizedQuery = listQuery.trim().toLowerCase();
  const matchingNodes = nodes.filter((node) => !normalizedQuery || node.name.toLowerCase().includes(normalizedQuery));
  const matchingWitness = witness.filter((row) => !normalizedQuery || row.pod.toLowerCase().includes(normalizedQuery));
  const nodePage = useLocalPage(matchingNodes, 10, `${scopeKey}\u0000${listQuery}`);
  const witnessPage = useLocalPage(matchingWitness, 10, `${scopeKey}\u0000${listQuery}`);
  const done = !!shownScan && !shownScanning;

  return (
    <div className="animate-fade-up space-y-6">
      <StepHead n={2} title="Scan" sub="Derive the selected target's physics/context inputs. Synthetic fixture responses remain explicitly labeled; GPU validation stays [SP-0-PENDING-P4]." />

      <Card>
        <CardContent className="flex flex-col items-center gap-5 py-10">
          <div className={cn("grid h-16 w-16 place-items-center rounded-2xl ring-1 transition-colors", !shownScanning && !done ? "bg-primary/10 ring-primary/30" : done ? "bg-success/10 ring-success/30" : "bg-primary/15 ring-primary/40")}>
            {shownScanning ? <Loader2 className="h-7 w-7 animate-spin text-primary" /> : done ? <Check className="h-7 w-7 text-success" /> : <Radar className="h-7 w-7 text-primary" />}
          </div>

          {lens === "owner" ? (
            <div className="w-full max-w-md rounded-md border border-border px-4 py-3 text-center text-sm text-muted-foreground">
              Live vendor scans are available to operator and investor roles. The customer-owner view uses tenant-scoped decision evidence and cannot invoke cluster scan endpoints.
            </div>
          ) : !shownScanning && !done ? (
            <>
              <div className="text-center text-sm text-muted-foreground">
                Request a fresh platform-physics scan — runs <span className="font-mono text-foreground/80">phorvex --scan</span> for
                <span className="font-mono text-foreground/80"> {ctxLabel}</span>
                {scanQuery.namespace && <> in namespace <span className="font-mono text-foreground/80">{scanQuery.namespace}</span></>} and returns fresh results.
              </div>
              <Button onClick={run}><Radar className="h-4 w-4" /> Run scan</Button>
              {err && <div className="w-full max-w-md"><ErrorBox msg={err} /></div>}
            </>
          ) : (
            <div className="w-full max-w-md space-y-2.5">
              <ReadStatus error={scanQuery.error} hasData={!!shownScan} updatedAt={scanQuery.dataUpdatedAt} refreshing={shownScanning} onRetry={() => void scanQuery.refetch()} />
              {PHASES.map((p) => {
                const st = shownScanning ? "run" : "done"; // retained rows describe the last completed exec
                return (
                  <div key={p.k} className={cn("flex items-center gap-3 rounded-md border px-3 py-2", st === "done" ? "border-success/20 bg-success/[0.04]" : st === "run" ? "border-primary/30 bg-primary/[0.05]" : "border-border/50 opacity-50")}>
                    {st === "done" ? <Check className="h-4 w-4 text-success" /> : st === "run" ? <Loader2 className="h-4 w-4 animate-spin text-primary" /> : <span className="h-4 w-4 rounded-full border border-border" />}
                    <div><div className="text-[13px] text-foreground">{p.label}</div><div className="text-[11px] text-muted-foreground">{p.detail}</div></div>
                  </div>
                );
              })}
            </div>
          )}

          {done && (
            <div className="w-full max-w-lg space-y-3">
              <input value={listQuery} onChange={(e) => setListQuery(e.target.value)} placeholder="Search node or pod…" aria-label="Search scan nodes and pods" className="w-full rounded-md border border-border bg-panel px-3 py-2 text-sm focus:outline-none" />
              <div className="flex flex-wrap items-center justify-center gap-2 text-[12px] text-muted-foreground">
                <Badge variant={shownScan?.platform === "local-fixture" ? "modeled" : "neutral"}><Check className="h-2.5 w-2.5" /> {err ? "cached scan snapshot · refresh failed" : shownScan?.platform === "local-fixture" ? "synthetic fixture response" : "scan response · source not attested"}</Badge>
                <Badge variant="accent">{shownScan?.platform || "generic-k8s"}</Badge>
                <span>{shownScan?.nodes ?? 0} node · <span className="tabular text-foreground">{shownScan?.pods ?? witness.length}</span> pods · {witness.length} physics rows</span>
                {(shownScan?.nodeList ?? []).some((n) => n.allocGPU > 0) && (
                  <Badge variant="accent">{(shownScan?.nodeList ?? []).filter((n) => n.allocGPU > 0).reduce((s, n) => s + n.allocGPU, 0)}× GPU on {(shownScan?.nodeList ?? []).filter((n) => n.allocGPU > 0).length} node</Badge>
                )}
                <span className="text-muted-foreground/60">snapshot {scanQuery.dataUpdatedAt ? new Date(scanQuery.dataUpdatedAt).toLocaleTimeString() : ""}</span>
              </div>
              {nodes.length > 0 && (
                <Card><CardContent className="p-0">
                  <div className="max-h-40 overflow-y-auto">
                    <table className="w-full text-[12px]">
                      <thead className="sticky top-0 bg-panel"><tr className="text-left text-[10px] uppercase text-muted-foreground"><th className="px-3 py-1.5">Node</th><th className="px-3 py-1.5">CPU</th><th className="px-3 py-1.5">Mem</th><th className="px-3 py-1.5">GPU</th></tr></thead>
                      <tbody>{nodePage.pageItems.map((n) => (
                        <tr key={n.name} className={"border-t border-border/40 " + (n.allocGPU > 0 ? "bg-accent/[0.06]" : "")}>
                          <td className="px-3 py-1.5 font-mono">{n.name.split(".")[0]}</td>
                          <td className="px-3 py-1.5 tabular">{(n.allocCPUm / 1000).toFixed(1)}</td>
                          <td className="px-3 py-1.5 tabular">{(n.allocMemMi / 1024).toFixed(1)}Gi</td>
                          <td className="px-3 py-1.5">{n.allocGPU > 0 ? <Badge variant="accent">{n.allocGPU}× GPU{n.migKinds > 0 ? ` · ${n.migKinds} MIG` : ""}</Badge> : <span className="text-muted-foreground/40">—</span>}</td>
                        </tr>
                      ))}</tbody>
                    </table>
                  </div>
                  <div className="border-t border-border/40 px-3 py-2">{matchingNodes.length === 0 && <div className="mb-1 text-[11px] text-muted-foreground">No nodes match this search.</div>}<PaginationBar page={nodePage.page} pageSize={10} total={matchingNodes.length} hasNext={nodePage.hasNext} onPrevious={() => nodePage.setPage((p) => Math.max(0, p - 1))} onNext={() => nodePage.setPage((p) => p + 1)} /></div>
                </CardContent></Card>
              )}
              {witness.length === 0 ? (
                <div className="rounded-md border border-warning/30 bg-warning/[0.05] px-3 py-2 text-center text-[12px] text-muted-foreground">
                  The scan ran but found no pods on <span className="font-mono">{ctxLabel}</span>. Check the cluster context / that workloads exist.
                </div>
              ) : (
                <Card><CardContent className="p-0">
                  <div className="max-h-56 overflow-y-auto">
                    <table className="w-full text-[12px]">
                      <thead className="sticky top-0 bg-panel"><tr className="text-left text-[10px] uppercase text-muted-foreground"><th className="px-3 py-1.5">Pod</th><th className="px-3 py-1.5">imgRarity</th><th className="px-3 py-1.5">coRes</th><th className="px-3 py-1.5">slack</th><th className="px-3 py-1.5">EPSS</th></tr></thead>
                      <tbody>{witnessPage.pageItems.map((w) => (
                        <tr key={w.pod} className="border-t border-border/40">
                          <td className="px-3 py-1.5 font-mono">{w.pod}</td>
                          <td className="px-3 py-1.5 tabular">{w.imageRarity.toFixed(2)}</td>
                          <td className="px-3 py-1.5 tabular">{w.coResidency.toFixed(2)}</td>
                          <td className="px-3 py-1.5 tabular">{w.slack.toFixed(2)}</td>
                          <td className="px-3 py-1.5 tabular">{w.epss.toFixed(2)}</td>
                        </tr>
                      ))}</tbody>
                    </table>
                  </div>
                  <div className="border-t border-border/40 px-3 py-2">{matchingWitness.length === 0 && <div className="mb-1 text-[11px] text-muted-foreground">No pods match this search.</div>}<PaginationBar page={witnessPage.page} pageSize={10} total={matchingWitness.length} hasNext={witnessPage.hasNext} onPrevious={() => witnessPage.setPage((p) => Math.max(0, p - 1))} onNext={() => witnessPage.setPage((p) => p + 1)} /></div>
                </CardContent></Card>
              )}
              <div className="flex items-center justify-center gap-3">
                <Button onClick={run} disabled={shownScanning}><Radar className="h-4 w-4" /> Re-scan (fresh)</Button>
                <Button onClick={() => go("discovered")}>See what was discovered <ArrowRight className="h-4 w-4" /></Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

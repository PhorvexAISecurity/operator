"use client";
import * as React from "react";
import { api, Lens, RTGate } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { ShieldCheck, Loader2, CheckCircle2, XCircle } from "lucide-react";

// RedTeamGates runs the regression gates LIVE (1.62× / P3 / lead-demo + suites) via the now-wired
// /api/redteam/gates endpoint — a SAFE trigger (runs the existing gate tests; no cluster write).
export function RedTeamGates({ lens }: { lens: Lens }) {
  const [gates, setGates] = React.useState<RTGate[]>([]);
  const [allPass, setAllPass] = React.useState<boolean | null>(null);
  const [ranAt, setRanAt] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState("");

  async function run() {
    setBusy(true);
    setErr("");
    try {
      const d = await api.redteamGates(lens);
      setGates(d.gates || []);
      setAllPass(d.allPass);
      setRanAt(d.ranAt);
    } catch (e: any) {
      setErr(String(e.message || e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardContent className="space-y-3 p-5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-primary" />
            <h3 className="text-sm font-semibold text-foreground">Live regression gates</h3>
          </div>
          <div className="flex items-center gap-2">
            {allPass !== null && <Badge variant={allPass ? "real" : "danger"}>{allPass ? "ALL PASS" : "FAILURES"}</Badge>}
            <Button size="sm" onClick={run} disabled={busy}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
              Run gates
            </Button>
          </div>
        </div>
        {err && <p className="text-sm text-danger">{err}</p>}
        {ranAt && <p className="text-xs text-muted-foreground">ran at {ranAt}</p>}
        {gates.map((g) => (
          <div key={g.label} className="flex items-start gap-2 rounded-md border border-border bg-panel/40 px-3 py-2 text-sm">
            {g.pass ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-success" /> : <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-danger" />}
            <div className="min-w-0">
              <span className="font-medium text-foreground">{g.label}</span>
              {g.out && <span className="ml-2 truncate text-xs text-muted-foreground">{g.out}</span>}
            </div>
          </div>
        ))}
        {gates.length === 0 && !busy && <p className="text-sm text-muted-foreground">Click “Run gates” to execute the regression suite live.</p>}
      </CardContent>
    </Card>
  );
}

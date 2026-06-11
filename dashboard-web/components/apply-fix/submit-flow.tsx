"use client";
import * as React from "react";
import { applyFixApi, ApplyFixDelta, AFIdentity, GatePreview, Lens } from "@/lib/api";
import { Card, CardContent, Badge, Button } from "@/components/ui/primitives";
import { ShieldCheck, ShieldAlert, Loader2, Send, FlaskConical } from "lucide-react";

// The allowlisted, bounded parameters (mirrors the server-side envelope; the server is authoritative).
const PARAMS: { key: keyof ApplyFixDelta; label: string; min: number; max: number; step: number; hint: string }[] = [
  { key: "normSparsity", label: "Norm sparsity", min: 0.1, max: 10, step: 0.1, hint: "structural cost weight" },
  { key: "flowDisruption", label: "Flow disruption", min: 0.1, max: 10, step: 0.1, hint: "warm-load cost weight" },
  { key: "maxMovesPerTick", label: "Max moves / tick", min: 1, max: 50, step: 1, hint: "budget B" },
  { key: "proactiveFloorSec", label: "Proactive floor (s)", min: 60, max: 86400, step: 60, hint: "hygiene rotation floor" },
];

// PRESETS — a recommended safe tune and a deliberately-malicious one (to demonstrate the gate rejection).
const PRESETS: { name: string; danger?: boolean; delta: ApplyFixDelta }[] = [
  { name: "Recommended tune (safe)", delta: { normSparsity: 1.5, flowDisruption: 1 } },
  { name: "Starve (malicious)", danger: true, delta: { maxMovesPerTick: 0 } },
  { name: "Over-expensive (gate-breaking, in-bounds)", danger: true, delta: { normSparsity: 10, flowDisruption: 10 } },
];

const field =
  "w-full rounded-md border border-border bg-background/60 px-2.5 py-1.5 text-sm text-foreground focus:border-primary focus:outline-none";

export function SubmitFlow({ id, lens, onSubmitted }: { id: AFIdentity; lens: Lens; onSubmitted: () => void }) {
  const [delta, setDelta] = React.useState<ApplyFixDelta>({ normSparsity: 1.5 });
  const [preview, setPreview] = React.useState<GatePreview | null>(null);
  const [previewing, setPreviewing] = React.useState(false);
  const [submitting, setSubmitting] = React.useState(false);
  const [result, setResult] = React.useState<{ ok: boolean; msg: string } | null>(null);

  const ready = !!id.user && !!id.tenant;

  function setNum(key: keyof ApplyFixDelta, v: string) {
    setPreview(null);
    setResult(null);
    setDelta((d) => {
      const next = { ...d };
      if (v === "") delete next[key];
      else (next[key] as number) = Number(v);
      return next;
    });
  }

  async function runPreview() {
    if (!ready) return;
    setPreviewing(true);
    setResult(null);
    try {
      setPreview(await applyFixApi.gatePreview(delta, id, lens));
    } catch (e: any) {
      setPreview({ pass: false, reason: String(e.message || e) });
    } finally {
      setPreviewing(false);
    }
  }

  async function submit() {
    if (!ready) return;
    setSubmitting(true);
    setResult(null);
    const reqId = `af-${id.tenant}-${Date.now()}`;
    try {
      const r = await applyFixApi.submit(reqId, delta, "operator-initiated policy tune", id, lens);
      setResult({ ok: true, msg: `Submitted ${r.id} — ${r.note}` });
      onSubmitted();
    } catch (e: any) {
      // a gate/allowlist rejection arrives as HTTP 422 with the reason.
      setResult({ ok: false, msg: `${e.status === 422 ? "REJECTED (422)" : "Error"}: ${String(e.message || e)}` });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Card>
      <CardContent className="space-y-4 p-5">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-foreground">Propose a policy change (apply-fix)</h3>
          <Badge variant="neutral">allowlisted params only · no free-form YAML</Badge>
        </div>

        <div className="flex flex-wrap gap-2">
          {PRESETS.map((p) => (
            <Button
              key={p.name}
              variant="outline"
              size="sm"
              onClick={() => {
                setDelta(p.delta);
                setPreview(null);
                setResult(null);
              }}
            >
              {p.danger ? <ShieldAlert className="h-3.5 w-3.5 text-danger" /> : <FlaskConical className="h-3.5 w-3.5" />}
              {p.name}
            </Button>
          ))}
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {PARAMS.map((p) => (
            <label key={p.key} className="space-y-1">
              <span className="flex items-center justify-between text-xs text-muted-foreground">
                <span>{p.label}</span>
                <span className="text-[10px]">
                  [{p.min}…{p.max}] · {p.hint}
                </span>
              </span>
              <input
                className={field}
                type="number"
                min={p.min}
                max={p.max}
                step={p.step}
                placeholder="unchanged"
                value={delta[p.key] ?? ""}
                onChange={(e) => setNum(p.key, e.target.value)}
              />
            </label>
          ))}
        </div>

        {preview && (
          <div
            className={
              "flex items-start gap-2 rounded-md border p-3 text-sm " +
              (preview.pass ? "border-success/30 bg-success/10 text-success" : "border-danger/30 bg-danger/10 text-danger")
            }
          >
            {preview.pass ? <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" /> : <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />}
            <span>
              <span className="font-medium">Gate {preview.pass ? "PASSES" : "FAILS"}</span> — {preview.reason}
            </span>
          </div>
        )}

        {result && (
          <div
            className={
              "rounded-md border p-3 text-sm " +
              (result.ok ? "border-info/30 bg-info/10 text-info" : "border-danger/30 bg-danger/10 text-danger")
            }
          >
            {result.msg}
          </div>
        )}

        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={runPreview} disabled={!ready || previewing}>
            {previewing ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
            Preview gate (1.62× · P3 · no-harm)
          </Button>
          <Button onClick={submit} disabled={!ready || submitting}>
            {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
            Submit for approval
          </Button>
          {!ready && <span className="text-xs text-muted-foreground">set your user + tenant above first</span>}
        </div>
        <p className="text-xs text-muted-foreground">
          The server re-runs the safety gate on submit (and again at approval — no TOCTOU). A gate-breaking delta is
          rejected with <span className="text-danger">422</span> and the reason, before any cluster write.
        </p>
      </CardContent>
    </Card>
  );
}

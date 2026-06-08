"use client";
import * as React from "react";
import { Badge } from "@/components/ui/primitives";

export function StepHead({ n, title, sub, lens }: { n: number; title: string; sub: string; lens?: string }) {
  return (
    <div>
      <div className="flex items-center gap-2">
        <span className="grid h-6 w-6 place-items-center rounded-md bg-primary/15 text-[12px] font-bold text-primary ring-1 ring-primary/30">{n}</span>
        <span className="text-[11px] font-medium uppercase tracking-[0.16em] text-muted-foreground">Step {n} of 6</span>
        {lens === "owner" && <Badge variant="accent">IP-walled view</Badge>}
      </div>
      <h1 className="mt-2 text-2xl font-semibold tracking-tight">{title}</h1>
      <p className="mt-1.5 max-w-3xl text-sm leading-relaxed text-muted-foreground">{sub}</p>
    </div>
  );
}

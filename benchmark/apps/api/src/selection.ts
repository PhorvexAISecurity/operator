import { z } from 'zod';
import { APPLICATIONS } from './config';

const counts = z.object({
  total:z.number().int().nonnegative(), ready:z.number().int().nonnegative(),
  benchmarkBlocked:z.number().int().nonnegative(), launchable:z.number().int().nonnegative(),
  blocked:z.number().int().nonnegative(),
}).refine(c=>c.ready<=c.total && c.benchmarkBlocked<=c.total && c.launchable<=c.ready && c.blocked===c.total-c.launchable);
export const SELECTION = counts.and(z.object({applications:z.array(z.object({namespace:z.enum(APPLICATIONS),counts})).max(4)}))
  .refine(s=>new Set(s.applications.map(a=>a.namespace)).size===s.applications.length &&
    (['total','ready','benchmarkBlocked','launchable','blocked'] as const).every(key=>s[key]===s.applications.reduce((sum,a)=>sum+a.counts[key],0)));
export type Selection = z.infer<typeof SELECTION>;

export function selection(cases:Record<string,unknown>[],applications:readonly string[]):Selection {
  const count=(rows:Record<string,unknown>[])=>{
    const ready=rows.filter(c=>c.armed===true && c.compatible===true).length;
    const launchable=rows.filter(c=>c.armed===true && c.compatible===true && c.benchmarkBlocked!==true).length;
    return {total:rows.length,ready,benchmarkBlocked:rows.filter(c=>c.benchmarkBlocked===true).length,launchable,blocked:rows.length-launchable};
  };
  return {...count(cases),applications:applications.map(namespace=>({namespace:namespace as typeof APPLICATIONS[number],counts:count(cases.filter(c=>c.namespace===namespace))}))};
}

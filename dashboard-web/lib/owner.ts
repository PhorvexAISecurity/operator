"use client";
import * as React from "react";
import { api, Lens } from "./api";

const KEY = "phorvex-owner-tenant";
const EVT = "phorvex-owner-tenant";

// useOwnerTenant gives the owner lens a concrete tenant so its (tenant-scoped) panels populate.
// It fetches the selectable tenants from /api/owner/tenants, defaults to the first (or the saved
// pick), and syncs the selection across owner components via a window event. Demo-trust: real
// per-tenant authn is [PENDING-P-VCLUSTER].
export function useOwnerTenant(lens: Lens) {
  const [tenants, setTenants] = React.useState<string[]>([]);
  const [tenant, setT] = React.useState<string>("");
  React.useEffect(() => {
    if (lens !== "owner") {
      setT("");
      return;
    }
    let live = true;
    api.ownerTenants(lens).then((d) => {
      if (!live) return;
      const ts = d.tenants ?? [];
      setTenants(ts);
      const saved = typeof window !== "undefined" ? localStorage.getItem(KEY) || "" : "";
      const next = saved && ts.includes(saved) ? saved : ts[0] || "";
      setT(next);
      if (next && typeof window !== "undefined") localStorage.setItem(KEY, next);
    }).catch(() => {});
    const onSync = () => setT((typeof window !== "undefined" && localStorage.getItem(KEY)) || "");
    if (typeof window !== "undefined") window.addEventListener(EVT, onSync);
    return () => {
      live = false;
      if (typeof window !== "undefined") window.removeEventListener(EVT, onSync);
    };
  }, [lens]);
  const setTenant = React.useCallback((t: string) => {
    if (typeof window !== "undefined") {
      localStorage.setItem(KEY, t);
      window.dispatchEvent(new Event(EVT));
    }
    setT(t);
  }, []);
  return { tenant, tenants, setTenant };
}

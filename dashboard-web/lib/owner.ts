"use client";
import * as React from "react";
import { api, Lens } from "./api";
import { useApiRead } from "./query";

const KEY = "phorvex-owner-tenant";
const EVT = "phorvex-owner-tenant";

// useOwnerTenant gives the owner lens a concrete tenant so its (tenant-scoped) panels populate.
// It fetches the selectable tenants from /api/owner/tenants, defaults to the first (or the saved
// pick), and syncs the selection across owner components via a window event. Demo-trust: real
// per-tenant authn is [PENDING-P-VCLUSTER].
export function useOwnerTenant(lens: Lens) {
  const [tenant, setT] = React.useState<string>("");
  const tenantRead = useApiRead({ lens, resource: "owner-tenants", fetcher: (signal) => api.ownerTenants(lens, signal), staleTime: 60_000, enabled: lens === "owner" });
  React.useEffect(() => {
    if (lens !== "owner") {
      setT("");
      return;
    }
    const d = tenantRead.data;
    if (d) {
      const ts = d.tenants ?? [];
      let saved = "";
      try { saved = typeof window !== "undefined" ? localStorage.getItem(KEY) || "" : ""; } catch {}
      const next = saved && ts.includes(saved) ? saved : ts[0] || "";
      setT(next);
      if (next && typeof window !== "undefined") { try { localStorage.setItem(KEY, next); } catch {} }
    } else if (tenantRead.error) setT("");
    const onSync = () => { try { setT((typeof window !== "undefined" && localStorage.getItem(KEY)) || ""); } catch { setT(""); } };
    if (typeof window !== "undefined") window.addEventListener(EVT, onSync);
    return () => {
      if (typeof window !== "undefined") window.removeEventListener(EVT, onSync);
    };
  }, [lens, tenantRead.data]);
  const tenants = tenantRead.data?.tenants ?? [];
  const selected = tenants.includes(tenant) ? tenant : "";
  const setTenant = React.useCallback((t: string) => {
    if (!tenants.includes(t)) return;
    if (typeof window !== "undefined") {
      try { localStorage.setItem(KEY, t); } catch {}
      window.dispatchEvent(new Event(EVT));
    }
    setT(t);
  }, [tenants]);
  return { tenant: selected, tenants, tenantListPartial: !!tenantRead.data?.partial, error: tenantRead.error, retry: tenantRead.refetch, setTenant };
}

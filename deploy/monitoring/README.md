# Monitoring source of record

The `kube-prom-stack` release in `monitoring` (kube-prometheus-stack 88.5.3) is not managed by
Argo CD, and until 2026-09-29 these two pieces existed only on the cluster.

| File | Live object |
| --- | --- |
| `additional-scrape-configs.yaml` | Secret `monitoring/kube-prom-stack-kube-prome-prometheus-scrape-confg`, key `additional-scrape-configs.yaml` (the release's `prometheus.prometheusSpec.additionalScrapeConfigs`) |
| `phorvex-apps-dashboard.json` | ConfigMap `monitoring/phorvex-apps-dashboard`, key `phorvex-apps.json`, label `grafana_dashboard=1` |

## Applying

Run from a directory holding both files, with cluster-admin `kubectl`:

```sh
B=$(base64 -w0 additional-scrape-configs.yaml)
kubectl -n monitoring patch secret kube-prom-stack-kube-prome-prometheus-scrape-confg --type=json \
  -p "[{\"op\":\"replace\",\"path\":\"/data/additional-scrape-configs.yaml\",\"value\":\"$B\"}]"

kubectl -n monitoring create configmap phorvex-apps-dashboard \
  --from-file=phorvex-apps.json=phorvex-apps-dashboard.json --dry-run=client -o yaml \
  | kubectl label --local -f - grafana_dashboard=1 -o yaml \
  | kubectl -n monitoring apply -f -
```

Prometheus reloads the scrape config within about two minutes, and the Grafana sidecar picks up
the dashboard on its next poll. The label must be part of the applied manifest: the existing
object's last-applied record contains `grafana_dashboard=1`, so an `apply` without it removes the
label and the Grafana sidecar stops loading the dashboard (this happened once on 2026-09-29). On the next
`helm upgrade` of `kube-prom-stack`, pass `additional-scrape-configs.yaml` as
`additionalScrapeConfigs` or the vllm job reverts.

## 2026-09-29 changes

- **vllm scrape job — still down.** It kept container port 8000, the guardrail boundary, which answers
  `/metrics` with 404. The job was changed to scrape the engine on 8001, but the engine is started
  with `--host 127.0.0.1` and the boundary (`dual_server.py`) deliberately exposes no upstream route,
  so the target now reports "connection refused". Collecting `vllm:*` series needs a boundary change
  (for example a read-only `/metrics` pass-through, or a metrics sidecar in the vLLM Pod); until
  then the LLM-serving latency, TTFT, queue and token panels stay empty.
- **Dashboard.** "Apps attacked" and "Apps under attack" use the 15-minute peak of the candidate
  coverage, because the attacked app's value drops back to 0 within seconds of the defense. The
  defense panels add the brain's selected decisions and the actuation attempts by outcome. Token
  throughput reads `vllm:generation_tokens_total` and `vllm:prompt_tokens_total`; `nim_tokens_total`
  never existed on this cluster.

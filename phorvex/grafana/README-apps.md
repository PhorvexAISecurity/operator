# Applications dashboard source

`phorvex-apps.json` tracks the dashboard currently provisioned from the
`monitoring/phorvex-apps-dashboard` ConfigMap (UID
`29f58a07-9e45-46f3-86a0-a6b873981086`). It was copied from the installed
`phorvex-apps.json` data value at resourceVersion `49349612` (original SHA-256
`e87c8f0c404d1e9f4757f0bc8437f593264d40de7c0362923ccb075cb614180d`).
The provisioned ConfigMap had a `kubectl` last-applied annotation and no
tracked source in this repository before this file.

Version 6 changes wording and neutral coverage-value colors only. The panel
IDs, positions, PromQL expressions, datasource references and data joins are
unchanged. `phorvex_pod_risk_score` remains the legacy metric name: P1 publishes
candidate coverage value, which can be zero even when a trusted event was
previously observed. This source file does not apply a ConfigMap or change the
running Grafana dashboard. The dashboard owner must review and deploy it via
the existing ConfigMap provisioning path.

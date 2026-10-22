{{/*
phorvex-common.podMonitor: a PodMonitor for one service's metrics port, when
phorvex.metrics.podMonitor.enabled. It requires the PodMonitor API (prometheus-operator)
and labels every series with phorvex.metrics.podMonitor.environment, so one Prometheus
can tell the environments beside each other apart.

Arguments: root (the chart's root context), values (the phorvex values), name,
selector (matchLabels, as YAML), labels (as YAML).
*/}}
{{- define "phorvex-common.podMonitor" -}}
{{- $m := dig "metrics" "podMonitor" (dict) .values -}}
{{- if $m.enabled }}
{{- if not (.root.Capabilities.APIVersions.Has "monitoring.coreos.com/v1/PodMonitor") }}
{{- fail "phorvex.metrics.podMonitor.enabled requires the PodMonitor API (monitoring.coreos.com/v1)" }}
{{- end }}
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: {{ .name }}
  namespace: {{ .root.Release.Namespace }}
  labels:
    {{- .labels | nindent 4 }}
spec:
  namespaceSelector:
    matchNames: [{{ .root.Release.Namespace | quote }}]
  selector:
    matchLabels:
      {{- .selector | nindent 6 }}
  podMetricsEndpoints:
  - port: metrics
    path: /metrics
    interval: {{ $m.interval | default "30s" }}
    # The services' own namespace labels (a policy's tenant) stay theirs.
    honorLabels: true
    relabelings:
    - action: replace
      sourceLabels: [__meta_kubernetes_pod_name]
      targetLabel: instance
    {{- with $m.environment }}
    - action: replace
      targetLabel: environment
      replacement: {{ . | quote }}
    {{- end }}
    {{- with $m.metricRelabelings }}
    metricRelabelings:
      {{- toYaml . | nindent 6 }}
    {{- end }}
{{- end }}
{{- end -}}

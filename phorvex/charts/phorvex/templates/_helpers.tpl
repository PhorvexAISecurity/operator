{{- define "phorvex.name" -}}
phorvex
{{- end -}}

{{- define "phorvex.fullname" -}}
{{- printf "%s-%s" .Release.Name "phorvex" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "phorvex.labels" -}}
app.kubernetes.io/name: {{ include "phorvex.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: phorvex
{{- end -}}

{{- define "phorvex.serviceAccountName" -}}
{{ include "phorvex.fullname" . }}-manager
{{- end -}}

{{/* Cluster-scoped guard names include namespace plus a hash of untruncated scope. */}}
{{- define "phorvex.auditVolumeGuardName" -}}
{{- $scope := printf "%s/%s" .Release.Namespace (include "phorvex.fullname" .) -}}
{{- printf "%s-%s-audit-pvc-%s" (.Release.Namespace | trunc 16 | trimSuffix "-") (include "phorvex.fullname" . | trunc 24 | trimSuffix "-") ($scope | sha256sum | trunc 10) -}}
{{- end -}}

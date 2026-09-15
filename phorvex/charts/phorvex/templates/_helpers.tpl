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

{{- define "phorvex.consoleServiceAccountName" -}}
{{ include "phorvex.fullname" . }}-console
{{- end -}}

{{/* Cluster-scoped guard names include namespace plus a hash of untruncated scope. */}}
{{- define "phorvex.auditVolumeGuardName" -}}
{{- $scope := printf "%s/%s" .Release.Namespace (include "phorvex.fullname" .) -}}
{{- printf "%s-%s-audit-pvc-%s" (.Release.Namespace | trunc 16 | trimSuffix "-") (include "phorvex.fullname" . | trunc 24 | trimSuffix "-") ($scope | sha256sum | trunc 10) -}}
{{- end -}}

{{/*
M-94 SecurityEvent creator-identity guard. Cluster-scoped like the audit guard, so the
name carries namespace + release and a hash of the UNTRUNCATED scope: two releases never
collide, and the value is a pure function of the scope — repeated renders of the same
release produce the same name (no genCA/randAlphaNum drift).
*/}}
{{- define "phorvex.eventIdentityPolicyName" -}}
{{- $scope := printf "%s/%s" .Release.Namespace (include "phorvex.fullname" .) -}}
{{- printf "%s-%s-se-creator-%s" (.Release.Namespace | trunc 16 | trimSuffix "-") (include "phorvex.fullname" . | trunc 24 | trimSuffix "-") ($scope | sha256sum | trunc 10) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

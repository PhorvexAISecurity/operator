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
{{- default (printf "%s-manager" (include "phorvex.fullname" .)) .Values.phorvex.serviceAccountName -}}
{{- end -}}

{{/* The manager image, pinned to the digest the release pushed once one is set. */}}
{{- define "phorvex.image" -}}
{{- $image := .Values.phorvex.image -}}
{{- with $image.releaseDigest }}{{ if not (regexMatch "^sha256:[0-9a-f]{64}$" .) }}{{ fail "phorvex.image.releaseDigest must be sha256:<64 lowercase hex>" }}{{ end }}{{ end -}}
{{ $image.repository }}:{{ $image.tag }}{{ with $image.releaseDigest }}@{{ . }}{{ end }}
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

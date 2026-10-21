{{- define "phorvex-actuator.fullname" -}}
{{- printf "%s-%s" .Release.Name "actuator" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "phorvex-actuator.selectorLabels" -}}
app.kubernetes.io/name: phorvex-actuator
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "phorvex-actuator.labels" -}}
{{ include "phorvex-actuator.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: phorvex
app.kubernetes.io/component: actuator
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{/* The manager release's fullname: its detector ServiceAccounts are trusted by name. */}}
{{- define "phorvex-actuator.managerFullname" -}}
{{- default (printf "%s-phorvex" .Release.Name | trunc 63 | trimSuffix "-") .Values.managerFullname -}}
{{- end -}}

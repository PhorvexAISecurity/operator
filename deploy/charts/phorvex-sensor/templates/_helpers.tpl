{{- define "phorvex-sensor.fullname" -}}
{{- printf "%s-%s" .Release.Name "sensor" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "phorvex-sensor.selectorLabels" -}}
app.kubernetes.io/name: phorvex-sensor
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "phorvex-sensor.labels" -}}
{{ include "phorvex-sensor.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: phorvex
app.kubernetes.io/component: sensor
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{/* The manager release's fullname: its detector and observer ServiceAccounts are trusted by name. */}}
{{- define "phorvex-sensor.managerFullname" -}}
{{- default (printf "%s-phorvex" .Release.Name | trunc 63 | trimSuffix "-") .Values.managerFullname -}}
{{- end -}}

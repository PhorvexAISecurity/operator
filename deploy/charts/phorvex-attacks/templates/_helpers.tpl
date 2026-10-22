{{/* The manager release's fullname. The attacks service runs the console's pod, which
names the objects the manager chart creates for it (the grants, the audit source and
its client Secret, the catalogue profiles) after it. */}}
{{- define "phorvex.fullname" -}}
{{- printf "%s-phorvex" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "phorvex-attacks.selectorLabels" -}}
app.kubernetes.io/name: phorvex-attacks
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* The labels the console's pod template puts on its objects, for this service. */}}
{{- define "phorvex.labels" -}}
{{ include "phorvex-attacks.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: phorvex
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

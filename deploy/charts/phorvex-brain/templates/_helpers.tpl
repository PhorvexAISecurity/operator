{{- define "phorvex-brain.fullname" -}}
{{- printf "%s-%s" .Release.Name "brain" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "phorvex-brain.selectorLabels" -}}
app.kubernetes.io/name: phorvex-brain
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "phorvex-brain.labels" -}}
{{ include "phorvex-brain.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: phorvex
app.kubernetes.io/component: brain
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

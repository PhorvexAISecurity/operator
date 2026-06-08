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

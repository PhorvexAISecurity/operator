{{/* Dashboard image: prefer <global.registry>/<repo-basename>:<tag> when a registry
     is set, else the explicit dashboard.image.repository:tag. */}}
{{- define "phorvex-stack.dashboardImage" -}}
{{- $img := .Values.dashboard.image -}}
{{- $reg := .Values.global.registry -}}
{{- if $reg -}}
{{- $base := $img.repository | base -}}
{{- printf "%s/%s:%s" $reg $base $img.tag -}}
{{- else -}}
{{- printf "%s:%s" $img.repository $img.tag -}}
{{- end -}}
{{- end -}}

{{- define "phorvex-stack.dashboardName" -}}
{{- printf "%s-console" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "phorvex-stack.dashboardLabels" -}}
app.kubernetes.io/name: phorvex-console
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: phorvex-stack
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

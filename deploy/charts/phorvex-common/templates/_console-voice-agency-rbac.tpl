{{/* console-voice-agency-rbac.yaml, moved from the manager chart: the manager chart renders it unless
phorvex.console.separate, and deploy/charts/phorvex-console renders it when it is. */}}
{{- define "phorvex-common.console.voice-agency-rbac" -}}
{{- if and .Values.phorvex.console.enabled .Values.phorvex.console.voiceAgencyLive.enabled }}
{{- $full := include "phorvex.fullname" . }}
{{- $uid := required "console.voiceAgencyLive.deploymentUID required" .Values.phorvex.console.voiceAgencyLive.deploymentUID }}
{{- $prefix := printf "phorvex-voice-refund-%s-" (trunc 32 (sha256sum $uid)) }}
# The Live reader can GET the exact owned Voice rule, never change it.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ $full }}-console-voice-agency-rule
  namespace: voice
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["voice-refund-policy"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ $full }}-console-voice-agency-rule
  namespace: voice
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ $full }}-console-voice-agency-rule
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" . }}
  namespace: {{ .Release.Namespace }}
---
# Dynamic journal names are deterministic for one Deployment UID. Grant only
# its possible 1..256 append revisions; an owner change requires a new pin.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ $full }}-console-voice-agency-journal
  namespace: {{ default .Release.Namespace .Values.phorvex.operatorNamespace | quote }}
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames:
  {{- range $i := until 256 }}
  - {{ printf "%s%d" $prefix (add1 $i) | quote }}
  {{- end }}
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ $full }}-console-voice-agency-journal
  namespace: {{ default .Release.Namespace .Values.phorvex.operatorNamespace | quote }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ $full }}-console-voice-agency-journal
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" . }}
  namespace: {{ .Release.Namespace }}
{{- end }}
{{- end -}}

{{/* console-voice-admission-rbac.yaml, moved from the manager chart: the manager chart renders it unless
phorvex.console.separate, and deploy/charts/phorvex-console renders it when it is. */}}
{{- define "phorvex-common.console.voice-admission-rbac" -}}
{{- if and .Values.phorvex.console.enabled .Values.phorvex.voiceAdmission.enabled }}
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" . }}-console-voice-admission
  namespace: voice
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["voice-session-admission-policy", {{ .Values.phorvex.voiceAdmission.sourceConfigMapName | quote }}, {{ .Values.phorvex.voiceAdmission.legacyConfigMapName | quote }}]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["services"]
  resourceNames: ["voice-bot"]
  verbs: ["get"]
- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["list"]
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  resourceNames: ["voice-bot-public"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" . }}-console-voice-admission
  namespace: voice
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" . }}-console-voice-admission
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" . }}
  namespace: {{ .Release.Namespace }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" . }}-console-voice-admission-journal
  namespace: {{ default .Release.Namespace .Values.phorvex.operatorNamespace | quote }}
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["phorvex-voice-admission-journal"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" . }}-console-voice-admission-journal
  namespace: {{ default .Release.Namespace .Values.phorvex.operatorNamespace | quote }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" . }}-console-voice-admission-journal
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" . }}
  namespace: {{ .Release.Namespace }}
{{- end }}
{{- end -}}

{{/* console-endpoint-lease-rbac.yaml, moved from the manager chart: the manager chart renders it unless
phorvex.console.separate, and deploy/charts/phorvex-console renders it when it is. */}}
{{- define "phorvex-common.console.endpoint-lease-rbac" -}}
{{- if and .Values.phorvex.console.enabled .Values.phorvex.console.endpointLease.enabled }}
{{- $full := include "phorvex.fullname" . }}
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ $full }}-console-endpoint-lease-source
  namespace: vllm
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["phorvex-endpoint-lease-policy", {{ .Values.phorvex.console.endpointLease.sourceConfigMapName | quote }}]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["phorvex-endpoint-lease-keys"]
  verbs: ["get"]
- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ $full }}-console-endpoint-lease-source
  namespace: vllm
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ $full }}-console-endpoint-lease-source
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" . }}
  namespace: {{ .Release.Namespace }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ $full }}-console-endpoint-lease-private
  namespace: {{ .Release.Namespace }}
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["vllm-endpoint-lease-callers"]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["phorvex-endpoint-lease-journal"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ $full }}-console-endpoint-lease-private
  namespace: {{ .Release.Namespace }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ $full }}-console-endpoint-lease-private
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" . }}
  namespace: {{ .Release.Namespace }}
{{- end }}
{{- end -}}

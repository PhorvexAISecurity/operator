{{/* console-mongo-exposure.yaml, moved from the manager chart: the manager chart renders it unless
phorvex.console.separate, and deploy/charts/phorvex-console renders it when it is. */}}
{{- define "phorvex-common.console.mongo-exposure" -}}
{{- if and .Values.phorvex.console.mongoExposure.enabled (not .Values.phorvex.console.enabled) }}
{{- fail "mongoExposure.enabled requires console.enabled" }}
{{- end }}
{{- if and .Values.phorvex.console.enabled .Values.phorvex.console.mongoExposure.enabled }}
# One fixed installed namespace for a nonce-owned synthetic document and
# uncredentialed Service-path read. This adds no Secret, policy, namespace or
# Service mutation authority; the worker pins the exact names and UIDs.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" . }}-console-mongo-exposure
  namespace: document-store
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "create", "delete"]
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["pods/portforward"]
  verbs: ["create"]
- apiGroups: [""]
  resources: ["services"]
  resourceNames: ["mongo"]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["persistentvolumeclaims"]
  resourceNames: ["mongo-data"]
  verbs: ["get"]
- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" . }}-console-mongo-exposure
  namespace: document-store
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" . }}-console-mongo-exposure
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" . }}
  namespace: {{ .Release.Namespace }}
{{- end }}
{{- end -}}

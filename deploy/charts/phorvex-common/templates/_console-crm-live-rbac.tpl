{{/* console-crm-live-rbac.yaml, moved from the manager chart: the manager chart renders it unless
phorvex.console.separate, and deploy/charts/phorvex-console renders it when it is. */}}
{{- define "phorvex-common.console.crm-live-rbac" -}}
{{- if and .Values.phorvex.console.enabled .Values.phorvex.console.crmRefundLive.enabled }}
{{- $full := include "phorvex.fullname" . }}
# The CRM Live producer stamps its trusted event with the deny-guard ConfigMap UID so the
# brain and the crm-refund-revoke actuator can bind it. The console already reads Pods,
# Services and PhorvexPolicies in crm; this adds a single resourceName-scoped GET of the
# guard ConfigMap's object (its UID only — the producer never needs the guard data) and
# never a write. The actuator's own write grant is a separate Role (see rbac.yaml).
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ $full }}-console-crm-refund-guard
  namespace: crm
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["crm-refund-guard"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ $full }}-console-crm-refund-guard
  namespace: crm
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ $full }}-console-crm-refund-guard
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" . }}
  namespace: {{ .Release.Namespace }}
{{- end }}
{{- end -}}

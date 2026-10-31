{{/* console-rbac.yaml, moved from the manager chart: the manager chart renders it unless
phorvex.console.separate, and deploy/charts/phorvex-console renders it when it is. */}}
{{- define "phorvex-common.console.rbac" -}}
{{- if and .Values.phorvex.console.guardrailStatic.enabled (not .Values.phorvex.console.enabled) }}
{{- fail "guardrailStatic.enabled requires console.enabled" }}
{{- end }}
{{- if and .Values.phorvex.console.guardrailAvailability.enabled (not .Values.phorvex.console.enabled) }}
{{- fail "guardrailAvailability.enabled requires console.enabled" }}
{{- end }}
{{- if and .Values.phorvex.console.guardrailEffect.enabled (not .Values.phorvex.console.enabled) }}
{{- fail "guardrailEffect.enabled requires console.enabled" }}
{{- end }}
{{- if and .Values.phorvex.console.guardrailOutput.enabled (not .Values.phorvex.console.enabled) }}
{{- fail "guardrailOutput.enabled requires console.enabled" }}
{{- end }}
{{- if and .Values.phorvex.console.litellmLive.enabled (not .Values.phorvex.console.enabled) }}
{{- fail "litellmLive.enabled requires console.enabled" }}
{{- end }}
{{- if and .Values.phorvex.console.voiceAgencyLive.enabled (not .Values.phorvex.console.enabled) }}
{{- fail "voiceAgencyLive.enabled requires console.enabled" }}
{{- end }}
{{- if and .Values.phorvex.console.litellmOutput.enabled (not .Values.phorvex.console.enabled) }}
{{- fail "litellmOutput.enabled requires console.enabled" }}
{{- end }}
{{- if and .Values.phorvex.console.voiceOutputLive.enabled (not .Values.phorvex.console.enabled) }}
{{- fail "voiceOutputLive.enabled requires console.enabled" }}
{{- end }}
{{- if .Values.phorvex.console.enabled }}
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "phorvex.consoleServiceAccountName" . }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "phorvex.labels" . | nindent 4 }}
    app.kubernetes.io/component: console
---
# This identity is for the authenticated console only. It has no manager
# journal, lease, admission, AMTD, actuator or webhook-secret binding.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{ include "phorvex.fullname" . }}-console-role
  labels:
    {{- include "phorvex.labels" . | nindent 4 }}
rules:
- apiGroups: [""]
  resources: ["pods", "nodes", "namespaces", "services"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["statefulsets", "deployments", "replicasets", "daemonsets"]
  verbs: ["get", "list"]
# The attack-catalogue k8s preflight lists EndpointSlices to confirm the demo-api
# baseline is fully represented by Ready Service endpoints before a quarantine.
# Mirrors the cluster-wide pods/services read above (EndpointSlices are the modern
# analog of the Endpoints the console already resolves through Services).
- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get"]
{{- if not .Values.phorvex.services.attacks.endpoint }}
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
{{- end }}
- apiGroups: ["amtd.r6security.com"]
  resources: ["securityevents"]
  # Served remotely, firing and reaping red-team events are the attacks service's.
  verbs: {{ if .Values.phorvex.services.attacks.endpoint }}["get", "list", "watch"]{{ else }}["get", "list", "watch", "create", "update", "patch", "delete"]{{ end }}
- apiGroups: ["phorvex.ai"]
  resources: ["phorvexpolicies"]
  # Confined (attackNamespaces), policy edits are the per-namespace Roles' below.
  verbs: ["get", "list"{{ if not (and .Values.phorvex.services.attacks.endpoint .Values.phorvex.console.attackNamespaces) }}, "patch"{{ end }}]
{{- if and .Values.phorvex.console.allowWorkloadMutations (not .Values.phorvex.services.attacks.endpoint) }}
# The console's vLLM attack adapters label Pods, patch Services and can
# delete test Pods. This is explicit opt-in; it grants no journal or SA writes.
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["update", "patch", "delete"]
- apiGroups: [""]
  resources: ["services"]
  verbs: ["patch"]
{{- end }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {{ include "phorvex.fullname" . }}-console-rolebinding
  labels:
    {{- include "phorvex.labels" . | nindent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {{ include "phorvex.fullname" . }}-console-role
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.consoleServiceAccountName" . }}
  namespace: {{ .Release.Namespace }}
{{- if .Values.phorvex.services.attacks.endpoint }}
{{- $attacksSA := include "phorvex-common.attacksServiceAccountName" . }}
{{- $scoped := .Values.phorvex.console.attackNamespaces }}
{{- $attackCatalog := dig "attackCatalog" "enabled" false .Values.phorvex.console }}
{{- $agentActionCatalog := dig "attackCatalog" "agentAction" "enabled" false .Values.phorvex.console }}
---
# The attacks service fires what the console fired, so it holds the console's base
# grants beyond reading. With console.attackNamespaces, what it and the console may exec
# into and change, policies included, is limited to those namespaces; SecurityEvents
# are cluster-scoped.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{ include "phorvex.fullname" . }}-attacks-role
  labels:
    {{- include "phorvex.labels" . | nindent 4 }}
rules:
- apiGroups: [""]
  resources: {{ if $scoped }}["nodes", "namespaces"]{{ else }}["pods", "nodes", "namespaces", "services"]{{ end }}
  verbs: ["get", "list"]
- apiGroups: ["amtd.r6security.com"]
  resources: ["securityevents"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["phorvex.ai"]
  resources: ["phorvexpolicies"]
  verbs: ["get", "list"{{ if not $scoped }}, "patch"{{ end }}]
{{- if $attackCatalog }}
# TokenReview confirms the short-lived credential before and after the exact identity
# rotation. It grants no credential or impersonation authority.
- apiGroups: ["authentication.k8s.io"]
  resources: ["tokenreviews"]
  verbs: ["create"]
{{- end }}
{{- if $attackCatalog }}
# Reviews grant no authority; exact adapters use them only to prove the fixed
# attacks, manager, sensor, and actuator identities have the installed grants.
- apiGroups: ["authorization.k8s.io"]
  resources: ["selfsubjectaccessreviews", "subjectaccessreviews"]
  verbs: ["create"]
{{- end }}
{{- if not $scoped }}
{{- include "phorvex.attackTargetRules" . }}
{{- end }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {{ include "phorvex.fullname" . }}-attacks-rolebinding
  labels:
    {{- include "phorvex.labels" . | nindent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {{ include "phorvex.fullname" . }}-attacks-role
subjects:
- kind: ServiceAccount
  name: {{ $attacksSA }}
  namespace: {{ .Release.Namespace }}
{{- if $attackCatalog }}
{{- if not (dig "identityRotate" "enabled" false .Values.phorvex) }}{{- fail "console.attackCatalog.enabled requires identityRotate.enabled" }}{{- end }}
{{- $identityNamespace := required "identityRotate.targetNamespace is required for console.attackCatalog" .Values.phorvex.identityRotate.targetNamespace }}
{{- $identityServiceAccount := required "identityRotate.serviceAccountName is required for console.attackCatalog" .Values.phorvex.identityRotate.serviceAccountName }}
---
# AML.T0012 reads and marks only the installed identity fixture. Create cannot be
# resourceName-restricted by Kubernetes; the server contains no caller-controlled name.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" . }}-attacks-identity-catalog
  namespace: {{ $identityNamespace | quote }}
  labels:
    {{- include "phorvex.labels" . | nindent 4 }}
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["serviceaccounts"]
  resourceNames: [{{ $identityServiceAccount | quote }}]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["serviceaccounts/token"]
  resourceNames: [{{ $identityServiceAccount | quote }}]
  verbs: ["create"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["list"]
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: [{{ $identityServiceAccount | quote }}]
  verbs: ["get", "delete"]
- apiGroups: [""]
  resources: ["configmaps"]
  verbs: ["create"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" . }}-attacks-identity-catalog
  namespace: {{ $identityNamespace | quote }}
  labels:
    {{- include "phorvex.labels" . | nindent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" . }}-attacks-identity-catalog
subjects:
- kind: ServiceAccount
  name: {{ $attacksSA }}
  namespace: {{ .Release.Namespace }}
{{- end }}
{{- range $scoped }}
{{- if not (and $agentActionCatalog (eq . "p6-demo")) }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" $ }}-attacks-target
  namespace: {{ . }}
  labels:
    {{- include "phorvex.labels" $ | nindent 4 }}
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list"]
- apiGroups: ["phorvex.ai"]
  resources: ["phorvexpolicies"]
  verbs: ["patch"]
{{- include "phorvex.attackTargetRules" $ }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" $ }}-attacks-target
  namespace: {{ . }}
  labels:
    {{- include "phorvex.labels" $ | nindent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" $ }}-attacks-target
subjects:
- kind: ServiceAccount
  name: {{ $attacksSA }}
  namespace: {{ $.Release.Namespace }}
{{- end }}
---
# The console's policy edits (/api/policy/edit, the optimizer knobs), in this namespace only.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-policy-edit
  namespace: {{ . }}
  labels:
    {{- include "phorvex.labels" $ | nindent 4 }}
rules:
- apiGroups: ["phorvex.ai"]
  resources: ["phorvexpolicies"]
  verbs: ["patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-policy-edit
  namespace: {{ . }}
  labels:
    {{- include "phorvex.labels" $ | nindent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" $ }}-console-policy-edit
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.consoleServiceAccountName" $ }}
  namespace: {{ $.Release.Namespace }}
{{- end }}
{{- end }}
---
# Separate read-only scan inputs so existing console installations can add them safely.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{ include "phorvex.fullname" . }}-console-scan-role
  labels:
    {{- include "phorvex.labels" . | nindent 4 }}
rules:
# Read-only inputs for the live snapshot and reachability graph.
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "list"]
- apiGroups: ["policy"]
  resources: ["poddisruptionbudgets"]
  verbs: ["get", "list"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "clusterroles", "rolebindings", "clusterrolebindings"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {{ include "phorvex.fullname" . }}-console-scan-rolebinding
  labels:
    {{- include "phorvex.labels" . | nindent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {{ include "phorvex.fullname" . }}-console-scan-role
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.consoleServiceAccountName" . }}
  namespace: {{ .Release.Namespace }}
{{- with .Values.phorvex.console.catalogueV1 }}
{{- if and .enabled .voice.enabled .voice.namespace }}
---
# Exact Voice functional-fixture authority. It can establish a port-forward,
# inspect the owned workload/endpoints and submit one PDB-governed eviction;
# it cannot delete Pods directly or change workload/configuration objects.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-voice-v1
  namespace: {{ .voice.namespace }}
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["pods/portforward", "pods/exec"]
  verbs: ["create"]
- apiGroups: [""]
  resources: ["pods/eviction"]
  verbs: ["create"]
- apiGroups: ["policy"]
  resources: ["poddisruptionbudgets"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list"]
- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-voice-v1
  namespace: {{ .voice.namespace }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" $ }}-console-voice-v1
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" $ }}
  namespace: {{ $.Release.Namespace }}
{{- end }}
{{- if and .enabled .guardrailCalibration.enabled }}
---
# Guardrail calibration reads one reviewed namespace. Kubernetes RBAC cannot
# restrict pods/proxy to the two fixed paths; the worker pins target and paths.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-calibration-v1
  namespace: {{ required "guardrail calibration namespace is required" .guardrailCalibration.namespace }}
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["services"]
  resourceNames: [{{ .guardrailCalibration.service | quote }}]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: [{{ .guardrailCalibration.sourceConfigMap | quote }}]
  verbs: ["get"]
- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["list"]
- apiGroups: [""]
  resources: ["pods/proxy"]
  verbs: ["get", "create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-calibration-v1
  namespace: {{ required "guardrail calibration namespace is required" .guardrailCalibration.namespace }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-calibration-v1
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" $ }}
  namespace: {{ $.Release.Namespace }}
{{- end }}
{{- if and .enabled .mcpSession.enabled }}
---
# Fixed installed MCP source/read and one in-memory session protocol. The
# worker constrains the proxy to one Pod, one /mcp path and six fixed requests.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-mcp-session
  namespace: {{ .mcpSession.namespace }}
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["services"]
  resourceNames: [{{ .mcpSession.service | quote }}]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: [{{ .mcpSession.sourceConfigMap | quote }}]
  verbs: ["get"]
- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["list"]
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
- apiGroups: [""]
  resources: ["pods/proxy"]
  verbs: ["create", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-mcp-session
  namespace: {{ .mcpSession.namespace }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" $ }}-console-mcp-session
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" $ }}
  namespace: {{ $.Release.Namespace }}
{{- end }}
{{- if and .enabled .chroma.enabled }}
---
# One reviewed Chroma namespace. The worker fixes the Pod route and only
# creates/deletes its nonce-owned synthetic collection over exact Pod exec loopback.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-chroma-control
  namespace: {{ required "chroma namespace is required" .chroma.namespace }}
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["services"]
  resourceNames: [{{ .chroma.service | quote }}]
  verbs: ["get"]
- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["list"]
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-chroma-control
  namespace: {{ required "chroma namespace is required" .chroma.namespace }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" $ }}-console-chroma-control
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" $ }}
  namespace: {{ $.Release.Namespace }}
{{- end }}
{{- if and .enabled .litellm.enabled }}
---
# LiteLLM direct GET controls use exact Pod exec loopback, so Kubernetes
# credentials never become application Authorization headers.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-litellm-control
  namespace: {{ required "litellm namespace is required" .litellm.namespace }}
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["services"]
  resourceNames: [{{ .litellm.service | quote }}]
  verbs: ["get"]
- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["list"]
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: [{{ .litellm.configMap | quote }}]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-litellm-control
  namespace: {{ required "litellm namespace is required" .litellm.namespace }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" $ }}-console-litellm-control
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" $ }}
  namespace: {{ $.Release.Namespace }}
{{- end }}
{{- end }}
{{- with .Values.phorvex.console.litellmLive }}
{{- if and $.Values.phorvex.console.enabled .enabled }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-litellm-live-source
  namespace: litellm
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: [{{ .sourceConfigMapName | quote }}, "phorvex-litellm-live-clients", "phorvex-litellm-client-policy"]
  verbs: ["get"]
- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-litellm-live-source
  namespace: litellm
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" $ }}-console-litellm-live-source
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" $ }}
  namespace: {{ $.Release.Namespace }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-litellm-live-journal
  namespace: {{ default $.Release.Namespace $.Values.phorvex.operatorNamespace | quote }}
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: [{{ .journalName | quote }}]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-litellm-live-journal
  namespace: {{ default $.Release.Namespace $.Values.phorvex.operatorNamespace | quote }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" $ }}-console-litellm-live-journal
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" $ }}
  namespace: {{ $.Release.Namespace }}
{{- end }}
{{- end }}
{{- with .Values.phorvex.console.litellmOutput }}
{{- if and $.Values.phorvex.console.enabled .enabled }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-litellm-output-source
  namespace: litellm
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["litellm-output-policy"]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames:
  {{- range $index := until 32 }}
  - {{ printf "litellm-output-rule-%02d" $index | quote }}
  {{- end }}
  verbs: ["get", "update"]
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["phorvex-litellm-output-document", "phorvex-litellm-output-prompt"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-litellm-output-source
  namespace: litellm
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" $ }}-console-litellm-output-source
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" $ }}
  namespace: {{ $.Release.Namespace }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-litellm-output-journal
  namespace: {{ default $.Release.Namespace $.Values.phorvex.operatorNamespace | quote }}
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["phorvex-litellm-output-journal"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-litellm-output-journal
  namespace: {{ default $.Release.Namespace $.Values.phorvex.operatorNamespace | quote }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" $ }}-console-litellm-output-journal
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" $ }}
  namespace: {{ $.Release.Namespace }}
{{- end }}
{{- end }}
{{- with .Values.phorvex.console.guardrailOutput }}
{{- if and $.Values.phorvex.console.enabled .enabled }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-output-source
  namespace: {{ .targetNamespace | quote }}
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: [{{ .sourceConfigMap | quote }}, {{ .outputPolicyConfigMapName | quote }}]
  verbs: ["get"]
- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-output-source
  namespace: {{ .targetNamespace | quote }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-output-source
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" $ }}
  namespace: {{ $.Release.Namespace }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-output-journal
  namespace: {{ default $.Release.Namespace $.Values.phorvex.operatorNamespace | quote }}
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: [{{ .outputPolicyJournalName | quote }}]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-output-journal
  namespace: {{ default $.Release.Namespace $.Values.phorvex.operatorNamespace | quote }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-output-journal
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" $ }}
  namespace: {{ $.Release.Namespace }}
{{- end }}
{{- end }}
{{- end }}
{{- with .Values.phorvex.console.guardrailStatic }}
{{- if and $.Values.phorvex.console.enabled .enabled }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-static-source
  namespace: vllm
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: [{{ required "guardrailStatic.sourceConfigMap is required" .sourceConfigMap | quote }}]
  verbs: ["get"]
- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-static-source
  namespace: vllm
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-static-source
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" $ }}
  namespace: {{ $.Release.Namespace }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-static-journals
  namespace: phorvex-system
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: [{{ required "guardrailStatic.guardrailJournalName is required" .guardrailJournalName | quote }}, {{ required "guardrailStatic.kvJournalName is required" .kvJournalName | quote }}]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-static-journals
  namespace: phorvex-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-static-journals
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" $ }}
  namespace: {{ $.Release.Namespace }}
{{- end }}
{{- end }}
{{- with .Values.phorvex.console.guardrailAvailability }}
{{- if and $.Values.phorvex.console.enabled .enabled }}
---
# The recovery case reads only its reviewed vLLM source and route inventory.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-availability-source
  namespace: vllm
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["guardrail-proxy"]
  verbs: ["get"]
- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-availability-source
  namespace: vllm
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-availability-source
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" $ }}
  namespace: {{ $.Release.Namespace }}
---
# The original operation journal is read by exact reviewed ConfigMap name.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-availability-journal
  namespace: phorvex-system
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: [{{ .guardrailJournalName | quote }}]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-availability-journal
  namespace: phorvex-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-availability-journal
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" $ }}
  namespace: {{ $.Release.Namespace }}
{{- end }}
{{- end }}
{{- with .Values.phorvex.console.guardrailEffect }}
{{- if and $.Values.phorvex.console.enabled .enabled }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-effect-source
  namespace: vllm
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["guardrail-proxy"]
  verbs: ["get"]
- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-effect-source
  namespace: vllm
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-effect-source
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" $ }}
  namespace: {{ $.Release.Namespace }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-effect-journal
  namespace: phorvex-system
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: [{{ .guardrailJournalName | quote }}]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-effect-journal
  namespace: phorvex-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" $ }}-console-guardrail-effect-journal
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" $ }}
  namespace: {{ $.Release.Namespace }}
{{- end }}
{{- end }}
{{- if and .Values.phorvex.console.enabled .Values.phorvex.console.drainLive.enabled }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" . }}-console-drain-live-route
  namespace: vllm
rules:
- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" . }}-console-drain-live-route
  namespace: vllm
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" . }}-console-drain-live-route
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" . }}
  namespace: {{ .Release.Namespace }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ include "phorvex.fullname" . }}-console-drain-live-journal
  namespace: phorvex-system
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: [{{ .Values.phorvex.console.drainLive.journalName | quote }}]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ include "phorvex.fullname" . }}-console-drain-live-journal
  namespace: phorvex-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ include "phorvex.fullname" . }}-console-drain-live-journal
subjects:
- kind: ServiceAccount
  name: {{ include "phorvex.attackServiceAccountName" . }}
  namespace: {{ .Release.Namespace }}
{{- end }}
{{- end -}}

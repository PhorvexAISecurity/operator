{{/*
The catalog of every permission the manager's ServiceAccount holds today
(phorvex/charts/phorvex: rbac.yaml, leader-election-rbac.yaml,
voice-admission-rbac.yaml and the MIG agent client role), keyed by the same
values under `phorvex`.

Each rule names who receives its verbs:
- read verbs (get, list, watch) go to the sensor, the dispatcher and the
  actuator, unless the rule lists its `readers`; a Secret rule must;
- every other verb goes to the services the rule lists as `writers`.

Arguments: values (the `phorvex` values), releaseNamespace.
*/}}
{{- define "phorvex-common.rbac.catalog" -}}
{{- $v := .values -}}
{{- $operatorNamespace := default .releaseNamespace $v.operatorNamespace -}}
{{- $nativeOrHybrid := has $v.actuator (list "native" "hybrid") -}}
cluster:
# M-158: uncached, read-only discovery of the installed policy action enum.
- {apiGroups: ["apiextensions.k8s.io"], resources: ["customresourcedefinitions"], resourceNames: ["phorvexpolicies.phorvex.ai"], verbs: ["get"]}
- {apiGroups: ["admissionregistration.k8s.io"], resources: ["mutatingwebhookconfigurations"], verbs: ["get", "list"]}
{{- if $v.codeExecAdmission.enabled }}
# M-6: GET-by-name of the two code-exec admission objects, to verify the deny-policy is in force.
- {apiGroups: ["admissionregistration.k8s.io"], resources: ["validatingadmissionpolicies", "validatingadmissionpolicybindings"], resourceNames: ["phorvex-codeexec-ephemeral"], verbs: ["get"]}
{{- end }}
{{- with dig "eventIdentityPolicy" "external" "" $v }}
# M-94: GET-by-name of the creator-identity guard another release installs, to verify it is in force.
- {apiGroups: ["admissionregistration.k8s.io"], resources: ["validatingadmissionpolicies", "validatingadmissionpolicybindings"], resourceNames: [{{ . | quote }}], verbs: ["get"], readers: [sensor, dispatcher]}
{{- end }}
- {apiGroups: [""], resources: ["pods", "namespaces", "nodes", "services", "configmaps"], verbs: ["get", "list", "watch"]}
- {apiGroups: [""], resources: ["serviceaccounts"], verbs: ["list"]}
- {apiGroups: ["discovery.k8s.io"], resources: ["endpointslices"], verbs: ["get", "list", "watch"]}
- {apiGroups: [""], resources: ["events"], verbs: ["create", "patch"], writers: [dispatcher]}
- {apiGroups: ["networking.k8s.io"], resources: ["networkpolicies"], verbs: ["get", "list", "watch"]}
- {apiGroups: ["policy"], resources: ["poddisruptionbudgets"], verbs: ["get", "list", "watch"]}
- {apiGroups: ["rbac.authorization.k8s.io"], resources: ["roles", "clusterroles", "rolebindings", "clusterrolebindings"], verbs: ["get", "list", "watch"]}
# T1-E: a service reviews its OWN access; creating a review grants nothing.
- {apiGroups: ["authorization.k8s.io"], resources: ["selfsubjectaccessreviews"], verbs: ["create"], writers: [dispatcher, actuator]}
{{- /* Only the Phoenix route creates SecurityEvents and AMTDs (actuator/phoenix.go). */}}
{{- if eq $v.actuator "native" }}
- {apiGroups: ["amtd.r6security.com"], resources: ["securityevents"], verbs: ["get", "list", "watch"]}
- {apiGroups: ["amtd.r6security.com"], resources: ["adaptivemovingtargetdefenses"], verbs: ["get", "list", "watch"]}
{{- else }}
- {apiGroups: ["amtd.r6security.com"], resources: ["securityevents"], verbs: ["get", "list", "watch", "create"], writers: [actuator]}
- {apiGroups: ["amtd.r6security.com"], resources: ["adaptivemovingtargetdefenses"], verbs: ["get", "list", "watch", "create", "update", "patch"], writers: [actuator]}
{{- end }}
- {apiGroups: ["phorvex.ai"], resources: ["phorvexpolicies"], verbs: ["get", "list", "watch"]}
- {apiGroups: ["phorvex.ai"], resources: ["phorvexpolicies/status"], verbs: ["get", "update", "patch"], writers: [dispatcher]}
- {apiGroups: ["phorvex.ai"], resources: ["phorvexpolicies/finalizers"], verbs: ["update"], writers: [dispatcher]}
roles:
# Protected operation receipts and the capacity ledgers live with the operator.
- name: operation-journal
  namespace: {{ $operatorNamespace | quote }}
  rules:
  - {apiGroups: [""], resources: ["configmaps"], verbs: ["get", "list", "create", "update", "delete"], writers: [dispatcher, actuator]}
  {{- if and (eq $v.servingSecurity.mode "secure-required") $nativeOrHybrid }}
  {{- range $v.servingSecurity.bindings }}
  - {apiGroups: [""], resources: ["secrets"], resourceNames: [{{ required "servingSecurity binding secretName is required" .secretName | quote }}], verbs: ["get"], readers: [actuator]}
  {{- end }}
  {{- end }}
{{- range $namespace := $v.actuatorNamespaces }}
# Native/hybrid routine mutations, opted in per tenant namespace.
- name: actuator-routine
  namespace: {{ $namespace | quote }}
  labelled: true
  rules:
  - {apiGroups: [""], resources: ["pods"], verbs: ["get", "list", "delete", "update", "patch"], writers: [actuator]}
  - {apiGroups: [""], resources: ["pods/eviction"], verbs: ["create"], writers: [actuator]}
  - {apiGroups: ["networking.k8s.io"], resources: ["networkpolicies"], verbs: ["create", "get", "list", "delete", "update"], writers: [actuator]}
  - {apiGroups: ["apps"], resources: ["replicasets", "statefulsets", "daemonsets", "deployments"], verbs: ["get"]}
  - {apiGroups: [""], resources: ["replicationcontrollers"], verbs: ["get"]}
  - {apiGroups: ["batch"], resources: ["jobs"], verbs: ["get"]}
  - {apiGroups: [""], resources: ["services"], verbs: ["get", "list", "update"], writers: [actuator]}
  - {apiGroups: ["discovery.k8s.io"], resources: ["endpointslices"], verbs: ["list"]}
{{- end }}
{{- if $v.outputPolicy.enabled }}
{{- $namespace := required "outputPolicy.targetNamespace is required" $v.outputPolicy.targetNamespace }}
{{- $name := required "outputPolicy.configMapName is required" $v.outputPolicy.configMapName }}
{{- if not (regexMatch "^phorvex-output-policy-[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $name) }}{{- fail "outputPolicy.configMapName must name the exact fixture policy" }}{{- end }}
- name: output-policy-activation
  namespace: {{ $namespace | quote }}
  rules:
  - {apiGroups: [""], resources: ["configmaps"], resourceNames: [{{ $name | quote }}], verbs: ["get", "update"], writers: [actuator]}
{{- end }}
{{- if $v.litellmClientRevoke.enabled }}
{{- if not $nativeOrHybrid }}{{- fail "litellmClientRevoke requires native or hybrid actuator" }}{{- end }}
- name: litellm-client-revoke
  namespace: litellm
  rules:
  - {apiGroups: [""], resources: ["configmaps"], resourceNames: ["phorvex-litellm-client-policy"], verbs: ["get", "update"], writers: [actuator]}
{{- end }}
{{- if $v.crmRefundRevoke.enabled }}
{{- if not $nativeOrHybrid }}{{- fail "crmRefundRevoke requires native or hybrid actuator" }}{{- end }}
- name: crm-refund-revoke
  namespace: crm
  rules:
  - {apiGroups: [""], resources: ["configmaps"], resourceNames: ["crm-refund-guard"], verbs: ["get", "update"], writers: [actuator]}
{{- end }}
{{- if $v.agentActionDeny.enabled }}
{{- if not $nativeOrHybrid }}{{- fail "agentActionDeny requires native or hybrid actuator" }}{{- end }}
{{- range $namespace := $v.actuatorNamespaces }}
{{- /* Namespace-parametric analog of crm-refund-revoke: granted only on the fixed guard name per enabled namespace. */}}
- name: agent-action-deny
  namespace: {{ $namespace | quote }}
  rules:
  - {apiGroups: [""], resources: ["configmaps"], resourceNames: ["agent-deny-guard"], verbs: ["get", "update"], writers: [actuator]}
{{- end }}
{{- end }}
{{- if $v.endpointLease.enabled }}
{{- if not $nativeOrHybrid }}{{- fail "endpointLease requires native or hybrid actuator" }}{{- end }}
- name: endpoint-lease
  namespace: vllm
  rules:
  - {apiGroups: [""], resources: ["configmaps"], resourceNames: ["phorvex-endpoint-lease-policy"], verbs: ["get", "update"], writers: [actuator]}
  - {apiGroups: [""], resources: ["configmaps"], resourceNames: ["guardrail-proxy"], verbs: ["get"]}
  - {apiGroups: [""], resources: ["services"], resourceNames: ["vllm"], verbs: ["get"]}
  - {apiGroups: ["apps"], resources: ["deployments"], resourceNames: ["vllm"], verbs: ["get"]}
  - {apiGroups: ["apps"], resources: ["replicasets"], verbs: ["get"]}
- name: endpoint-lease-journal
  namespace: {{ $operatorNamespace | quote }}
  rules:
  - {apiGroups: [""], resources: ["configmaps"], resourceNames: ["phorvex-endpoint-lease-journal"], verbs: ["get", "update"], writers: [actuator]}
{{- end }}
{{- /*
LIGHT identity-rotate (actuator/handlers_k8s.go, identity_rotation.go): the actuator
deletes and recreates the dedicated fixture ServiceAccount (a new UID) and removes its
legacy token Secrets; the sensor's observation builder (identityfixture.Observe) watches
the fixture. `dig` keeps the feature off where the values omit it, so the manager chart's
defaults and the library probe render unchanged (tools/test_service_charts.py).
*/}}
{{- if dig "identityRotate" "enabled" false $v }}
{{- if not $nativeOrHybrid }}{{- fail "identityRotate requires native or hybrid actuator" }}{{- end }}
{{- $idNamespace := required "identityRotate.targetNamespace is required" $v.identityRotate.targetNamespace }}
{{- $idServiceAccount := required "identityRotate.serviceAccountName is required" $v.identityRotate.serviceAccountName }}
# The actuator's SA-mutation authority: it gets+deletes the pinned fixture ServiceAccount
# and creates its successor (K8s cannot name-restrict create), and gets+deletes the legacy
# token Secrets in the namespace (K8s SSAR checks per-name, the handler touches only exact
# legacy Secret names). Modelled on the live phorvex-phorvex-identity-rotation-0 role.
- name: identity-rotate
  namespace: {{ $idNamespace | quote }}
  rules:
  - {apiGroups: [""], resources: ["serviceaccounts"], resourceNames: [{{ $idServiceAccount | quote }}], verbs: ["get", "delete"], readers: [actuator], writers: [actuator]}
  - {apiGroups: [""], resources: ["serviceaccounts"], verbs: ["create"], writers: [actuator]}
  - {apiGroups: [""], resources: ["secrets"], verbs: ["get", "delete"], readers: [actuator], writers: [actuator]}
# The sensor's observation of the fixture (identityfixture.Observe): the pinned
# ServiceAccount, the namespace's Secrets, and the Deployment/ReplicaSet behind it. Pods,
# namespaces, configmaps and phorvexpolicies are already read cluster-wide (above).
- name: identity-rotate-observe
  namespace: {{ $idNamespace | quote }}
  rules:
  - {apiGroups: [""], resources: ["serviceaccounts"], resourceNames: [{{ $idServiceAccount | quote }}], verbs: ["get"], readers: [sensor]}
  - {apiGroups: [""], resources: ["secrets"], verbs: ["list"], readers: [sensor]}
  - {apiGroups: ["apps"], resources: ["deployments", "replicasets"], verbs: ["get"], readers: [sensor]}
{{- end }}
{{- range $feature, $policy := dict "voiceMemory" "voice-memory-policy" "voiceOutput" "voice-output-policy" "voiceRefund" "voice-refund-policy" "voiceMCP" "voice-mcp-tool-policy" }}
{{- if (index $v $feature).enabled }}
{{- if not $nativeOrHybrid }}{{- fail (printf "%s requires native or hybrid actuator" $feature) }}{{- end }}
- name: {{ get (dict "voiceMemory" "voice-memory" "voiceOutput" "voice-output" "voiceRefund" "voice-refund" "voiceMCP" "voice-mcp") $feature }}
  namespace: voice
  rules:
  - {apiGroups: [""], resources: ["configmaps"], resourceNames: [{{ $policy | quote }}], verbs: ["get", "update"], writers: [actuator]}
  - {apiGroups: [""], resources: ["secrets"], resourceNames: ["voice-memory-state-token"], verbs: ["get"], readers: [actuator]}
{{- end }}
{{- end }}
{{- if $v.litellmOutput.enabled }}
{{- if not $v.litellmClientRevoke.enabled }}{{- fail "litellmOutput requires litellmClientRevoke for the private status credential" }}{{- end }}
- name: litellm-output
  namespace: litellm
  rules:
  - {apiGroups: [""], resources: ["configmaps"], resourceNames: ["litellm-output-policy"], verbs: ["get", "update"], writers: [actuator]}
  # The sensor binds the observation to these objective seeds; the actuator verifies them.
  - {apiGroups: [""], resources: ["secrets"], resourceNames: ["phorvex-litellm-output-document", "phorvex-litellm-output-prompt"], verbs: ["get"], readers: [sensor, actuator]}
{{- end }}
# client-go LeaseLock uses get/create/update; only the elected manager needs it.
- name: leader-election
  namespace: {{ .releaseNamespace | quote }}
  rules:
  - {apiGroups: ["coordination.k8s.io"], resources: ["leases"], verbs: ["get", "create", "update"], readers: [dispatcher], writers: [dispatcher]}
{{- if $v.voiceAdmission.enabled }}
{{- if not $nativeOrHybrid }}{{- fail "voiceAdmission requires native or hybrid actuator" }}{{- end }}
{{- range list "sourceConfigMapName" "legacyConfigMapName" }}
{{- $name := required (printf "voiceAdmission.%s required" .) (index $v.voiceAdmission .) }}
{{- if or (gt (len $name) 63) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $name)) }}{{- fail "voiceAdmission source ConfigMap name invalid" }}{{- end }}
{{- end }}
- name: voice-admission
  namespace: voice
  rules:
  - {apiGroups: [""], resources: ["configmaps"], resourceNames: ["voice-session-admission-policy"], verbs: ["get", "update"], writers: [actuator]}
  - {apiGroups: [""], resources: ["configmaps"], resourceNames: [{{ $v.voiceAdmission.sourceConfigMapName | quote }}, {{ $v.voiceAdmission.legacyConfigMapName | quote }}], verbs: ["get"]}
  - {apiGroups: [""], resources: ["secrets"], resourceNames: ["voice-memory-state-token"], verbs: ["get"], readers: [actuator]}
  - {apiGroups: ["networking.k8s.io"], resources: ["ingresses"], resourceNames: ["voice-bot-public"], verbs: ["get"]}
- name: voice-admission-journal
  namespace: {{ $operatorNamespace | quote }}
  rules:
  - {apiGroups: [""], resources: ["configmaps"], resourceNames: ["phorvex-voice-admission-journal"], verbs: ["get", "update"], writers: [actuator]}
{{- end }}
{{- if $v.mig.nodeExec.enabled }}
{{- $namespace := required "phorvex.mig.nodeExec.namespace is required when enabled" $v.mig.nodeExec.namespace }}
{{- $daemonSet := required "phorvex.mig.nodeExec.daemonSetName is required when enabled" $v.mig.nodeExec.daemonSetName }}
# Exec into the trusted MIG agent only; no other namespace receives exec.
- name: mig-agent-client
  namespace: {{ $namespace | quote }}
  rules:
  - {apiGroups: [""], resources: ["pods"], verbs: ["get", "list"], readers: [actuator]}
  - {apiGroups: [""], resources: ["pods/exec"], verbs: ["create"], writers: [actuator]}
  - {apiGroups: ["apps"], resources: ["daemonsets"], resourceNames: [{{ $daemonSet | quote }}], verbs: ["get"], readers: [actuator]}
{{- end }}
{{- end -}}

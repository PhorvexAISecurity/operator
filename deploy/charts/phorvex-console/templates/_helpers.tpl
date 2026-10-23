{{/* The names the manager chart (phorvex/charts/phorvex) gives the console's objects,
which this chart keeps: a console moved between the two charts keeps its objects and
its Deployment's selector. tools/test_service_charts.py requires both charts to render
the same objects. */}}
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

{{- define "phorvex.consoleServiceAccountName" -}}
{{ include "phorvex.fullname" . }}-console
{{- end -}}

{{/* The ServiceAccount that fires attacks: the attacks service's once the attack routes
are served remotely (services.attacks.endpoint), otherwise the console's. */}}
{{- define "phorvex.attackServiceAccountName" -}}
{{- if .Values.phorvex.services.attacks.endpoint -}}
{{- include "phorvex-common.attacksServiceAccountName" . -}}
{{- else -}}
{{- include "phorvex.consoleServiceAccountName" . -}}
{{- end -}}
{{- end -}}

{{/* What the attacks service needs in the namespaces it attacks. */}}
{{- define "phorvex.attackTargetRules" }}
- apiGroups: ["apps"]
  resources: ["statefulsets", "deployments", "replicasets", "daemonsets"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
{{- if .Values.phorvex.console.allowWorkloadMutations }}
# The vLLM attack adapters label Pods, patch Services and can delete test Pods.
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["update", "patch", "delete"]
- apiGroups: [""]
  resources: ["services"]
  verbs: ["patch"]
{{- end }}
{{- end }}

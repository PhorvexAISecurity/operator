{{/*
phorvex-common.rbac.rules keeps the verbs of each rule that `service` receives (see
the catalog), dropping rules left with none. Service "all" keeps every verb:
the manager acting in process. Returns {rules: [...]} as YAML.
*/}}
{{- define "phorvex-common.rbac.rules" -}}
{{- $service := .service -}}
{{- $reads := list "get" "list" "watch" -}}
{{- $out := list -}}
{{- range .rules -}}
{{- $rule := . -}}
{{- if and (has "secrets" $rule.resources) (not $rule.readers) -}}{{- fail "phorvex-common: a Secret rule must name its readers" -}}{{- end -}}
{{- $readers := $rule.readers | default (list "sensor" "dispatcher" "actuator") -}}
{{- $writers := $rule.writers | default (list) -}}
{{- $verbs := list -}}
{{- range $rule.verbs -}}
{{- if and (not (has . $reads)) (not $writers) -}}{{- fail (printf "phorvex-common: verb %s on %v names no writer" . $rule.resources) -}}{{- end -}}
{{- if or (eq $service "all") (has $service (ternary $readers $writers (has . $reads))) -}}
{{- $verbs = append $verbs . -}}
{{- end -}}
{{- end -}}
{{- if $verbs -}}
{{- $kept := dict "apiGroups" $rule.apiGroups "resources" $rule.resources "verbs" $verbs -}}
{{- if $rule.resourceNames -}}{{- $_ := set $kept "resourceNames" $rule.resourceNames -}}{{- end -}}
{{- $out = append $out $kept -}}
{{- end -}}
{{- end -}}
{{- toYaml (dict "rules" $out) -}}
{{- end -}}

{{/*
phorvex-common.rbac.objects renders one service's ClusterRole, Roles and their
bindings to its ServiceAccount.

Arguments:
  service             all | dispatcher | sensor | actuator
  values              the `phorvex` values
  releaseNamespace    the release namespace
  serviceAccountName  the subject
  clusterRoleName, clusterRoleBindingName
  rolePrefix          each Role and RoleBinding is <rolePrefix>-<name>
  labels              metadata labels (YAML)
In mode "all" the objects are labelled exactly as the manager chart labels
them today; a split service labels every object.
*/}}
{{- define "phorvex-common.rbac.objects" -}}
{{- $args := . -}}
{{- if not (has .service (list "all" "dispatcher" "sensor" "actuator")) -}}{{- fail (printf "phorvex-common: unknown service %q" .service) -}}{{- end -}}
{{- $catalog := include "phorvex-common.rbac.catalog" (dict "values" .values "releaseNamespace" .releaseNamespace) | fromYaml -}}
{{- $cluster := include "phorvex-common.rbac.rules" (dict "rules" $catalog.cluster "service" .service) | fromYaml -}}
{{- if $cluster.rules }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{ .clusterRoleName }}
  labels:
    {{- .labels | nindent 4 }}
rules:
{{ toYaml $cluster.rules }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {{ .clusterRoleBindingName }}
  labels:
    {{- .labels | nindent 4 }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {{ .clusterRoleName }}
subjects:
- kind: ServiceAccount
  name: {{ .serviceAccountName }}
  namespace: {{ .releaseNamespace }}
{{- end }}
{{- range $catalog.roles }}
{{- $rules := include "phorvex-common.rbac.rules" (dict "rules" .rules "service" $args.service) | fromYaml }}
{{- if $rules.rules }}
{{- $labelled := or (ne $args.service "all") .labelled }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ printf "%s-%s" $args.rolePrefix .name }}
  namespace: {{ .namespace | quote }}
  {{- if $labelled }}
  labels:
    {{- $args.labels | nindent 4 }}
  {{- end }}
rules:
{{ toYaml $rules.rules }}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: {{ printf "%s-%s" $args.rolePrefix .name }}
  namespace: {{ .namespace | quote }}
  {{- if $labelled }}
  labels:
    {{- $args.labels | nindent 4 }}
  {{- end }}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: {{ printf "%s-%s" $args.rolePrefix .name }}
subjects:
- kind: ServiceAccount
  name: {{ $args.serviceAccountName }}
  namespace: {{ $args.releaseNamespace }}
{{- end }}
{{- end }}
{{- end -}}

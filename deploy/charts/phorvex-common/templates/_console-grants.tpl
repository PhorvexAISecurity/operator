{{/* console-grants.yaml, moved from the manager chart: the manager chart renders it unless
phorvex.console.separate, and deploy/charts/phorvex-console renders it when it is. */}}
{{/* Optional additive subjects survive a later catalogue overlay replacing data.
The default path returns the original bytes, including the existing checksum. */}}
{{- define "phorvex-common.console.grantsData" -}}
{{- $raw := .Values.phorvex.console.auth.grants.data | default "{\n  \"version\": 1,\n  \"subjects\": []\n}\n" -}}
{{- $extra := list -}}
{{- if hasKey .Values.phorvex.console.auth.grants "extraSubjects" -}}{{- $extra = .Values.phorvex.console.auth.grants.extraSubjects -}}{{- end -}}
{{- if not (kindIs "slice" $extra) -}}{{- fail "console grants extraSubjects must be a list" -}}{{- end -}}
{{- if $extra -}}
{{- if and (hasKey .Values.phorvex.console.auth.grants "data") (not (kindIs "string" .Values.phorvex.console.auth.grants.data)) -}}
{{- fail "console grants data must be a JSON string" -}}
{{- end -}}
{{- $doc := mustFromJson $raw -}}
{{- if or (not (kindIs "map" $doc)) (not (kindIs "float64" $doc.version)) (ne (toString $doc.version) "1") (not (kindIs "slice" $doc.subjects)) -}}
{{- fail "console grants data must contain version 1 and a subjects list" -}}
{{- end -}}
{{- range $key, $_ := $doc -}}{{- if not (has $key (list "version" "subjects")) -}}{{- fail "console grants data contains an unknown field" -}}{{- end -}}{{- end -}}
{{- $subjects := concat $doc.subjects $extra -}}
{{- $seen := dict -}}
{{- range $grant := $subjects -}}
{{- if not (kindIs "map" $grant) -}}{{- fail "console grants subject must be an object" -}}{{- end -}}
{{- range $key, $_ := $grant -}}{{- if not (has $key (list "issuer" "subject" "roles" "tenants" "targets" "note")) -}}{{- fail "console grants subject contains an unknown field" -}}{{- end -}}{{- end -}}
{{- range $field := list "issuer" "subject" -}}
{{- $value := get $grant $field -}}
{{- if not (kindIs "string" $value) -}}{{- fail "console grants issuer and subject must be strings" -}}{{- end -}}
{{- if or (empty (trim $value)) (eq (trim $value) "*") -}}{{- fail "console grants issuer and subject must be exact nonempty strings" -}}{{- end -}}
{{- end -}}
{{- $key := toJson (list (trim $grant.issuer) (trim $grant.subject)) -}}
{{- if hasKey $seen $key -}}{{- fail "console grants contain a duplicate issuer/subject binding" -}}{{- end -}}
{{- $_ := set $seen $key true -}}
{{- if or (not (kindIs "slice" $grant.roles)) (empty $grant.roles) -}}{{- fail "console grants roles must be a nonempty list" -}}{{- end -}}
{{- range $role := $grant.roles -}}
{{- if not (kindIs "string" $role) -}}{{- fail "console grants role must be a string" -}}{{- end -}}
{{- if not (has (trim $role) (list "owner" "investor" "operator")) -}}{{- fail "console grants contain an unknown role" -}}{{- end -}}
{{- end -}}
{{- range $field := list "tenants" "targets" -}}
{{- if hasKey $grant $field -}}
{{- if not (kindIs "slice" (get $grant $field)) -}}{{- fail "console grants scopes must be lists" -}}{{- end -}}
{{- range $scope := get $grant $field -}}
{{- if not (kindIs "string" $scope) -}}{{- fail "console grants scope must be a string" -}}{{- end -}}
{{- if empty (trim $scope) -}}{{- fail "console grants scope must not be empty" -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if and (hasKey $grant "note") (not (kindIs "string" $grant.note)) -}}{{- fail "console grants note must be a string" -}}{{- end -}}
{{- end -}}
{{- $_ := set $doc "subjects" $subjects -}}
{{- toJson $doc -}}
{{- else -}}{{- $raw -}}{{- end -}}
{{- end -}}

{{- define "phorvex-common.console.grants" -}}
{{- if and .Values.phorvex.console.enabled .Values.phorvex.console.auth.grants.enabled .Values.phorvex.console.auth.grants.create }}
# ── console subject grants (M-136) ────────────────────────────────────────────
# The console's authorization policy: which VERIFIED issuer+subject holds which role, over which
# tenants and cluster targets. This is DevOps policy, not something the console can infer.
#
# Rendering it here is a convenience for GitOps. The console never invents an entry: no binding
# means the subject is authenticated and authorized for nothing, which is the correct state until
# a human decides who the operators are. Do NOT bind a subject because an identity provider let
# them log in, because their email looks internal, or to "unblock" a demo — a wildcard tenant
# grant on the operator role is full cluster control through the console's ServiceAccount.
#
# Subjects are the Cognito user-pool `sub` (a UUID), not an email address.
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Values.phorvex.console.auth.grants.configMapName | default (printf "%s-console-grants" (include "phorvex.fullname" .)) }}
  labels:
    app.kubernetes.io/name: {{ include "phorvex.name" . }}
    app.kubernetes.io/instance: {{ .Release.Name }}
    app.kubernetes.io/component: console-auth
data:
  {{ .Values.phorvex.console.auth.grants.fileName }}: |
{{ include "phorvex-common.console.grantsData" . | indent 4 }}
{{- end }}
{{- end -}}

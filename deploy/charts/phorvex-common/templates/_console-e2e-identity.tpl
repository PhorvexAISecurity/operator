{{/* console-e2e-identity.yaml, moved from the manager chart: the manager chart renders it unless
phorvex.console.separate, and deploy/charts/phorvex-console renders it when it is. */}}
{{- define "phorvex-common.console.e2e-identity" -}}
{{- if .Values.phorvex.console.auth.e2eIdentity.enabled }}
{{- $name := printf "%s-console-e2e" (include "phorvex.fullname" .) }}
# The End-to-End pipeline's console identity (docs/CONSOLE-AUTH.md, "DevOps handoff").
# The cluster's own OIDC issuer is the bearer IdP: CI mints a short-lived projected token
# for THIS ServiceAccount with the console audience (`kubectl create token --audience`), the
# console verifies it against the issuer's public JWKS, and the grant table maps the subject
#   system:serviceaccount:{{ .Release.Namespace }}:{{ $name }}
# to exactly the tenants the pipeline attacks. The account carries no RBAC at all — its token
# is a console credential, not a Kubernetes one — and no permanent token is ever created.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ $name }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "phorvex.labels" . | nindent 4 }}
automountServiceAccountToken: false
{{- end }}
{{- end -}}

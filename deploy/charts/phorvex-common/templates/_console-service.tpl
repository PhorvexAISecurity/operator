{{/* console-service.yaml, moved from the manager chart: the manager chart renders it unless
phorvex.console.separate, and deploy/charts/phorvex-console renders it when it is. */}}
{{- define "phorvex-common.console.service" -}}
{{- $ingress := .Values.phorvex.console.ingress }}
{{- if $ingress.enabled }}
{{- if not $ingress.host }}{{ fail "phorvex.console.ingress.host is required" }}{{ end }}
# The console's own Service and Ingress, for an environment that exposes the console
# itself rather than through the production stack's dashboard (deploy/helm/phorvex-stack).
apiVersion: v1
kind: Service
metadata:
  name: {{ include "phorvex.fullname" . }}-console
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "phorvex.labels" . | nindent 4 }}
    app.kubernetes.io/component: console
spec:
  type: ClusterIP
  selector:
    app.kubernetes.io/name: phorvex-console
    app.kubernetes.io/instance: {{ .Release.Name }}
  ports:
  - name: http
    port: 80
    targetPort: http
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ include "phorvex.fullname" . }}-console
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "phorvex.labels" . | nindent 4 }}
    app.kubernetes.io/component: console
  {{- with $ingress.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  {{- with $ingress.className }}
  ingressClassName: {{ . }}
  {{- end }}
  rules:
  - host: {{ $ingress.host | quote }}
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: {{ include "phorvex.fullname" . }}-console
            port:
              name: http
{{- end }}
{{- end -}}

{{/*
The services' gRPC mutual TLS (ADR-0001, phorvex/internal/servicetls), on with
phorvex.serviceTLS.enabled. Each end mounts its own Secret, which
deploy/eks/provision-service-mtls.sh writes: <release>-<end>-grpc-tls, holding
tls.crt, tls.key and ca.crt. The sensor, brain and actuator admit only the
dispatcher's certificate identity; the dispatcher admits only the service it dialed.

The templates take a dict of root (the including chart's root context) and end
(dispatcher, brain, sensor or actuator).
*/}}
{{- define "phorvex-common.serviceTLS.secretName" -}}
{{- printf "%s-%s-grpc-tls" .root.Release.Name .end | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* The DNS name the dispatcher's client certificate is issued for. Arguments: the root context. */}}
{{- define "phorvex-common.serviceTLS.dispatcherIdentity" -}}
{{- printf "%s-dispatcher.%s.svc" .Release.Name .Release.Namespace -}}
{{- end -}}

{{- define "phorvex-common.serviceTLS.args" -}}
- --grpc-tls-cert=/etc/phorvex/grpc-tls/tls.crt
- --grpc-tls-key=/etc/phorvex/grpc-tls/tls.key
- --grpc-tls-ca=/etc/phorvex/grpc-tls/ca.crt
{{- if ne .end "dispatcher" }}
- --grpc-tls-peer={{ include "phorvex-common.serviceTLS.dispatcherIdentity" .root }}
{{- end }}
{{- end -}}

{{- define "phorvex-common.serviceTLS.volumeMount" -}}
- name: grpc-tls
  mountPath: /etc/phorvex/grpc-tls
  readOnly: true
{{- end -}}

{{- define "phorvex-common.serviceTLS.volume" -}}
- name: grpc-tls
  secret:
    secretName: {{ include "phorvex-common.serviceTLS.secretName" . }}
{{- end -}}

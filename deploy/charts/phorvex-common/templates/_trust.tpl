{{/*
The trust every service must read alike. The service handshakes compare it, so a
service trusting other identities than the manager is refused (ADR-0001). These
derive it from the same `phorvex` values the manager chart reads, as that chart
does.

Arguments of each: values (the `phorvex` values), releaseNamespace, and
managerFullname, the manager release's fullname, which names its detector and
observer ServiceAccounts.
*/}}

{{/* phorvex-common.trustedDetectors: the --trusted-detectors list, or empty. */}}
{{- define "phorvex-common.trustedDetectors" -}}
{{- $v := .values -}}
{{- $detectors := $v.trustedDetectors | default list -}}
{{- if $v.e2eDetector.enabled -}}
{{- $detectors = append $detectors (printf "%s/%s-e2e-detector" .releaseNamespace .managerFullname) -}}
{{- end -}}
{{- if $v.console.podBoundTokenCPU.enabled -}}
{{- $detectors = append $detectors (printf "%s/%s-e2e-detector-cpu" .releaseNamespace .managerFullname) -}}
{{- end -}}
{{- join "," $detectors -}}
{{- end -}}

{{/* phorvex-common.trustedLossObservers: the --trusted-loss-observers list, or empty. */}}
{{- define "phorvex-common.trustedLossObservers" -}}
{{- $loss := .values.lossHistory -}}
{{- if $loss.enabled -}}
{{- $observers := $loss.trustedObservers | default list -}}
{{- if $loss.observer.enabled -}}
{{- $observers = append $observers (printf "%s/%s" .releaseNamespace (printf "%s-loss-observer" .managerFullname | trunc 63 | trimSuffix "-")) -}}
{{- end -}}
{{- if eq (len $observers) 0 -}}{{- fail "phorvex.lossHistory.trustedObservers is required when enabled" -}}{{- end -}}
{{- join "," $observers -}}
{{- end -}}
{{- end -}}

{{/* phorvex-common.trustedCurrentInventoryObservers: the --trusted-current-inventory-observers list, or empty. */}}
{{- define "phorvex-common.trustedCurrentInventoryObservers" -}}
{{- $loss := .values.lossHistory -}}
{{- $current := $loss.currentInventory -}}
{{- if and $current.enabled (not $loss.enabled) -}}{{- fail "phorvex.lossHistory.currentInventory.enabled requires phorvex.lossHistory.enabled" -}}{{- end -}}
{{- if $current.enabled -}}
{{- $observers := $current.trustedObservers | default list -}}
{{- if $current.observer.enabled -}}
{{- $observers = append $observers (printf "%s/%s" .releaseNamespace (printf "%s-current-inventory-observer" .managerFullname | trunc 63 | trimSuffix "-")) -}}
{{- end -}}
{{- if eq (len $observers) 0 -}}{{- fail "phorvex.lossHistory.currentInventory.trustedObservers is required when enabled" -}}{{- end -}}
{{- join "," $observers -}}
{{- end -}}
{{- end -}}

{{/*
phorvex-common.injectorEnv: the ServiceAccount the workload live arms create their
SecurityEvents as (--injector-identity), or nothing for the default
(phorvex-system/phorvex-phorvex-console). Every service and the console read it from
this variable, which an image older than the setting ignores. It is
phorvex.injectorIdentity when set; otherwise the release's attacks service once the
attacks routes are served remotely (phorvex.services.attacks.endpoint), and otherwise
.default, which the attacks service sets to its own account.
*/}}
{{- define "phorvex-common.injectorEnv" -}}
{{- $identity := .values.injectorIdentity | default .default -}}
{{- if and (not $identity) (dig "services" "attacks" "endpoint" "" .values) -}}
{{- $identity = printf "%s/%s" .releaseNamespace (printf "%s-attacks" .releaseName | trunc 63 | trimSuffix "-") -}}
{{- end -}}
{{- with $identity -}}
- name: PHORVEX_INJECTOR_IDENTITY
  value: {{ . | quote }}
{{- end -}}
{{- end -}}

{{/*
phorvex-common.endpointLeaseEnv: the reviewed endpoint lease authority as the
container environment the trust flags default from, or nothing when the lease is
off. Only immutable references are accepted.
*/}}
{{- define "phorvex-common.endpointLeaseEnv" -}}
{{- $lease := .values.endpointLease -}}
{{- if $lease.enabled -}}
{{- if not (regexMatch "^[0-9a-f]{64}$" $lease.approvedSourceSHA256) -}}{{- fail "endpointLease.approvedSourceSHA256 requires lowercase SHA-256" -}}{{- end -}}
{{- if not (regexMatch "^[^[:space:]@]+@sha256:[0-9a-f]{64}$" $lease.approvedProxyImage) -}}{{- fail "endpointLease.approvedProxyImage requires immutable repo@sha256" -}}{{- end -}}
{{- if not (regexMatch "^[^[:space:]@]+@sha256:[0-9a-f]{64}$" $lease.approvedEngineImage) -}}{{- fail "endpointLease.approvedEngineImage requires immutable repo@sha256" -}}{{- end -}}
- name: PHORVEX_ENDPOINT_LEASE_APPROVED_SOURCE_SHA256
  value: {{ $lease.approvedSourceSHA256 | quote }}
- name: PHORVEX_ENDPOINT_LEASE_APPROVED_PROXY_IMAGE
  value: {{ $lease.approvedProxyImage | quote }}
- name: PHORVEX_ENDPOINT_LEASE_APPROVED_ENGINE_IMAGE
  value: {{ $lease.approvedEngineImage | quote }}
{{- end -}}
{{- end -}}

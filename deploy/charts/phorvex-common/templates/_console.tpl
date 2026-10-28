{{/*
phorvex-common.consoleDeployment: the console's Deployment, rendered from the root
context of the chart that includes it (ADR-0001, phase 6). It reads the manager chart's
keys under phorvex. The manager chart renders the console with it, and the attacks
chart (phorvex-attacks) the attacks service: the same pod, run as cmd/attacks under its
own ServiceAccount, name, image and state.
*/}}
{{- define "phorvex-common.attacksServiceAccountName" -}}
{{- printf "%s-attacks" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* The grants ConfigMap the pod mounts. The pod reads it once, at startup, so the
attacks chart renders its own copy when the grants are rendered at all: then a grants
change and the pod it rolls arrive in the same sync, and the pod never starts on the
manager release's older copy. */}}
{{- define "phorvex-common.grantsConfigMapName" -}}
{{- $grants := .Values.phorvex.console.auth.grants -}}
{{- if and (eq .Chart.Name "phorvex-attacks") $grants.create -}}
{{- printf "%s-attacks-grants" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $grants.configMapName | default (printf "%s-console-grants" (include "phorvex.fullname" .)) -}}
{{- end -}}
{{- end -}}

{{- define "phorvex-common.consoleDeployment" -}}
{{- $attacks := eq .Chart.Name "phorvex-attacks" }}
{{- $remoteAttacks := and (not $attacks) .Values.phorvex.services.attacks.endpoint }}
{{- $podServiceAccount := "" }}
{{- if $attacks }}{{ $podServiceAccount = include "phorvex-common.attacksServiceAccountName" . }}{{ else }}{{ $podServiceAccount = include "phorvex.consoleServiceAccountName" . }}{{ end }}
{{- /* The ServiceAccount the workload live arms create their SecurityEvents as. */}}
{{- $injector := $podServiceAccount }}
{{- if $remoteAttacks }}{{ $injector = include "phorvex-common.attacksServiceAccountName" . }}{{ end }}
{{- if and .Values.phorvex.console.catalogueV1.litellm.inferenceEnabled (not .Values.phorvex.console.enabled) }}
{{- fail "console.catalogueV1.litellm.inferenceEnabled requires console.enabled" }}
{{- end }}
{{- if .Values.phorvex.console.catalogueV1.mcpVoiceModel.enabled }}
{{- if not (and .Values.phorvex.console.enabled .Values.phorvex.console.catalogueV1.enabled .Values.phorvex.console.catalogueV1.voice.enabled .Values.phorvex.console.catalogueV1.mcpSession.enabled .Values.phorvex.console.catalogueV1.litellm.enabled .Values.phorvex.console.catalogueV1.litellm.inferenceEnabled) }}
{{- fail "console.catalogueV1.mcpVoiceModel requires catalogueV1, Voice, MCP and LiteLLM inference enabled" }}
{{- end }}
{{- if ne .Values.phorvex.console.catalogueV1.litellm.modelAlias "gpt-4o-mini" }}
{{- fail "console.catalogueV1.mcpVoiceModel requires reviewed gpt-4o-mini alias" }}
{{- end }}
{{- if not (regexMatch "^[0-9a-f]{64}$" .Values.phorvex.console.catalogueV1.mcpVoiceModel.voiceSourceSHA256) }}
{{- fail "console.catalogueV1.mcpVoiceModel.voiceSourceSHA256 requires lowercase SHA-256" }}
{{- end }}
{{- end }}
{{- if .Values.phorvex.console.enabled }}
{{- if not .Values.phorvex.audit.enabled }}
{{- fail "console.enabled requires audit.enabled: separate console Pod cannot serve live history without authenticated manager audit source" }}
{{- end }}
{{- if not .Values.phorvex.console.auditTransport.serverDNSName }}
{{- fail "console.auditTransport.serverDNSName required" }}
{{- end }}
{{- if and (not .Values.phorvex.console.state.persistence.enabled) (not .Values.phorvex.console.state.allowEphemeral) }}
{{- fail "console state persistence is required; set console.state.allowEphemeral=true explicitly for nondurable development use" }}
{{- end }}
{{- with .Values.phorvex.console.catalogueV1 }}
{{- with .litellm }}
{{- if .inferenceEnabled }}
{{- if not (and $.Values.phorvex.console.catalogueV1.enabled .enabled) }}
{{- fail "console.catalogueV1.litellm.inferenceEnabled requires catalogueV1 and litellm enabled" }}
{{- end }}
{{- $alias := required "console.catalogueV1.litellm.modelAlias is required for inference" .modelAlias }}
{{- if not (regexMatch "^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$" $alias) }}
{{- fail "console.catalogueV1.litellm.modelAlias must be a reviewed model alias" }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- if .Values.phorvex.console.podBoundToken.enabled }}
{{- $sourceName := required "console.podBoundToken.configMapName is required" .Values.phorvex.console.podBoundToken.configMapName }}
{{- if or (gt (len $sourceName) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$" $sourceName)) }}
{{- fail "console.podBoundToken.configMapName must be a DNS subdomain name" }}
{{- end }}
{{- $profileSHA := required "console.podBoundToken.profileSHA256 is required" .Values.phorvex.console.podBoundToken.profileSHA256 }}
{{- if not (regexMatch "^[0-9a-f]{64}$" $profileSHA) }}
{{- fail "console.podBoundToken.profileSHA256 must be 64 lowercase hex characters" }}
{{- end }}
{{- end }}
{{- if .Values.phorvex.console.podBoundTokenCPU.enabled }}
{{- $sourceName := required "console.podBoundTokenCPU.configMapName is required" .Values.phorvex.console.podBoundTokenCPU.configMapName }}
{{- if or (gt (len $sourceName) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$" $sourceName)) }}
{{- fail "console.podBoundTokenCPU.configMapName must be a DNS subdomain name" }}
{{- end }}
{{- $profileSHA := required "console.podBoundTokenCPU.profileSHA256 is required" .Values.phorvex.console.podBoundTokenCPU.profileSHA256 }}
{{- if not (regexMatch "^[0-9a-f]{64}$" $profileSHA) }}
{{- fail "console.podBoundTokenCPU.profileSHA256 must be 64 lowercase hex characters" }}
{{- end }}
{{- end }}
{{- if .Values.phorvex.console.mongoExposure.enabled }}
{{- $name := required "console.mongoExposure.configMapName is required" .Values.phorvex.console.mongoExposure.configMapName }}
{{- if or (gt (len $name) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" $name)) }}
{{- fail "console.mongoExposure.configMapName must be a DNS subdomain name" }}
{{- end }}
{{- range (splitList "." $name) }}{{- if gt (len .) 63 }}{{- fail "console.mongoExposure.configMapName DNS label exceeds 63 characters" }}{{- end }}{{- end }}
{{- $sha := required "console.mongoExposure.profileSHA256 is required" .Values.phorvex.console.mongoExposure.profileSHA256 }}
{{- if not (regexMatch "^[0-9a-f]{64}$" $sha) }}{{- fail "console.mongoExposure.profileSHA256 must be 64 lowercase hex characters" }}{{- end }}
{{- end }}
{{- if .Values.phorvex.console.natsExposure.enabled }}
{{- $name := required "console.natsExposure.configMapName is required" .Values.phorvex.console.natsExposure.configMapName }}
{{- if or (gt (len $name) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" $name)) }}{{- fail "console.natsExposure.configMapName must be a DNS subdomain name" }}{{- end }}
{{- range (splitList "." $name) }}{{- if gt (len .) 63 }}{{- fail "console.natsExposure.configMapName DNS label exceeds 63 characters" }}{{- end }}{{- end }}
{{- $sha := required "console.natsExposure.profileSHA256 is required" .Values.phorvex.console.natsExposure.profileSHA256 }}
{{- if not (regexMatch "^[0-9a-f]{64}$" $sha) }}{{- fail "console.natsExposure.profileSHA256 must be 64 lowercase hex characters" }}{{- end }}
{{- end }}
{{- if .Values.phorvex.console.natsExposure.clientResponse.enabled }}
{{- if not .Values.phorvex.console.natsExposure.enabled }}{{- fail "console.natsExposure.clientResponse.enabled requires console.natsExposure.enabled" }}{{- end }}
{{- $name := required "console.natsExposure.clientResponse.configMapName is required" .Values.phorvex.console.natsExposure.clientResponse.configMapName }}
{{- if or (gt (len $name) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" $name)) }}{{- fail "console.natsExposure.clientResponse.configMapName must be a DNS subdomain name" }}{{- end }}
{{- range (splitList "." $name) }}{{- if gt (len .) 63 }}{{- fail "console.natsExposure.clientResponse.configMapName DNS label exceeds 63 characters" }}{{- end }}{{- end }}
{{- $sha := required "console.natsExposure.clientResponse.profileSHA256 is required" .Values.phorvex.console.natsExposure.clientResponse.profileSHA256 }}
{{- if not (regexMatch "^[0-9a-f]{64}$" $sha) }}{{- fail "console.natsExposure.clientResponse.profileSHA256 must be 64 lowercase hex characters" }}{{- end }}
{{- end }}
{{- if .Values.phorvex.console.guardrailStatic.enabled }}
{{- $name := required "console.guardrailStatic.configMapName is required" .Values.phorvex.console.guardrailStatic.configMapName }}
{{- if or (gt (len $name) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" $name)) }}
{{- fail "console.guardrailStatic.configMapName must be a DNS subdomain name" }}
{{- end }}
{{- range (splitList "." $name) }}{{- if gt (len .) 63 }}{{- fail "console.guardrailStatic.configMapName DNS label exceeds 63 characters" }}{{- end }}{{- end }}
{{- $sha := required "console.guardrailStatic.profileSHA256 is required" .Values.phorvex.console.guardrailStatic.profileSHA256 }}
{{- if not (regexMatch "^[0-9a-f]{64}$" $sha) }}{{- fail "console.guardrailStatic.profileSHA256 must be 64 lowercase hex characters" }}{{- end }}
{{- end }}
{{- if .Values.phorvex.console.guardrailAvailability.enabled }}
{{- if not .Values.phorvex.console.catalogueV1.enabled }}{{- fail "console.guardrailAvailability.enabled requires catalogueV1.enabled" }}{{- end }}
{{- if not .Values.phorvex.console.catalogueV1.scopedToken.existingSecret }}{{- fail "console.guardrailAvailability.enabled requires catalogueV1.scopedToken.existingSecret" }}{{- end }}
{{- if ne .Values.phorvex.console.catalogueV1.scopedToken.key "token" }}{{- fail "console.guardrailAvailability requires scopedToken key token" }}{{- end }}
{{- if ne .Values.phorvex.console.catalogueV1.scopedToken.mountPath "/etc/phorvex-catalogue-v1" }}{{- fail "console.guardrailAvailability requires fixed scopedToken mountPath" }}{{- end }}
{{- if ne .Values.phorvex.console.catalogueV1.loopbackURL "http://127.0.0.1:8090" }}{{- fail "console.guardrailAvailability requires fixed catalogue loopbackURL" }}{{- end }}
{{- if ne (int .Values.phorvex.console.auditTransport.port) 8445 }}{{- fail "console.guardrailAvailability requires auditTransport port 8445" }}{{- end }}
{{- $auditHost := printf "%s-audit-source.%s.svc" (include "phorvex.fullname" .) .Release.Namespace }}
{{- if ne .Values.phorvex.console.auditTransport.serverDNSName $auditHost }}{{- fail "console.guardrailAvailability requires the release audit source DNS" }}{{- end }}
{{- $name := required "console.guardrailAvailability.configMapName is required" .Values.phorvex.console.guardrailAvailability.configMapName }}
{{- if or (gt (len $name) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" $name)) }}{{- fail "console.guardrailAvailability.configMapName must be a DNS subdomain name" }}{{- end }}
{{- range (splitList "." $name) }}{{- if gt (len .) 63 }}{{- fail "console.guardrailAvailability.configMapName DNS label exceeds 63 characters" }}{{- end }}{{- end }}
{{- $sha := required "console.guardrailAvailability.profileSHA256 is required" .Values.phorvex.console.guardrailAvailability.profileSHA256 }}
{{- if not (regexMatch "^[0-9a-f]{64}$" $sha) }}{{- fail "console.guardrailAvailability.profileSHA256 must be 64 lowercase hex characters" }}{{- end }}
{{- if ne .Values.phorvex.console.guardrailAvailability.sourceConfigMap "guardrail-proxy" }}{{- fail "console.guardrailAvailability.sourceConfigMap must be guardrail-proxy" }}{{- end }}
{{- $journal := required "console.guardrailAvailability.guardrailJournalName is required" .Values.phorvex.console.guardrailAvailability.guardrailJournalName }}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $journal) }}{{- fail "console.guardrailAvailability.guardrailJournalName must be a DNS label" }}{{- end }}
{{- end }}
{{- if .Values.phorvex.console.guardrailEffect.enabled }}
{{- if not .Values.phorvex.console.catalogueV1.enabled }}{{- fail "console.guardrailEffect.enabled requires catalogueV1.enabled" }}{{- end }}
{{- if not .Values.phorvex.console.catalogueV1.scopedToken.existingSecret }}{{- fail "console.guardrailEffect.enabled requires catalogueV1.scopedToken.existingSecret" }}{{- end }}
{{- if ne .Values.phorvex.console.catalogueV1.scopedToken.key "token" }}{{- fail "console.guardrailEffect requires scopedToken key token" }}{{- end }}
{{- if ne .Values.phorvex.console.catalogueV1.scopedToken.mountPath "/etc/phorvex-catalogue-v1" }}{{- fail "console.guardrailEffect requires fixed scopedToken mountPath" }}{{- end }}
{{- if ne .Values.phorvex.console.catalogueV1.loopbackURL "http://127.0.0.1:8090" }}{{- fail "console.guardrailEffect requires fixed catalogue loopbackURL" }}{{- end }}
{{- if ne (int .Values.phorvex.console.auditTransport.port) 8445 }}{{- fail "console.guardrailEffect requires auditTransport port 8445" }}{{- end }}
{{- $auditHost := printf "%s-audit-source.%s.svc" (include "phorvex.fullname" .) .Release.Namespace }}
{{- if ne .Values.phorvex.console.auditTransport.serverDNSName $auditHost }}{{- fail "console.guardrailEffect requires the release audit source DNS" }}{{- end }}
{{- $name := required "console.guardrailEffect.configMapName is required" .Values.phorvex.console.guardrailEffect.configMapName }}
{{- if or (gt (len $name) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" $name)) }}{{- fail "console.guardrailEffect.configMapName must be a DNS subdomain name" }}{{- end }}
{{- range (splitList "." $name) }}{{- if gt (len .) 63 }}{{- fail "console.guardrailEffect.configMapName DNS label exceeds 63 characters" }}{{- end }}{{- end }}
{{- $sha := required "console.guardrailEffect.profileSHA256 is required" .Values.phorvex.console.guardrailEffect.profileSHA256 }}
{{- if not (regexMatch "^[0-9a-f]{64}$" $sha) }}{{- fail "console.guardrailEffect.profileSHA256 must be 64 lowercase hex characters" }}{{- end }}
{{- if ne .Values.phorvex.console.guardrailEffect.sourceConfigMap "guardrail-proxy" }}{{- fail "console.guardrailEffect.sourceConfigMap must be guardrail-proxy" }}{{- end }}
{{- $journal := required "console.guardrailEffect.guardrailJournalName is required" .Values.phorvex.console.guardrailEffect.guardrailJournalName }}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $journal) }}{{- fail "console.guardrailEffect.guardrailJournalName must be a DNS label" }}{{- end }}
{{- end }}
{{- if .Values.phorvex.console.guardrailOutput.enabled }}
{{- if not .Values.phorvex.console.catalogueV1.enabled }}{{- fail "console.guardrailOutput.enabled requires catalogueV1.enabled" }}{{- end }}
{{- if not .Values.phorvex.console.catalogueV1.scopedToken.existingSecret }}{{- fail "console.guardrailOutput.enabled requires catalogueV1.scopedToken.existingSecret" }}{{- end }}
{{- $consoleSA := $injector }}
{{- $shortCreator := printf "%s/%s" .Release.Namespace $consoleSA }}
{{- $colonCreator := printf "%s:%s" .Release.Namespace $consoleSA }}
{{- $fullCreator := printf "system:serviceaccount:%s:%s" .Release.Namespace $consoleSA }}
{{- $creatorTrusted := false }}
{{- range .Values.phorvex.trustedDetectors }}
{{- range splitList "," . }}
{{- $entry := trim . }}
{{- if or (eq $entry $shortCreator) (eq $entry $colonCreator) (eq $entry $fullCreator) }}{{- $creatorTrusted = true }}{{- end }}
{{- end }}
{{- end }}
{{- if not $creatorTrusted }}{{- fail (printf "console.guardrailOutput.enabled requires exact console creator %s in phorvex.trustedDetectors" $shortCreator) }}{{- end }}
{{- $name := required "console.guardrailOutput.configMapName is required" .Values.phorvex.console.guardrailOutput.configMapName }}
{{- if or (gt (len $name) 253) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?([.][a-z0-9]([-a-z0-9]*[a-z0-9])?)*$" $name)) }}{{- fail "console.guardrailOutput.configMapName must be a DNS subdomain" }}{{- end }}
{{- $sha := required "console.guardrailOutput.profileSHA256 is required" .Values.phorvex.console.guardrailOutput.profileSHA256 }}
{{- if not (regexMatch "^[0-9a-f]{64}$" $sha) }}{{- fail "console.guardrailOutput.profileSHA256 must be lowercase SHA256" }}{{- end }}
{{- if ne .Values.phorvex.console.guardrailOutput.sourceConfigMap "guardrail-output-fixture" }}{{- fail "console.guardrailOutput.sourceConfigMap must be guardrail-output-fixture" }}{{- end }}
{{- if ne .Values.phorvex.console.guardrailOutput.targetNamespace "vllm" }}{{- fail "console.guardrailOutput.targetNamespace must be vllm" }}{{- end }}
{{- $cm := required "console.guardrailOutput.outputPolicyConfigMapName is required" .Values.phorvex.console.guardrailOutput.outputPolicyConfigMapName }}
{{- if not (regexMatch "^phorvex-output-policy-[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $cm) }}{{- fail "console.guardrailOutput.outputPolicyConfigMapName is invalid" }}{{- end }}
{{- $journal := required "console.guardrailOutput.outputPolicyJournalName is required" .Values.phorvex.console.guardrailOutput.outputPolicyJournalName }}
{{- if not (regexMatch "^phorvex-output-[0-9a-f]{32}$" $journal) }}{{- fail "console.guardrailOutput.outputPolicyJournalName is invalid" }}{{- end }}
{{- end }}
{{- if and .Values.phorvex.console.litellmOutput.enabled (not .Values.phorvex.console.litellmLive.enabled) }}{{- fail "console.litellmOutput requires litellmLive" }}{{- end }}
{{- if .Values.phorvex.console.drainLive.enabled }}
{{- if not .Values.phorvex.console.catalogueV1.enabled }}{{- fail "console.drainLive.enabled requires catalogueV1.enabled" }}{{- end }}
{{- if not .Values.phorvex.console.catalogueV1.scopedToken.existingSecret }}{{- fail "console.drainLive.enabled requires scopedToken.existingSecret" }}{{- end }}
{{- $name := required "console.drainLive.configMapName is required" .Values.phorvex.console.drainLive.configMapName }}
{{- if not (regexMatch "^phorvex-catalogue-drain-live-[0-9a-f]{12}$" $name) }}{{- fail "console.drainLive.configMapName must be digest-named" }}{{- end }}
{{- $sha := required "console.drainLive.profileSHA256 is required" .Values.phorvex.console.drainLive.profileSHA256 }}
{{- if not (regexMatch "^[0-9a-f]{64}$" $sha) }}{{- fail "console.drainLive.profileSHA256 must be SHA-256" }}{{- end }}
{{- if ne $name (printf "phorvex-catalogue-drain-live-%s" (trunc 12 $sha)) }}{{- fail "console.drainLive profile name/hash mismatch" }}{{- end }}
{{- if not (regexMatch "^phorvex-operation-[0-9a-f]{40}$" .Values.phorvex.console.drainLive.journalName) }}{{- fail "console.drainLive.journalName must be exact protected journal" }}{{- end }}
{{- end }}
{{- if .Values.phorvex.console.endpointLease.enabled }}
{{- if or (ne .Release.Namespace "phorvex-system") (ne (default .Release.Namespace .Values.phorvex.operatorNamespace) "phorvex-system") }}{{- fail "console.endpointLease requires phorvex-system" }}{{- end }}
{{- if not .Values.phorvex.endpointLease.enabled }}{{- fail "console.endpointLease requires native endpointLease.enabled" }}{{- end }}
{{- $creator := printf "system:serviceaccount:%s:%s" .Release.Namespace $injector }}
{{- if ne $creator "system:serviceaccount:phorvex-system:phorvex-phorvex-console" }}{{- fail "console.endpointLease requires reviewed console creator" }}{{- end }}
{{- $trusted := false }}
{{- range .Values.phorvex.trustedDetectors }}{{- range splitList "," . }}{{- if eq (trim .) $creator }}{{- $trusted = true }}{{- end }}{{- end }}{{- end }}
{{- if not $trusted }}{{- fail "console.endpointLease requires exact trusted creator" }}{{- end }}
{{- $name := required "console.endpointLease.configMapName required" .Values.phorvex.console.endpointLease.configMapName }}
{{- $sha := required "console.endpointLease.profileSHA256 required" .Values.phorvex.console.endpointLease.profileSHA256 }}
{{- if or (not (regexMatch "^[0-9a-f]{64}$" $sha)) (ne $name (printf "phorvex-catalogue-endpoint-lease-%s" (trunc 12 $sha))) }}{{- fail "console.endpointLease profile name/hash mismatch" }}{{- end }}
{{- if ne .Values.phorvex.console.endpointLease.callerSecretName "vllm-endpoint-lease-callers" }}{{- fail "console.endpointLease requires exact owner-provisioned caller Secret" }}{{- end }}
{{- $source := required "console.endpointLease.sourceConfigMapName required" .Values.phorvex.console.endpointLease.sourceConfigMapName }}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $source) }}{{- fail "console.endpointLease source ConfigMap name invalid" }}{{- end }}
{{- end }}
{{- if .Values.phorvex.console.litellmLive.enabled }}
{{- if ne (default .Release.Namespace .Values.phorvex.operatorNamespace) "phorvex-system" }}{{- fail "console.litellmLive requires phorvex-system effective operator namespace for protected journals" }}{{- end }}
{{- if not .Values.phorvex.console.catalogueV1.enabled }}{{- fail "console.litellmLive.enabled requires catalogueV1.enabled" }}{{- end }}
{{- if ne .Release.Namespace "phorvex-system" }}{{- fail "console.litellmLive requires phorvex-system release namespace" }}{{- end }}
{{- $creator := printf "system:serviceaccount:%s:%s" .Release.Namespace $injector }}
{{- $trusted := false }}
{{- range .Values.phorvex.trustedDetectors }}{{- range splitList "," . }}
{{- if eq (trim .) $creator }}{{- $trusted = true }}{{- end }}
{{- end }}{{- end }}
{{- if not $trusted }}{{- fail "console.litellmLive requires the exact console creator in trustedDetectors" }}{{- end }}
{{- $sha := required "console.litellmLive.profileSHA256 required" .Values.phorvex.console.litellmLive.profileSHA256 }}
{{- if not (regexMatch "^[0-9a-f]{64}$" $sha) }}{{- fail "console.litellmLive.profileSHA256 must be lowercase SHA256" }}{{- end }}
{{- range list "configMapName" "seedSecret" "statusSecret" }}
{{- $name := required (printf "console.litellmLive.%s required" .) (index $.Values.phorvex.console.litellmLive .) }}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $name) }}{{- fail (printf "console.litellmLive.%s invalid" .) }}{{- end }}
{{- end }}
{{- if .Values.phorvex.console.litellmOutput.enabled }}
{{- if not .Values.phorvex.litellmOutput.enabled }}{{- fail "console.litellmOutput requires native litellmOutput.enabled" }}{{- end }}
{{- if not .Values.phorvex.console.litellmLive.enabled }}{{- fail "console.litellmOutput requires litellmLive" }}{{- end }}
{{- $sha := required "console.litellmOutput.profileSHA256 required" .Values.phorvex.console.litellmOutput.profileSHA256 }}
{{- if not (regexMatch "^[0-9a-f]{64}$" $sha) }}{{- fail "console.litellmOutput.profileSHA256 must be lowercase SHA256" }}{{- end }}
{{- $name := required "console.litellmOutput.configMapName required" .Values.phorvex.console.litellmOutput.configMapName }}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $name) }}{{- fail "console.litellmOutput.configMapName invalid" }}{{- end }}
{{- if ne .Values.phorvex.console.litellmOutput.documentSeedSecret "phorvex-litellm-output-document" }}{{- fail "console.litellmOutput.documentSeedSecret invalid" }}{{- end }}
{{- if ne .Values.phorvex.console.litellmOutput.promptSeedSecret "phorvex-litellm-output-prompt" }}{{- fail "console.litellmOutput.promptSeedSecret invalid" }}{{- end }}
{{- end }}
{{- if ne .Values.phorvex.console.litellmLive.journalName "phorvex-litellm-revoke-journal" }}{{- fail "console.litellmLive.journalName invalid" }}{{- end }}
{{- $sourceName := .Values.phorvex.console.litellmLive.sourceConfigMapName }}
{{- if and (ne $sourceName "phorvex-litellm-admission-gateway") (not (regexMatch "^phorvex-litellm-admission-gateway-[0-9a-f]{12}$" $sourceName)) }}{{- fail "console.litellmLive.sourceConfigMapName invalid" }}{{- end }}
{{- end }}
{{- if .Values.phorvex.console.voiceAgencyLive.enabled }}
{{- if or (ne .Release.Namespace "phorvex-system") (ne (default .Release.Namespace .Values.phorvex.operatorNamespace) "phorvex-system") }}{{- fail "console.voiceAgencyLive requires phorvex-system release and effective operator namespaces" }}{{- end }}
{{- if not .Values.phorvex.voiceRefund.enabled }}{{- fail "console.voiceAgencyLive requires voiceRefund.enabled" }}{{- end }}
{{- $creator := printf "system:serviceaccount:%s:%s" .Release.Namespace $injector }}
{{- if ne $creator "system:serviceaccount:phorvex-system:phorvex-phorvex-console" }}{{- fail "console.voiceAgencyLive requires the profile-bound console service account" }}{{- end }}
{{- $trusted := false }}
{{- range .Values.phorvex.trustedDetectors }}{{- range splitList "," . }}
{{- if eq (trim .) $creator }}{{- $trusted = true }}{{- end }}
{{- end }}{{- end }}
{{- if not $trusted }}{{- fail "console.voiceAgencyLive requires exact console creator in trustedDetectors" }}{{- end }}
{{- $name := required "console.voiceAgencyLive.configMapName required" .Values.phorvex.console.voiceAgencyLive.configMapName }}
{{- if or (gt (len $name) 63) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $name)) }}{{- fail "console.voiceAgencyLive.configMapName invalid" }}{{- end }}
{{- $sha := required "console.voiceAgencyLive.profileSHA256 required" .Values.phorvex.console.voiceAgencyLive.profileSHA256 }}
{{- if not (regexMatch "^[0-9a-f]{64}$" $sha) }}{{- fail "console.voiceAgencyLive.profileSHA256 must be lowercase SHA256" }}{{- end }}
{{- $uid := required "console.voiceAgencyLive.deploymentUID required" .Values.phorvex.console.voiceAgencyLive.deploymentUID }}
{{- if not (regexMatch "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" $uid) }}{{- fail "console.voiceAgencyLive.deploymentUID must be lowercase UUID" }}{{- end }}
{{- end }}
{{- if .Values.phorvex.console.voiceOutputLive.enabled }}
{{- if ne .Release.Namespace "phorvex-system" }}{{- fail "console.voiceOutputLive requires phorvex-system release namespace" }}{{- end }}
{{- $creator := printf "system:serviceaccount:%s:%s" .Release.Namespace $injector }}
{{- if ne $creator "system:serviceaccount:phorvex-system:phorvex-phorvex-console" }}{{- fail "console.voiceOutputLive requires the profile-bound console service account" }}{{- end }}
{{- $trusted := false }}
{{- range .Values.phorvex.trustedDetectors }}{{- range splitList "," . }}
{{- if eq (trim .) $creator }}{{- $trusted = true }}{{- end }}
{{- end }}{{- end }}
{{- if not $trusted }}{{- fail "console.voiceOutputLive requires exact console creator in trustedDetectors" }}{{- end }}
{{- $name := required "console.voiceOutputLive.configMapName required" .Values.phorvex.console.voiceOutputLive.configMapName }}
{{- if or (gt (len $name) 63) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $name)) }}{{- fail "console.voiceOutputLive.configMapName invalid" }}{{- end }}
{{- $sha := required "console.voiceOutputLive.profileSHA256 required" .Values.phorvex.console.voiceOutputLive.profileSHA256 }}
{{- if not (regexMatch "^[0-9a-f]{64}$" $sha) }}{{- fail "console.voiceOutputLive.profileSHA256 must be lowercase SHA256" }}{{- end }}
{{- end }}
{{- if .Values.phorvex.console.voiceAdmissionLive.enabled }}
{{- if or (ne .Release.Namespace "phorvex-system") (ne (default .Release.Namespace .Values.phorvex.operatorNamespace) "phorvex-system") }}{{- fail "console.voiceAdmissionLive requires phorvex-system release and operator namespaces" }}{{- end }}
{{- if not .Values.phorvex.voiceAdmission.enabled }}{{- fail "console.voiceAdmissionLive requires native voiceAdmission.enabled" }}{{- end }}
{{- $creator := printf "system:serviceaccount:%s:%s" .Release.Namespace $injector }}
{{- if ne $creator "system:serviceaccount:phorvex-system:phorvex-phorvex-console" }}{{- fail "console.voiceAdmissionLive requires profile-bound console service account" }}{{- end }}
{{- $trusted := false }}
{{- range .Values.phorvex.trustedDetectors }}{{- range splitList "," . }}{{- if eq (trim .) $creator }}{{- $trusted = true }}{{- end }}{{- end }}{{- end }}
{{- if not $trusted }}{{- fail "console.voiceAdmissionLive requires exact console creator in trustedDetectors" }}{{- end }}
{{- range list "configMapName" "sourceConfigMapName" "legacyConfigMapName" }}
{{- $name := required (printf "console.voiceAdmissionLive.%s required" .) (index $.Values.phorvex.console.voiceAdmissionLive .) }}
{{- if or (gt (len $name) 63) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $name)) }}{{- fail "console.voiceAdmissionLive ConfigMap name invalid" }}{{- end }}
{{- end }}
{{- if not (regexMatch "^[0-9a-f]{64}$" .Values.phorvex.console.voiceAdmissionLive.profileSHA256) }}{{- fail "console.voiceAdmissionLive.profileSHA256 must be lowercase SHA256" }}{{- end }}
{{- if or (ne .Values.phorvex.console.voiceAdmissionLive.sourceConfigMapName .Values.phorvex.voiceAdmission.sourceConfigMapName) (ne .Values.phorvex.console.voiceAdmissionLive.legacyConfigMapName .Values.phorvex.voiceAdmission.legacyConfigMapName) }}{{- fail "Console/native admission source pins differ" }}{{- end }}
{{- end }}
{{- if .Values.phorvex.console.voiceMCPLive.enabled }}
{{- if or (ne .Release.Namespace "phorvex-system") (ne (default .Release.Namespace .Values.phorvex.operatorNamespace) "phorvex-system") }}{{- fail "console.voiceMCPLive requires phorvex-system release and effective operator namespaces" }}{{- end }}
{{- if not .Values.phorvex.voiceMCP.enabled }}{{- fail "console.voiceMCPLive requires native voiceMCP.enabled" }}{{- end }}
{{- $creator := printf "system:serviceaccount:%s:%s" .Release.Namespace $injector }}
{{- if ne $creator "system:serviceaccount:phorvex-system:phorvex-phorvex-console" }}{{- fail "console.voiceMCPLive requires profile-bound console service account" }}{{- end }}
{{- $trusted := false }}
{{- range .Values.phorvex.trustedDetectors }}{{- range splitList "," . }}
{{- if eq (trim .) $creator }}{{- $trusted = true }}{{- end }}
{{- end }}{{- end }}
{{- if not $trusted }}{{- fail "console.voiceMCPLive requires exact console creator in trustedDetectors" }}{{- end }}
{{- range list "configMapName" "sourceConfigMapName" "mcpSourceConfigMapName" }}
{{- $name := required (printf "console.voiceMCPLive.%s required" .) (index $.Values.phorvex.console.voiceMCPLive .) }}
{{- if or (gt (len $name) 63) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $name)) }}{{- fail (printf "console.voiceMCPLive.%s invalid" .) }}{{- end }}
{{- end }}
{{- $sha := required "console.voiceMCPLive.profileSHA256 required" .Values.phorvex.console.voiceMCPLive.profileSHA256 }}
{{- if not (regexMatch "^[0-9a-f]{64}$" $sha) }}{{- fail "console.voiceMCPLive.profileSHA256 must be lowercase SHA256" }}{{- end }}
{{- $uid := required "console.voiceMCPLive.deploymentUID required" .Values.phorvex.console.voiceMCPLive.deploymentUID }}
{{- if not (regexMatch "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" $uid) }}{{- fail "console.voiceMCPLive.deploymentUID must be lowercase UUID" }}{{- end }}
{{- end }}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ if $attacks }}{{ $podServiceAccount }}{{ else }}{{ include "phorvex.fullname" . }}-console{{ end }}
  namespace: {{ .Release.Namespace }}
  labels:
    {{- include "phorvex.labels" . | nindent 4 }}
    app.kubernetes.io/component: {{ if $attacks }}attacks{{ else }}console{{ end }}
spec:
  replicas: 1
  # Initial archive compression and byte-for-byte verification can exceed ten minutes.
  progressDeadlineSeconds: 3900
  # State ledgers use process-local serialization. Recreate prevents ordinary upgrades from
  # overlapping old and new console writers on the same claim.
  strategy:
    type: Recreate
    # Explicitly clear the old RollingUpdate fields during an in-place migration.
    rollingUpdate: null
  selector:
    matchLabels:
      app.kubernetes.io/name: {{ if $attacks }}phorvex-attacks{{ else }}phorvex-console{{ end }}
      app.kubernetes.io/instance: {{ .Release.Name }}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: {{ if $attacks }}phorvex-attacks{{ else }}phorvex-console{{ end }}
        app.kubernetes.io/instance: {{ .Release.Name }}
        app.kubernetes.io/component: {{ if $attacks }}attacks{{ else }}console{{ end }}
      {{- if and .Values.phorvex.console.auth.grants.enabled .Values.phorvex.console.auth.grants.create }}
      annotations:
        checksum/console-grants: {{ .Values.phorvex.console.auth.grants.data | default "{\n  \"version\": 1,\n  \"subjects\": []\n}\n" | sha256sum | quote }}
      {{- end }}
    spec:
      serviceAccountName: {{ $podServiceAccount }}
      securityContext:
        runAsNonRoot: true
        fsGroup: 65532
      {{- with .Values.phorvex.nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.phorvex.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      containers:
      {{- if $attacks }}
      - name: attacks
        {{- with .Values.image.digest }}{{ if not (regexMatch "^sha256:[0-9a-f]{64}$" .) }}{{ fail "image.digest must be sha256:<64 lowercase hex>" }}{{ end }}{{ end }}
        image: "{{ .Values.image.repository }}:{{ default .Chart.AppVersion .Values.image.tag }}{{ with .Values.image.digest }}@{{ . }}{{ end }}"
        imagePullPolicy: {{ .Values.image.pullPolicy }}
        args:
        - -root={{ .Values.phorvex.console.root }}
      {{- else }}
      - name: console
        {{- with .Values.phorvex.console.image.releaseDigest }}{{ if not (regexMatch "^sha256:[0-9a-f]{64}$" .) }}{{ fail "phorvex.console.image.releaseDigest must be sha256:<64 lowercase hex>" }}{{ end }}{{ end }}
        image: "{{ .Values.phorvex.console.image.repository }}:{{ .Values.phorvex.console.image.tag }}{{ with .Values.phorvex.console.image.releaseDigest }}@{{ . }}{{ end }}"
        imagePullPolicy: {{ .Values.phorvex.console.image.pullPolicy }}
        args:
        - -root={{ .Values.phorvex.console.root }}
        - -web={{ .Values.phorvex.console.web }}
      {{- end }}
        - -addr=:{{ .Values.phorvex.console.port }}
        - -state-dir={{ .Values.phorvex.console.state.mountPath }}
        {{- if .Values.phorvex.audit.enabled }}
        - -audit-source-url=https://{{ include "phorvex.fullname" . }}-audit-source.{{ .Release.Namespace }}.svc:{{ .Values.phorvex.console.auditTransport.port }}
        - -audit-source-server-dns={{ .Values.phorvex.console.auditTransport.serverDNSName }}
        - -audit-source-client-cert=/etc/audit-client/tls.crt
        - -audit-source-client-key=/etc/audit-client/tls.key
        - -audit-source-ca=/etc/audit-client/ca.crt
        {{- end }}
        {{- if .Values.phorvex.prometheusUrl }}
        # Let `phorvex --scan` (the console's Scan / Physics tab) reach the live DCGM/GPU feed.
        # The scan's SSRF guard only fetches a Prometheus whose host is allow-listed here, so
        # without this the URL is dropped and the GPU half of physics stays "unmeasured (no
        # GPU/DCGM scan)" even though dcgm-exporter is scraping. host[:port], scheme stripped.
        - -metrics-allow={{ .Values.phorvex.prometheusUrl | trimPrefix "https://" | trimPrefix "http://" }}
        {{- end }}
        {{- if .Values.phorvex.console.auth.grants.enabled }}
        # M-136: the DevOps-supplied subject grant table. Without it the console still starts and
        # still authenticates callers, but authorizes NOBODY — the fail-closed rollout state.
        - -auth-grants={{ .Values.phorvex.console.auth.grants.mountPath }}/{{ .Values.phorvex.console.auth.grants.fileName }}
        {{- end }}
        env:
        # Environment defaults keep chart-first rollouts compatible with older console images,
        # which ignore unknown environment variables. New binaries still allow explicit CLI
        # flags to override these defaults outside this chart.
        {{- with include "phorvex-common.injectorEnv" (dict "values" .Values.phorvex "releaseNamespace" .Release.Namespace "releaseName" .Release.Name "default" (ternary (printf "%s/%s" .Release.Namespace $podServiceAccount) "" $attacks)) }}
        {{- . | nindent 8 }}
        {{- end }}
        {{- if $remoteAttacks }}
        # The attack routes are the attacks service's (docs/services/attacks.md).
        - name: PHORVEX_CONSOLE_ATTACKS_URL
          value: {{ printf "http://%s" .Values.phorvex.services.attacks.endpoint | quote }}
        {{- end }}
        {{- with .Values.phorvex.console.attackNamespaces }}
        # Beside another environment, the red-team sweeper reaps only this one's events.
        - name: PHORVEX_CONSOLE_SWEEP_NAMESPACES
          value: {{ join "," . | quote }}
        {{- end }}
        - name: PHORVEX_CONSOLE_HISTORY_MAX_BYTES
          value: {{ .Values.phorvex.console.state.historyArchiveMaxBytes | quote }}
        - name: PHORVEX_CONSOLE_HISTORY_MIN_FREE_BYTES
          value: {{ .Values.phorvex.console.state.historyMinFreeBytes | quote }}
        - name: PHORVEX_CONSOLE_HISTORY_RETENTION_DAYS
          value: {{ .Values.phorvex.console.state.historyRetentionDays | default 0 | quote }}
        {{- if dig "attackCatalog" "enabled" false .Values.phorvex.console }}
        - name: PHORVEX_CONSOLE_ATTACK_CATALOG_AUTHORIZATION_TENANT
          value: {{ required "console.attackCatalog.authorizationTenant is required for console.attackCatalog" .Values.phorvex.console.attackCatalog.authorizationTenant | quote }}
        - name: PHORVEX_CONSOLE_ATTACK_CATALOG_IDENTITY_TENANT
          value: {{ required "identityRotate.targetNamespace is required for console.attackCatalog" .Values.phorvex.identityRotate.targetNamespace | quote }}
        {{- end }}
        {{- if and $attacks (dig "attackCatalog" "enabled" false .Values.phorvex.console) }}
        # Metadata is embedded in the image; this fixed root-owned profile enables only
        # AML.T0012 and cannot be replaced by a request body.
        - name: PHORVEX_CONSOLE_ATTACK_CATALOG_ENABLED
          value: "true"
        - name: PHORVEX_CONSOLE_ATTACK_CATALOG_IDENTITY_PROFILE
          value: /etc/phorvex-attack-catalog/identity-profile.json
        {{- else }}
        - name: PHORVEX_CONSOLE_ATTACK_CATALOG_ENABLED
          value: "false"
        {{- end }}
        # The opt-in Role alone is not readiness; the server also validates the
        # fixed baked config and current installed source before admission.
        - name: PHORVEX_CONSOLE_MONGO_EXPOSURE_ENABLED
          value: {{ .Values.phorvex.console.mongoExposure.enabled | default false | quote }}
        {{- if .Values.phorvex.console.mongoExposure.enabled }}
        - name: PHORVEX_CONSOLE_MONGO_EXPOSURE_PROFILE_SHA256
          value: {{ .Values.phorvex.console.mongoExposure.profileSHA256 | quote }}
        {{- end }}
        - name: PHORVEX_CONSOLE_NATS_EXPOSURE_ENABLED
          value: {{ .Values.phorvex.console.natsExposure.enabled | default false | quote }}
        {{- if .Values.phorvex.console.natsExposure.enabled }}
        - name: PHORVEX_CONSOLE_NATS_EXPOSURE_PROFILE_SHA256
          value: {{ .Values.phorvex.console.natsExposure.profileSHA256 | quote }}
        {{- end }}
        - name: PHORVEX_CONSOLE_NATS_CLIENT_RESPONSE_ENABLED
          value: {{ .Values.phorvex.console.natsExposure.clientResponse.enabled | default false | quote }}
        {{- if .Values.phorvex.console.natsExposure.clientResponse.enabled }}
        - name: PHORVEX_CONSOLE_NATS_CLIENT_RESPONSE_PROFILE_SHA256
          value: {{ .Values.phorvex.console.natsExposure.clientResponse.profileSHA256 | quote }}
        {{- end }}
        - name: PHORVEX_CONSOLE_GUARDRAIL_STATIC_ENABLED
          value: {{ .Values.phorvex.console.guardrailStatic.enabled | default false | quote }}
        {{- if .Values.phorvex.console.guardrailStatic.enabled }}
        - name: PHORVEX_CONSOLE_GUARDRAIL_STATIC_PROFILE_SHA256
          value: {{ .Values.phorvex.console.guardrailStatic.profileSHA256 | quote }}
        {{- end }}
        - name: PHORVEX_CONSOLE_GUARDRAIL_AVAILABILITY_ENABLED
          value: {{ .Values.phorvex.console.guardrailAvailability.enabled | default false | quote }}
        {{- if .Values.phorvex.console.guardrailAvailability.enabled }}
        - name: PHORVEX_CONSOLE_GUARDRAIL_AVAILABILITY_PROFILE_SHA256
          value: {{ .Values.phorvex.console.guardrailAvailability.profileSHA256 | quote }}
        {{- end }}
        - name: PHORVEX_CONSOLE_GUARDRAIL_EFFECT_ENABLED
          value: {{ .Values.phorvex.console.guardrailEffect.enabled | default false | quote }}
        {{- if .Values.phorvex.console.guardrailEffect.enabled }}
        - name: PHORVEX_CONSOLE_GUARDRAIL_EFFECT_PROFILE_SHA256
          value: {{ .Values.phorvex.console.guardrailEffect.profileSHA256 | quote }}
        {{- end }}
        - name: PHORVEX_CONSOLE_GUARDRAIL_OUTPUT_ENABLED
          value: {{ .Values.phorvex.console.guardrailOutput.enabled | default false | quote }}
        {{- if .Values.phorvex.console.guardrailOutput.enabled }}
        - name: PHORVEX_CONSOLE_GUARDRAIL_OUTPUT_PROFILE_SHA256
          value: {{ .Values.phorvex.console.guardrailOutput.profileSHA256 | quote }}
        {{- end }}
        - name: PHORVEX_CONSOLE_DRAIN_LIVE_ENABLED
          value: {{ .Values.phorvex.console.drainLive.enabled | default false | quote }}
        {{- if .Values.phorvex.console.drainLive.enabled }}
        - name: PHORVEX_CONSOLE_DRAIN_LIVE_PROFILE_SHA256
          value: {{ .Values.phorvex.console.drainLive.profileSHA256 | quote }}
        # V2 consumes independently published per-component authority. V1 ignores
        # these optional values and retains its original exact captured pins.
        - name: PHORVEX_CONSOLE_DRAIN_MANAGER_TEMPLATE_IMAGE
          value: {{ printf "%s:%s" .Values.phorvex.image.repository .Values.phorvex.image.tag | quote }}
        - name: PHORVEX_CONSOLE_DRAIN_MANAGER_IMAGE
          value: {{ if .Values.phorvex.image.releaseDigest }}{{ printf "%s@%s" .Values.phorvex.image.repository .Values.phorvex.image.releaseDigest | quote }}{{ else }}""{{ end }}
        - name: PHORVEX_CONSOLE_DRAIN_MANAGER_SOURCE_SHA
          value: {{ .Values.phorvex.image.releaseSourceSHA | quote }}
        - name: PHORVEX_CONSOLE_DRAIN_CONSOLE_TEMPLATE_IMAGE
          value: {{ printf "%s:%s" .Values.phorvex.console.image.repository .Values.phorvex.console.image.tag | quote }}
        - name: PHORVEX_CONSOLE_DRAIN_CONSOLE_IMAGE
          value: {{ if .Values.phorvex.console.image.releaseDigest }}{{ printf "%s@%s" .Values.phorvex.console.image.repository .Values.phorvex.console.image.releaseDigest | quote }}{{ else }}""{{ end }}
        - name: PHORVEX_CONSOLE_DRAIN_CONSOLE_SOURCE_SHA
          value: {{ .Values.phorvex.console.image.releaseSourceSHA | quote }}
        {{- end }}
        - name: PHORVEX_CONSOLE_ENDPOINT_LEASE_ENABLED
          value: {{ .Values.phorvex.console.endpointLease.enabled | default false | quote }}
        {{- if .Values.phorvex.console.endpointLease.enabled }}
        - name: PHORVEX_CONSOLE_ENDPOINT_LEASE_PROFILE_SHA256
          value: {{ .Values.phorvex.console.endpointLease.profileSHA256 | quote }}
        {{- end }}
        - name: PHORVEX_CONSOLE_LITELLM_LIVE_ENABLED
          value: {{ .Values.phorvex.console.litellmLive.enabled | default false | quote }}
        {{- with .Values.phorvex.console.liveAttackDisabled }}
        - name: PHORVEX_CONSOLE_LIVE_ATTACK_DISABLED
          value: {{ join "," . | quote }}
        {{- end }}
        {{- if .Values.phorvex.console.litellmLive.enabled }}
        - name: PHORVEX_CONSOLE_LITELLM_LIVE_PROFILE_SHA256
          value: {{ .Values.phorvex.console.litellmLive.profileSHA256 | quote }}
        {{- end }}
        - name: PHORVEX_CONSOLE_VOICE_AGENCY_LIVE_ENABLED
          value: {{ .Values.phorvex.console.voiceAgencyLive.enabled | default false | quote }}
        {{- if .Values.phorvex.console.voiceAgencyLive.enabled }}
        - name: PHORVEX_CONSOLE_VOICE_AGENCY_LIVE_PROFILE_SHA256
          value: {{ .Values.phorvex.console.voiceAgencyLive.profileSHA256 | quote }}
        {{- end }}
        - name: PHORVEX_CONSOLE_LITELLM_OUTPUT_ENABLED
          value: {{ .Values.phorvex.console.litellmOutput.enabled | default false | quote }}
        {{- if .Values.phorvex.console.litellmOutput.enabled }}
        - name: PHORVEX_CONSOLE_LITELLM_OUTPUT_PROFILE_SHA256
          value: {{ .Values.phorvex.console.litellmOutput.profileSHA256 | quote }}
        {{- end }}
        - name: PHORVEX_CONSOLE_VOICE_OUTPUT_LIVE_ENABLED
          value: {{ .Values.phorvex.console.voiceOutputLive.enabled | default false | quote }}
        {{- if .Values.phorvex.console.voiceOutputLive.enabled }}
        - name: PHORVEX_CONSOLE_VOICE_OUTPUT_LIVE_PROFILE_SHA256
          value: {{ .Values.phorvex.console.voiceOutputLive.profileSHA256 | quote }}
        {{- end }}
        - name: PHORVEX_CONSOLE_VOICE_ADMISSION_LIVE_ENABLED
          value: {{ .Values.phorvex.console.voiceAdmissionLive.enabled | default false | quote }}
        {{- if .Values.phorvex.console.voiceAdmissionLive.enabled }}
        - name: PHORVEX_CONSOLE_VOICE_ADMISSION_LIVE_PROFILE_SHA256
          value: {{ .Values.phorvex.console.voiceAdmissionLive.profileSHA256 | quote }}
        {{- end }}
        - name: PHORVEX_CONSOLE_VOICE_MCP_LIVE_ENABLED
          value: {{ .Values.phorvex.console.voiceMCPLive.enabled | default false | quote }}
        {{- if .Values.phorvex.console.voiceMCPLive.enabled }}
        - name: PHORVEX_CONSOLE_VOICE_MCP_LIVE_PROFILE_SHA256
          value: {{ .Values.phorvex.console.voiceMCPLive.profileSHA256 | quote }}
        {{- end }}
        - name: PHORVEX_CONSOLE_CRM_LIVE_ENABLED
          value: {{ .Values.phorvex.console.crmRefundLive.enabled | default false | quote }}
        {{- if or .Values.phorvex.console.guardrailAvailability.enabled .Values.phorvex.console.guardrailEffect.enabled .Values.phorvex.console.guardrailOutput.enabled .Values.phorvex.console.drainLive.enabled }}
        - name: PHORVEX_CONSOLE_POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: PHORVEX_CONSOLE_POD_UID
          valueFrom:
            fieldRef:
              fieldPath: metadata.uid
        {{- end }}
        - name: PHORVEX_CONSOLE_POD_BOUND_TOKEN_ENABLED
          value: {{ .Values.phorvex.console.podBoundToken.enabled | default false | quote }}
        {{- if .Values.phorvex.console.podBoundToken.enabled }}
        - name: PHORVEX_CONSOLE_POD_BOUND_TOKEN_PROFILE_SHA256
          value: {{ .Values.phorvex.console.podBoundToken.profileSHA256 | quote }}
        {{- end }}
        - name: PHORVEX_CONSOLE_POD_BOUND_TOKEN_CPU_ENABLED
          value: {{ .Values.phorvex.console.podBoundTokenCPU.enabled | default false | quote }}
        {{- if .Values.phorvex.console.podBoundTokenCPU.enabled }}
        - name: PHORVEX_CONSOLE_POD_BOUND_TOKEN_CPU_PROFILE_SHA256
          value: {{ .Values.phorvex.console.podBoundTokenCPU.profileSHA256 | quote }}
        {{- end }}
        {{- with .Values.phorvex.console.catalogueV1 }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_ENABLED
          value: {{ .enabled | default false | quote }}
        {{- if .enabled }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_LOOPBACK_URL
          value: {{ .loopbackURL | default "http://127.0.0.1:8090" | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_ALLOWED_TENANT
          value: {{ .allowedTenant | default "" | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_DENIED_TENANT
          value: {{ .deniedTenant | default "" | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_DENIED_TARGET
          value: {{ .deniedTarget | default "" | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_EXPECTED_SUBJECT
          value: {{ .expectedSubject | default "" | quote }}
        {{- if $.Values.phorvex.console.auth.grants.enabled }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_GRANT_FILE
          value: {{ printf "%s/%s" $.Values.phorvex.console.auth.grants.mountPath $.Values.phorvex.console.auth.grants.fileName | quote }}
        {{- end }}
        {{- with .scopedToken }}
        {{- if .existingSecret }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_TOKEN_FILE
          value: {{ printf "%s/%s" .mountPath .key | quote }}
        {{- end }}
        {{- end }}
        {{- with .voice }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_VOICE_ENABLED
          value: {{ .enabled | default false | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_VOICE_NAMESPACE
          value: {{ .namespace | default "" | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_VOICE_DEPLOYMENT
          value: {{ .deployment | default "" | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_VOICE_SERVICE
          value: {{ .service | default "" | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_VOICE_CONTAINER
          value: {{ .container | default "" | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_VOICE_PORT
          value: {{ .port | default 0 | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_VOICE_PDB
          value: {{ .pdb | default "" | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_TRANSCRIPT_SELECTOR
          value: {{ .transcriptSelector | default "" | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_TRANSCRIPT_CONTAINER
          value: {{ .transcriptContainer | default "" | quote }}
        {{- end }}
        {{- with .guardrailCalibration }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_CALIBRATION_ENABLED
          value: {{ .enabled | default false | quote }}
        {{- if .enabled }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_NAMESPACE
          value: {{ required "console.catalogueV1.guardrailCalibration.namespace is required" .namespace | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_SERVICE
          value: {{ required "console.catalogueV1.guardrailCalibration.service is required" .service | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_PORT
          value: {{ .port | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_CONTAINER
          value: {{ required "console.catalogueV1.guardrailCalibration.container is required" .container | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_SOURCE_CONFIGMAP
          value: {{ required "console.catalogueV1.guardrailCalibration.sourceConfigMap is required" .sourceConfigMap | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_SOURCE_KEY
          value: {{ required "console.catalogueV1.guardrailCalibration.sourceKey is required" .sourceKey | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_GUARDRAIL_SOURCE_SHA256
          value: {{ required "console.catalogueV1.guardrailCalibration.sourceSHA256 is required" .sourceSHA256 | quote }}
        {{- end }}
        {{- end }}
        {{- with .mcpVoiceModel }}
        - name: PHORVEX_CONSOLE_CATALOGUE_MCP_VOICE_MODEL_ENABLED
          value: {{ .enabled | default false | quote }}
        {{- if .enabled }}
        - name: PHORVEX_CONSOLE_CATALOGUE_MCP_VOICE_MODEL_VOICE_SOURCE_SHA256
          value: {{ .voiceSourceSHA256 | quote }}
        {{- end }}
        {{- end }}
        {{- with .mcpSession }}
        - name: PHORVEX_CONSOLE_CATALOGUE_MCP_ENABLED
          value: {{ .enabled | default false | quote }}
        {{- if .enabled }}
        - name: PHORVEX_CONSOLE_CATALOGUE_MCP_NAMESPACE
          value: {{ required "console.catalogueV1.mcpSession.namespace is required" .namespace | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_MCP_DEPLOYMENT
          value: {{ required "console.catalogueV1.mcpSession.deployment is required" .deployment | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_MCP_SERVICE
          value: {{ required "console.catalogueV1.mcpSession.service is required" .service | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_MCP_CONTAINER
          value: {{ required "console.catalogueV1.mcpSession.container is required" .container | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_MCP_PORT
          value: {{ .port | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_MCP_SOURCE_CONFIGMAP
          value: {{ required "console.catalogueV1.mcpSession.sourceConfigMap is required" .sourceConfigMap | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_MCP_SOURCE_KEY
          value: {{ required "console.catalogueV1.mcpSession.sourceKey is required" .sourceKey | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_MCP_IMAGE_ID
          value: {{ required "console.catalogueV1.mcpSession.imageID is required" .imageID | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_MCP_SOURCE_SHA256
          value: {{ required "console.catalogueV1.mcpSession.sourceSHA256 is required" .sourceSHA256 | quote }}
        {{- end }}
        {{- end }}
        {{- with .chroma }}
        - name: PHORVEX_CONSOLE_CATALOGUE_CHROMA_ENABLED
          value: {{ .enabled | default false | quote }}
        {{- if .enabled }}
        - name: PHORVEX_CONSOLE_CATALOGUE_CHROMA_NAMESPACE
          value: {{ required "console.catalogueV1.chroma.namespace is required" .namespace | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_CHROMA_DEPLOYMENT
          value: {{ required "console.catalogueV1.chroma.deployment is required" .deployment | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_CHROMA_SERVICE
          value: {{ required "console.catalogueV1.chroma.service is required" .service | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_CHROMA_CONTAINER
          value: {{ required "console.catalogueV1.chroma.container is required" .container | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_CHROMA_PORT
          value: {{ .port | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_CHROMA_IMAGE_ID
          value: {{ required "console.catalogueV1.chroma.imageID is required" .imageID | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_CHROMA_VERSION_SOURCE_SHA256
          value: {{ required "console.catalogueV1.chroma.versionSourceSHA256 is required" .versionSourceSHA256 | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_CHROMA_SERVER_SOURCE_SHA256
          value: {{ required "console.catalogueV1.chroma.serverSourceSHA256 is required" .serverSourceSHA256 | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_CHROMA_SCHEMA_SOURCE_SHA256
          value: {{ required "console.catalogueV1.chroma.schemaSourceSHA256 is required" .schemaSourceSHA256 | quote }}
        {{- end }}
        {{- end }}
        {{- with .litellm }}
        - name: PHORVEX_CONSOLE_CATALOGUE_LITELLM_ENABLED
          value: {{ .enabled | default false | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_LITELLM_INFERENCE_ENABLED
          value: {{ .inferenceEnabled | default false | quote }}
        {{- if .inferenceEnabled }}
        - name: PHORVEX_CONSOLE_CATALOGUE_LITELLM_MODEL_ALIAS
          value: {{ .modelAlias | quote }}
        {{- end }}
        {{- if .enabled }}
        - name: PHORVEX_CONSOLE_CATALOGUE_LITELLM_NAMESPACE
          value: {{ required "console.catalogueV1.litellm.namespace is required" .namespace | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_LITELLM_DEPLOYMENT
          value: {{ required "console.catalogueV1.litellm.deployment is required" .deployment | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_LITELLM_SERVICE
          value: {{ required "console.catalogueV1.litellm.service is required" .service | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_LITELLM_CONTAINER
          value: {{ required "console.catalogueV1.litellm.container is required" .container | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_LITELLM_PORT
          value: {{ .port | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_LITELLM_CONFIGMAP
          value: {{ required "console.catalogueV1.litellm.configMap is required" .configMap | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_LITELLM_CONFIG_KEY
          value: {{ required "console.catalogueV1.litellm.configKey is required" .configKey | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_LITELLM_CONFIG_SHA256
          value: {{ required "console.catalogueV1.litellm.configSHA256 is required" .configSHA256 | quote }}
        {{- end }}
        {{- end }}
        {{- with .gpu }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_GPU_ENABLED
          value: {{ .enabled | default false | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_GPU_NAMESPACE
          value: {{ .namespace | default "" | quote }}
        {{- if .fixtureConfigMap }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_GPU_CONFIG
          value: {{ printf "%s/%s" .mountPath .fixtureKey | quote }}
        {{- end }}
        {{- if .runtimeSecret }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_GPU_KUBECONFIG
          value: {{ printf "%s/%s" .runtimeMountPath .kubeconfigKey | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_V1_GPU_KUBE_CONTEXT
          value: {{ required "console.catalogueV1.gpu.kubeContext is required when runtimeSecret is set" .kubeContext | quote }}
        {{- end }}
        {{- end }}
        {{- with .crm }}
        - name: PHORVEX_CONSOLE_CATALOGUE_CRM_ENABLED
          value: {{ .enabled | default false | quote }}
        {{- if .enabled }}
        - name: PHORVEX_CONSOLE_CATALOGUE_CRM_NAMESPACE
          value: {{ required "console.catalogueV1.crm.namespace is required" .namespace | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_CRM_NAMESPACE_UID
          value: {{ required "console.catalogueV1.crm.namespaceUID is required" .namespaceUID | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_CRM_SERVICE_ACCOUNT
          value: {{ required "console.catalogueV1.crm.serviceAccountName is required" .serviceAccountName | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_CRM_MANIFEST_FILE
          value: {{ printf "%s/%s" .manifestMountPath .manifestKey | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_CRM_MANIFEST_SHA256
          value: {{ required "console.catalogueV1.crm.manifestSHA256 is required" .manifestSHA256 | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_CRM_HARNESS_SHA256
          value: {{ required "console.catalogueV1.crm.harnessSHA256 is required" .harnessSHA256 | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_CRM_KUBECONFIG
          value: {{ printf "%s/%s" .runtimeMountPath .kubeconfigKey | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_CRM_KUBECONFIG_SHA256
          value: {{ required "console.catalogueV1.crm.kubeconfigSHA256 is required" .kubeconfigSHA256 | quote }}
        - name: PHORVEX_CONSOLE_CATALOGUE_CRM_KUBE_CONTEXT
          value: {{ required "console.catalogueV1.crm.kubeContext is required" .kubeContext | quote }}
        {{- end }}
        {{- end }}
        {{- end }}
        {{- end }}
        {{- if .Values.phorvex.prometheusUrl }}
        # The scan reads PHORVEX_PROM_URL as its default Prometheus when a request carries no
        # ?prometheus-url (subsystems.go Scan), so the browser Physics tab measures GPU physics.
        - name: PHORVEX_PROM_URL
          value: {{ .Values.phorvex.prometheusUrl | quote }}
        {{- end }}
        # ── M-136 console identity ─────────────────────────────────────────────
        # The console refuses to start unless at least one credential path is configured. These
        # are CONFIGURATION IDENTIFIERS (a load-balancer ARN, a user-pool issuer, an app-client
        # id) — not secrets — and they are per-deployment: never reuse one environment's signer
        # in another, or that environment's ALB becomes a trusted issuer for this one.
        {{- with .Values.phorvex.console.auth.alb }}
        {{- if .signerArn }}
        - name: PHORVEX_CONSOLE_ALB_SIGNER_ARN
          value: {{ .signerArn | quote }}
        {{- if .additionalSignerArns }}
        - name: PHORVEX_CONSOLE_ALB_ADDITIONAL_SIGNER_ARNS
          value: {{ join "," .additionalSignerArns | quote }}
        {{- end }}
        - name: PHORVEX_CONSOLE_ALB_ISSUER
          value: {{ required "console.auth.alb.issuer is required when signerArn is set" .issuer | quote }}
        - name: PHORVEX_CONSOLE_ALB_CLIENT_ID
          value: {{ required "console.auth.alb.clientId is required when signerArn is set" .clientId | quote }}
        {{- if .region }}
        - name: PHORVEX_CONSOLE_ALB_REGION
          value: {{ .region | quote }}
        {{- end }}
        {{- end }}
        {{- end }}
        {{- with .Values.phorvex.console.auth.oidc }}
        {{- if .issuer }}
        - name: PHORVEX_CONSOLE_OIDC_ISSUER
          value: {{ .issuer | quote }}
        - name: PHORVEX_CONSOLE_OIDC_AUDIENCE
          value: {{ required "console.auth.oidc.audience is required when issuer is set" .audience | quote }}
        - name: PHORVEX_CONSOLE_OIDC_JWKS_URL
          value: {{ required "console.auth.oidc.jwksUrl is required when issuer is set" .jwksUrl | quote }}
        {{- if .algorithms }}
        - name: PHORVEX_CONSOLE_OIDC_ALGS
          value: {{ join "," .algorithms | quote }}
        {{- end }}
        {{- end }}
        {{- end }}
        {{- if .Values.phorvex.console.auth.trustedOrigins }}
        # The same-origin/CSRF boundary for browser-driven state changes. Exact origins only;
        # there is no wildcard, and an unlisted origin gets no CORS grant either.
        - name: PHORVEX_CONSOLE_TRUSTED_ORIGINS
          value: {{ join "," .Values.phorvex.console.auth.trustedOrigins | quote }}
        {{- end }}
        ports:
        - name: http
          containerPort: {{ .Values.phorvex.console.port }}
        # One-time bounded archive migration completes before HTTP starts.
        # Allow both passes over a multi-GiB archive on the existing small console Pod.
        startupProbe:
          httpGet: { path: /api/health, port: http }
          periodSeconds: 5
          failureThreshold: 720
        readinessProbe:
          httpGet: { path: {{ if $attacks }}/api/health{{ else }}/{{ end }}, port: http }
          initialDelaySeconds: 3
          periodSeconds: 10
        livenessProbe:
          httpGet: { path: {{ if $attacks }}/api/health{{ else }}/{{ end }}, port: http }
          initialDelaySeconds: 10
          periodSeconds: 20
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
        resources:
          {{- toYaml .Values.phorvex.console.resources | nindent 10 }}
        volumeMounts:
        {{- if .Values.phorvex.audit.enabled }}
        - name: audit-client
          mountPath: /etc/audit-client
          readOnly: true
        {{- end }}
        # workload_attack.go writes the SecurityEvent manifest with os.CreateTemp before
        # applying it. With readOnlyRootFilesystem that fails, so /tmp must be writable —
        # an emptyDir keeps the root filesystem read-only while allowing it.
        - name: console-tmp
          mountPath: /tmp
        - name: console-state
          mountPath: {{ .Values.phorvex.console.state.mountPath }}
        {{- if and $attacks (dig "attackCatalog" "enabled" false .Values.phorvex.console) }}
        - name: attack-catalog-identity-fixture
          mountPath: /etc/phorvex-attack-catalog/identity-profile.json
          subPath: profile.json
          readOnly: true
        {{- end }}
        {{- if .Values.phorvex.console.auth.grants.enabled }}
        - name: console-grants
          mountPath: {{ .Values.phorvex.console.auth.grants.mountPath }}
          readOnly: true
        {{- end }}
        {{- if .Values.phorvex.console.podBoundToken.enabled }}
        # SubPath presents regular files to the profile/manifest no-symlink gates.
        - name: pod-bound-token-reviewed-source
          mountPath: {{ printf "%s/build/test-harness/config.pod-bound-api-auth-response.yaml" (trimSuffix "/" .Values.phorvex.console.root) }}
          subPath: config.pod-bound-api-auth-response.yaml
          readOnly: true
        - name: pod-bound-token-reviewed-source
          mountPath: /etc/phorvex-catalogue-pod-bound-token/manifest.json
          subPath: manifest.json
          readOnly: true
        {{- end }}
        {{- if .Values.phorvex.console.podBoundTokenCPU.enabled }}
        - name: pod-bound-token-cpu-reviewed-source
          mountPath: {{ printf "%s/build/test-harness/config.pod-bound-api-auth-response-cpu.yaml" (trimSuffix "/" .Values.phorvex.console.root) }}
          subPath: config.pod-bound-api-auth-response-cpu.yaml
          readOnly: true
        - name: pod-bound-token-cpu-reviewed-source
          mountPath: /etc/phorvex-catalogue-pod-bound-token-cpu/manifest.json
          subPath: manifest.json
          readOnly: true
        {{- end }}
        {{- if .Values.phorvex.console.mongoExposure.enabled }}
        - name: mongo-exposure-reviewed-profile
          mountPath: {{ printf "%s/build/test-harness/config.mongo-exposure-baseline.yaml" (trimSuffix "/" .Values.phorvex.console.root) }}
          subPath: config.mongo-exposure-baseline.yaml
          readOnly: true
        {{- end }}
        {{- if .Values.phorvex.console.natsExposure.enabled }}
        - name: nats-exposure-reviewed-profile
          mountPath: {{ printf "%s/build/test-harness/config.nats-exposure-baseline.yaml" (trimSuffix "/" .Values.phorvex.console.root) }}
          subPath: config.nats-exposure-baseline.yaml
          readOnly: true
        {{- end }}
        {{- if .Values.phorvex.console.natsExposure.clientResponse.enabled }}
        - name: nats-client-response-reviewed-profile
          mountPath: {{ printf "%s/build/test-harness/config.nats-client-response.yaml" (trimSuffix "/" .Values.phorvex.console.root) }}
          subPath: config.nats-client-response.yaml
          readOnly: true
        {{- end }}
        {{- if .Values.phorvex.console.guardrailStatic.enabled }}
        - name: guardrail-static-reviewed-profile
          mountPath: {{ printf "%s/build/test-harness/config.guardrail-confidentiality-static.yaml" (trimSuffix "/" .Values.phorvex.console.root) }}
          subPath: config.guardrail-confidentiality-static.yaml
          readOnly: true
        {{- end }}
        {{- if .Values.phorvex.console.guardrailAvailability.enabled }}
        - name: guardrail-availability-reviewed-profile
          mountPath: {{ printf "%s/build/test-harness/config.guardrail-availability-recovery.yaml" (trimSuffix "/" .Values.phorvex.console.root) }}
          subPath: config.guardrail-availability-recovery.yaml
          readOnly: true
        {{- end }}
        {{- if .Values.phorvex.console.guardrailEffect.enabled }}
        - name: guardrail-effect-reviewed-profile
          mountPath: /etc/phorvex-guardrail-effect/config.guardrail-effect.yaml
          subPath: config.guardrail-effect.yaml
          readOnly: true
        {{- end }}
        {{- if .Values.phorvex.console.guardrailOutput.enabled }}
        - name: guardrail-output-reviewed-profile
          mountPath: /etc/phorvex-guardrail-output/config.guardrail-output-response.yaml
          subPath: config.guardrail-output-response.yaml
          readOnly: true
        {{- end }}
        {{- if .Values.phorvex.console.drainLive.enabled }}
        - name: drain-live-reviewed-profile
          mountPath: /etc/phorvex-drain-live/profile.json
          subPath: profile.json
          readOnly: true
        {{- end }}
        {{- if .Values.phorvex.console.endpointLease.enabled }}
        - name: endpoint-lease-reviewed-profile
          mountPath: /etc/phorvex-endpoint-lease/profile.json
          subPath: profile.json
          readOnly: true
        - name: endpoint-lease-owned-callers
          mountPath: /etc/phorvex-endpoint-lease-callers
          readOnly: true
        {{- end }}
        {{- if .Values.phorvex.console.litellmLive.enabled }}
        # Single-file subPath mounts, like every other reviewed profile: the console opens the
        # profile with O_NOFOLLOW, and a directory mount of a projected volume exposes each key
        # as a symlink into ..data, which that open refuses (LiteLLM Live then never arms).
        - name: litellm-live-reviewed-inputs
          mountPath: /etc/phorvex-litellm-live/profile.json
          subPath: profile.json
          readOnly: true
        - name: litellm-live-reviewed-inputs
          mountPath: /etc/phorvex-litellm-live/seed
          subPath: seed
          readOnly: true
        - name: litellm-live-status-token
          mountPath: /etc/phorvex-litellm-status
          readOnly: true
        {{- end }}
        {{- if .Values.phorvex.console.voiceAgencyLive.enabled }}
        - name: voice-agency-reviewed-profile
          mountPath: /etc/phorvex-voice-agency/profile.json
          subPath: profile.json
          readOnly: true
        {{- end }}
        {{- if .Values.phorvex.console.litellmOutput.enabled }}
        - name: litellm-output-reviewed-inputs
          mountPath: /etc/phorvex-litellm-output
          readOnly: true
        {{- end }}
        {{- if .Values.phorvex.console.voiceOutputLive.enabled }}
        - name: voice-output-reviewed-profile
          mountPath: /etc/phorvex-voice-output/profile.json
          subPath: profile.json
          readOnly: true
        {{- end }}
        {{- if .Values.phorvex.console.voiceAdmissionLive.enabled }}
        - name: voice-admission-reviewed-profile
          mountPath: /etc/phorvex-voice-admission/profile.json
          subPath: profile.json
          readOnly: true
        {{- end }}
        {{- if .Values.phorvex.console.voiceMCPLive.enabled }}
        - name: voice-mcp-reviewed-profile
          mountPath: /etc/phorvex-voice-mcp/profile.json
          subPath: profile.json
          readOnly: true
        {{- end }}
        {{- with .Values.phorvex.console.catalogueV1 }}
        {{- if .enabled }}
        {{- with .scopedToken }}
        {{- if .existingSecret }}
        - name: catalogue-v1-token
          mountPath: {{ .mountPath }}
          readOnly: true
        {{- end }}
        {{- end }}
        {{- with .gpu }}
        {{- if .fixtureConfigMap }}
        - name: catalogue-v1-gpu
          mountPath: {{ .mountPath }}
          readOnly: true
        {{- end }}
        {{- if .runtimeSecret }}
        - name: catalogue-v1-gpu-runtime
          mountPath: {{ .runtimeMountPath }}
          readOnly: true
        {{- end }}
        {{- end }}
        {{- with .crm }}
        {{- if .enabled }}
        - name: catalogue-v1-crm-manifest
          mountPath: {{ .manifestMountPath }}
          readOnly: true
        - name: catalogue-v1-crm-runtime
          mountPath: {{ .runtimeMountPath }}
          readOnly: true
        {{- end }}
        {{- end }}
        {{- end }}
        {{- end }}
      volumes:
      - name: console-tmp
        emptyDir: {}
      - name: console-state
        {{- if .Values.phorvex.console.state.persistence.enabled }}
        persistentVolumeClaim:
          {{- if $attacks }}
          claimName: {{ printf "%s-state" $podServiceAccount }}
          {{- else }}
          claimName: {{ .Values.phorvex.console.state.persistence.existingClaim | default (printf "%s-console-state" (include "phorvex.fullname" .)) }}
          {{- end }}
        {{- else }}
        # Explicitly nondurable: all console mutation/experiment/uptime state is lost with the Pod.
        emptyDir: {}
        {{- end }}
      {{- if and $attacks (dig "attackCatalog" "enabled" false .Values.phorvex.console) }}
      - name: attack-catalog-identity-fixture
        configMap:
          name: {{ include "phorvex-common.attacksServiceAccountName" . }}-identity-fixture
          defaultMode: 0440
          items:
          - key: profile.json
            path: profile.json
      {{- end }}
      {{- if .Values.phorvex.audit.enabled }}
      - name: audit-client
        secret:
          secretName: {{ required "console.auditTransport.clientSecretName required" .Values.phorvex.console.auditTransport.clientSecretName }}
      {{- end }}
      {{- if .Values.phorvex.console.auth.grants.enabled }}
      - name: console-grants
        configMap:
          name: {{ include "phorvex-common.grantsConfigMapName" . }}
          defaultMode: 0440
      {{- end }}
      {{- if .Values.phorvex.console.podBoundToken.enabled }}
      - name: pod-bound-token-reviewed-source
        configMap:
          name: {{ .Values.phorvex.console.podBoundToken.configMapName | quote }}
          defaultMode: 0440
          items:
          - key: config.pod-bound-api-auth-response.yaml
            path: config.pod-bound-api-auth-response.yaml
          - key: manifest.json
            path: manifest.json
      {{- end }}
      {{- if .Values.phorvex.console.podBoundTokenCPU.enabled }}
      - name: pod-bound-token-cpu-reviewed-source
        configMap:
          name: {{ .Values.phorvex.console.podBoundTokenCPU.configMapName | quote }}
          defaultMode: 0440
          items:
          - key: config.pod-bound-api-auth-response-cpu.yaml
            path: config.pod-bound-api-auth-response-cpu.yaml
          - key: manifest.json
            path: manifest.json
      {{- end }}
      {{- if .Values.phorvex.console.mongoExposure.enabled }}
      - name: mongo-exposure-reviewed-profile
        configMap:
          name: {{ .Values.phorvex.console.mongoExposure.configMapName | quote }}
          defaultMode: 0440
          items:
          - key: config.mongo-exposure-baseline.yaml
            path: config.mongo-exposure-baseline.yaml
      {{- end }}
      {{- if .Values.phorvex.console.natsExposure.enabled }}
      - name: nats-exposure-reviewed-profile
        configMap:
          name: {{ .Values.phorvex.console.natsExposure.configMapName | quote }}
          defaultMode: 0440
          items:
          - key: config.nats-exposure-baseline.yaml
            path: config.nats-exposure-baseline.yaml
      {{- end }}
      {{- if .Values.phorvex.console.natsExposure.clientResponse.enabled }}
      - name: nats-client-response-reviewed-profile
        configMap:
          name: {{ .Values.phorvex.console.natsExposure.clientResponse.configMapName | quote }}
          defaultMode: 0440
          items:
          - key: config.nats-client-response.yaml
            path: config.nats-client-response.yaml
      {{- end }}
      {{- if .Values.phorvex.console.guardrailStatic.enabled }}
      - name: guardrail-static-reviewed-profile
        configMap:
          name: {{ .Values.phorvex.console.guardrailStatic.configMapName | quote }}
          defaultMode: 0440
          items:
          - key: config.guardrail-confidentiality-static.yaml
            path: config.guardrail-confidentiality-static.yaml
      {{- end }}
      {{- if .Values.phorvex.console.guardrailAvailability.enabled }}
      - name: guardrail-availability-reviewed-profile
        configMap:
          name: {{ .Values.phorvex.console.guardrailAvailability.configMapName | quote }}
          defaultMode: 0440
          items:
          - key: config.guardrail-availability-recovery.yaml
            path: config.guardrail-availability-recovery.yaml
      {{- end }}
      {{- if .Values.phorvex.console.guardrailEffect.enabled }}
      - name: guardrail-effect-reviewed-profile
        configMap:
          name: {{ .Values.phorvex.console.guardrailEffect.configMapName | quote }}
          defaultMode: 0440
          items:
          - key: config.guardrail-effect.yaml
            path: config.guardrail-effect.yaml
      {{- end }}
      {{- if .Values.phorvex.console.guardrailOutput.enabled }}
      - name: guardrail-output-reviewed-profile
        configMap:
          name: {{ .Values.phorvex.console.guardrailOutput.configMapName | quote }}
          defaultMode: 0440
          items:
          - key: config.guardrail-output-response.yaml
            path: config.guardrail-output-response.yaml
      {{- end }}
      {{- if .Values.phorvex.console.drainLive.enabled }}
      - name: drain-live-reviewed-profile
        configMap:
          name: {{ .Values.phorvex.console.drainLive.configMapName | quote }}
          defaultMode: 0440
          items:
          - key: profile.json
            path: profile.json
      {{- end }}
      {{- if .Values.phorvex.console.endpointLease.enabled }}
      - name: endpoint-lease-reviewed-profile
        configMap:
          name: {{ .Values.phorvex.console.endpointLease.configMapName | quote }}
          defaultMode: 0440
          items:
          - key: profile.json
            path: profile.json
      - name: endpoint-lease-owned-callers
        secret:
          secretName: {{ .Values.phorvex.console.endpointLease.callerSecretName | quote }}
          defaultMode: 0440
          items:
          - key: client-a
            path: client-a
          - key: client-b
            path: client-b
      {{- end }}
      {{- if .Values.phorvex.console.litellmLive.enabled }}
      - name: litellm-live-reviewed-inputs
        projected:
          defaultMode: 0440
          sources:
          - configMap:
              name: {{ .Values.phorvex.console.litellmLive.configMapName | quote }}
              items:
              - key: profile.json
                path: profile.json
          - secret:
              name: {{ .Values.phorvex.console.litellmLive.seedSecret | quote }}
              items:
              - key: seed
                path: seed
      - name: litellm-live-status-token
        secret:
          secretName: {{ .Values.phorvex.console.litellmLive.statusSecret | quote }}
          defaultMode: 0440
          items:
          - key: token
            path: token
      {{- end }}
      {{- if .Values.phorvex.console.voiceAgencyLive.enabled }}
      - name: voice-agency-reviewed-profile
        configMap:
          name: {{ .Values.phorvex.console.voiceAgencyLive.configMapName | quote }}
          defaultMode: 0440
          items:
          - key: profile.json
            path: profile.json
      {{- end }}
      {{- if .Values.phorvex.console.litellmOutput.enabled }}
      - name: litellm-output-reviewed-inputs
        projected:
          defaultMode: 0440
          sources:
          - configMap:
              name: {{ .Values.phorvex.console.litellmOutput.configMapName | quote }}
              items:
              - key: profile.json
                path: profile.json
          - secret:
              name: {{ .Values.phorvex.console.litellmOutput.documentSeedSecret | quote }}
              items:
              - key: seed
                path: document-seed
          - secret:
              name: {{ .Values.phorvex.console.litellmOutput.promptSeedSecret | quote }}
              items:
              - key: seed
                path: prompt-seed
      {{- end }}
      {{- if .Values.phorvex.console.voiceOutputLive.enabled }}
      - name: voice-output-reviewed-profile
        configMap:
          name: {{ .Values.phorvex.console.voiceOutputLive.configMapName | quote }}
          defaultMode: 0440
          items:
          - key: profile.json
            path: profile.json
      {{- end }}
      {{- if .Values.phorvex.console.voiceAdmissionLive.enabled }}
      - name: voice-admission-reviewed-profile
        configMap:
          name: {{ .Values.phorvex.console.voiceAdmissionLive.configMapName | quote }}
          defaultMode: 0440
          items:
          - key: profile.json
            path: profile.json
      {{- end }}
      {{- if .Values.phorvex.console.voiceMCPLive.enabled }}
      - name: voice-mcp-reviewed-profile
        configMap:
          name: {{ .Values.phorvex.console.voiceMCPLive.configMapName | quote }}
          defaultMode: 0440
          items:
          - key: profile.json
            path: profile.json
      {{- end }}
      {{- with .Values.phorvex.console.catalogueV1 }}
      {{- if .enabled }}
      {{- with .scopedToken }}
      {{- if .existingSecret }}
      - name: catalogue-v1-token
        secret:
          secretName: {{ .existingSecret }}
          defaultMode: 0440
          items:
          - key: {{ .key }}
            path: {{ .key }}
      {{- end }}
      {{- end }}
      {{- with .gpu }}
      {{- if .fixtureConfigMap }}
      - name: catalogue-v1-gpu
        configMap:
          name: {{ .fixtureConfigMap }}
          defaultMode: 0440
          items:
          - key: {{ .fixtureKey }}
            path: {{ .fixtureKey }}
      {{- end }}
      {{- if .runtimeSecret }}
      - name: catalogue-v1-gpu-runtime
        secret:
          secretName: {{ .runtimeSecret }}
          defaultMode: 0440
          items:
          - key: {{ .kubeconfigKey }}
            path: {{ .kubeconfigKey }}
          - key: {{ .bearerTokenKey }}
            path: {{ .bearerTokenKey }}
      {{- end }}
      {{- end }}
      {{- with .crm }}
      {{- if .enabled }}
      - name: catalogue-v1-crm-manifest
        configMap:
          name: {{ required "console.catalogueV1.crm.manifestConfigMap is required" .manifestConfigMap }}
          defaultMode: 0440
          items:
          - key: {{ .manifestKey }}
            path: {{ .manifestKey }}
      - name: catalogue-v1-crm-runtime
        secret:
          secretName: {{ required "console.catalogueV1.crm.runtimeSecret is required" .runtimeSecret }}
          defaultMode: 0440
          items:
          - key: {{ .kubeconfigKey }}
            path: {{ .kubeconfigKey }}
      {{- end }}
      {{- end }}
      {{- end }}
      {{- end }}
{{- end }}
{{- end -}}

{{/*
Expand the name of the chart.
*/}}
{{- define "guard-stack.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "guard-stack.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "guard-stack.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "guard-stack.labels" -}}
helm.sh/chart: {{ include "guard-stack.chart" . }}
{{ include "guard-stack.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: guard
{{- end }}

{{/*
Selector labels
*/}}
{{- define "guard-stack.selectorLabels" -}}
app.kubernetes.io/name: {{ include "guard-stack.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
API component labels
*/}}
{{- define "guard-stack.api.labels" -}}
{{ include "guard-stack.labels" . }}
app.kubernetes.io/component: api
{{- end }}

{{/*
API selector labels
*/}}
{{- define "guard-stack.api.selectorLabels" -}}
{{ include "guard-stack.selectorLabels" . }}
app.kubernetes.io/component: api
{{- end }}

{{/*
UI component labels
*/}}
{{- define "guard-stack.ui.labels" -}}
{{ include "guard-stack.labels" . }}
app.kubernetes.io/component: ui
{{- end }}

{{/*
UI selector labels
*/}}
{{- define "guard-stack.ui.selectorLabels" -}}
{{ include "guard-stack.selectorLabels" . }}
app.kubernetes.io/component: ui
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "guard-stack.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "guard-stack.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
API fullname
*/}}
{{- define "guard-stack.api.fullname" -}}
{{- printf "%s-api" (include "guard-stack.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
UI fullname
*/}}
{{- define "guard-stack.ui.fullname" -}}
{{- printf "%s-ui" (include "guard-stack.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Secret name
*/}}
{{- define "guard-stack.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- printf "%s-secrets" (include "guard-stack.fullname" .) }}
{{- end }}
{{- end }}

{{/*
ConfigMap name
*/}}
{{- define "guard-stack.configMapName" -}}
{{- printf "%s-config" (include "guard-stack.fullname" .) }}
{{- end }}

{{/*
Database URL
Supports: CNPG cluster, external database, or direct URL
*/}}
{{- define "guard-stack.databaseUrl" -}}
{{- if .Values.database.host }}
{{- printf "postgres://%s:$(DATABASE_PASSWORD)@%s:%d/%s?sslmode=%s" .Values.database.user .Values.database.host (int .Values.database.port) .Values.database.name .Values.database.sslMode }}
{{- else if .Values.cnpg.enabled }}
{{- $host := printf "%s-rw" .Values.cnpg.name }}
{{- printf "postgres://%s:$(DATABASE_PASSWORD)@%s:5432/%s?sslmode=%s" .Values.database.user $host .Values.database.name .Values.database.sslMode }}
{{- else }}
{{- fail "database.host must be set or cnpg.enabled must be true" }}
{{- end }}
{{- end }}

{{/*
Database host for migration wait
*/}}
{{- define "guard-stack.databaseHost" -}}
{{- if .Values.database.host }}
{{- .Values.database.host }}
{{- else if .Values.cnpg.enabled }}
{{- printf "%s-rw" .Values.cnpg.name }}
{{- else }}
{{- "localhost" }}
{{- end }}
{{- end }}

{{/*
Database port
*/}}
{{- define "guard-stack.databasePort" -}}
{{- .Values.database.port | default 5432 }}
{{- end }}

{{/*
 Valkey/Redis address
 */}}
{{- define "guard-stack.valkeyAddr" -}}
  {{- if .Values.externalValkey.addr }}
  {{- .Values.externalValkey.addr }}
  {{- else if .Values.valkey.enabled }}
  {{- printf "%s-valkey-primary:6379" .Release.Name }}
  {{- else }}
  {{- fail "externalValkey.addr must be set or valkey.enabled must be true" }}
  {{- end }}
{{- end }}

{{/*
Valkey database number
*/}}
{{- define "guard-stack.valkeyDB" -}}
{{- if .Values.externalValkey.addr }}
{{- .Values.externalValkey.db | default 0 }}
{{- else }}
{{- 0 }}
{{- end }}
{{- end }}

{{/*
API image
*/}}
{{- define "guard-stack.api.image" -}}
{{- $tag := .Values.api.image.tag | default .Chart.AppVersion }}
{{- printf "%s:%s" .Values.api.image.repository $tag }}
{{- end }}

{{/*
UI image
*/}}
{{- define "guard-stack.ui.image" -}}
{{- $tag := .Values.ui.image.tag | default .Chart.AppVersion }}
{{- printf "%s:%s" .Values.ui.image.repository $tag }}
{{- end }}

{{/*
Valkey secret name for password
*/}}
{{- define "guard-stack.valkey.secretName" -}}
{{- if and .Values.valkey.enabled .Values.valkey.auth.existingSecret }}
{{- .Values.valkey.auth.existingSecret }}
{{- else }}
{{- include "guard-stack.secretName" . }}
{{- end }}
{{- end }}

{{/*
Expand the name of the chart.
*/}}
{{- define "helm.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "helm.fullname" -}}
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
{{- define "helm.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "helm.labels" -}}
helm.sh/chart: {{ include "helm.chart" . }}
{{ include "helm.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "helm.selectorLabels" -}}
app.kubernetes.io/name: {{ include "helm.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "helm.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "helm.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Compatibility aliases so legacy template names keep working even if .Chart.Name changes.
*/}}
{{- define "spam.name" -}}
{{ include "helm.name" . }}
{{- end }}

{{- define "spam.fullname" -}}
{{ include "helm.fullname" . }}
{{- end }}

{{- define "spam.chart" -}}
{{ include "helm.chart" . }}
{{- end }}

{{- define "spam.labels" -}}
{{ include "helm.labels" . }}
{{- end }}

{{- define "spam.selectorLabels" -}}
{{ include "helm.selectorLabels" . }}
{{- end }}

{{- define "spam.serviceAccountName" -}}
{{ include "helm.serviceAccountName" . }}
{{- end }}

{{/*
Convert runner pod annotations map to comma-separated key=value pairs.
Example: map[k1:v1 k2:v2] -> "k1=v1,k2=v2"
*/}}
{{- define "spam.runnerPodAnnotations" -}}
{{- $pairs := list }}
{{- range $key, $value := .Values.runner.podAnnotations }}
{{- $pairs = append $pairs (printf "%s=%s" $key $value) }}
{{- end }}
{{- join "," $pairs }}
{{- end }}

{{- define "planeon-usage-ledger.name" -}}
planeon-usage-ledger
{{- end -}}

{{- define "planeon-usage-ledger.labels" -}}
app.kubernetes.io/name: {{ include "planeon-usage-ledger.name" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

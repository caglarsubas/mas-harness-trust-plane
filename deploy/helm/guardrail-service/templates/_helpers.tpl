{{- define "guardrail-service.name" -}}guardrail-service{{- end -}}
{{- define "guardrail-service.image" -}}
{{- printf "%s@%s" (required "image.repository is required" .Values.image.repository) (required "image.digest is required" .Values.image.digest) -}}
{{- end -}}

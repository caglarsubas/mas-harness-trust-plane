{{- define "policy-decision.name" -}}policy-decision{{- end -}}
{{- define "policy-decision.image" -}}
{{- printf "%s@%s" (required "image.repository is required" .Values.image.repository) (required "image.digest is required" .Values.image.digest) -}}
{{- end -}}
{{- define "policy-decision.opaImage" -}}
{{- printf "%s@%s" (required "opa.image.repository is required when OPA is enabled" .Values.opa.image.repository) (required "opa.image.digest is required when OPA is enabled" .Values.opa.image.digest) -}}
{{- end -}}

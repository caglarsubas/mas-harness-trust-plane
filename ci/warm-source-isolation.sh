#!/usr/bin/env bash

HARNESS_WARM_SOURCE_SENTINEL="/opt/planeon/forbidden-warm-source-sentinel"
warm_source_roots=()

harness_load_warm_source_roots() {
  local raw="${HARNESS_WARM_SOURCE_ROOTS:-}"
  [[ -n "$raw" ]] || { echo "HARNESS_WARM_SOURCE_ROOTS is required" >&2; return 2; }
  while IFS= read -r root; do
    [[ -n "$root" && "$root" == /* && "$root" != "/" ]] || { echo "invalid warm-source root" >&2; return 2; }
    warm_source_roots+=("$root")
  done <<< "$raw"
  [[ " ${warm_source_roots[*]} " == *" ${HARNESS_WARM_SOURCE_SENTINEL} "* ]] || warm_source_roots+=("$HARNESS_WARM_SOURCE_SENTINEL")
}

harness_scrub_warm_source_environment() {
  unset HARNESS_WARM_SOURCE_ROOTS
}

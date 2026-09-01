#!/usr/bin/env bash
set -euo pipefail

[[ "$#" -eq 0 ]] || { echo "offline verification accepts no arguments" >&2; exit 2; }
[[ -n "${HARNESS_TASK_PACKET:-}" && -f "$HARNESS_TASK_PACKET" ]] || { echo "HARNESS_TASK_PACKET is required" >&2; exit 2; }
ci_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
repo_root="$(CDPATH='' cd -- "${ci_dir}/.." && pwd -P)"
runner="${ci_dir}/run_packet_argv.py"
packet_dir="$(CDPATH='' cd -- "$(dirname -- "$HARNESS_TASK_PACKET")" && pwd -P)"
packet_path="${packet_dir}/$(basename -- "$HARNESS_TASK_PACKET")"
session_id="trust-001-$PPID-$$"
export SOURCE_DATE_EPOCH=946684800
export PYTHONPATH="${repo_root}/src"

if [[ "${HARNESS_OFFLINE_ENFORCED:-0}" == "1" ]]; then
  [[ -n "${HARNESS_OFFLINE_BACKEND:-}" && -n "${HARNESS_OFFLINE_SESSION_ID:-}" ]] || { echo "trusted isolation identity is missing" >&2; exit 2; }
  for setting in UV_OFFLINE UV_FROZEN UV_NO_SYNC; do [[ "${!setting:-}" == "1" ]] || { echo "$setting must be one" >&2; exit 2; }; done
  cd "$repo_root"
  exec python3 "$runner"
fi

source "${ci_dir}/warm-source-isolation.sh"
harness_load_warm_source_roots
case "$(uname -s)" in
  Darwin)
    [[ -x /usr/bin/sandbox-exec ]] || { echo "sandbox-exec unavailable" >&2; exit 2; }
    profile='(version 1) (allow default) (deny network*) (deny file-write* (literal (param "PACKET_PATH")))'
    parameters=(-D "PACKET_PATH=${packet_path}")
    index=0
    for root in "${warm_source_roots[@]}"; do
      [[ "$root" == "$HARNESS_WARM_SOURCE_SENTINEL" ]] && continue
      name="WARM_ROOT_${index}"
      parameters+=(-D "${name}=${root}")
      profile+=" (deny file-read* (subpath (param \"${name}\"))) (deny file-write* (subpath (param \"${name}\")))"
      index=$((index + 1))
    done
    harness_scrub_warm_source_environment
    cd "$repo_root"
    exec /usr/bin/sandbox-exec "${parameters[@]}" -p "$profile" env PATH="$PATH" PYTHONPATH="$PYTHONPATH" SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" HARNESS_TASK_PACKET="$packet_path" HARNESS_OFFLINE_ENFORCED=1 HARNESS_OFFLINE_BACKEND=darwin-sandbox HARNESS_OFFLINE_SESSION_ID="$session_id" UV_OFFLINE=1 UV_FROZEN=1 UV_NO_SYNC=1 python3 "$runner"
    ;;
  Linux)
    command -v firejail >/dev/null 2>&1 || { echo "firejail unavailable" >&2; exit 2; }
    arguments=(--quiet --net=none "--read-only=${packet_path}")
    for root in "${warm_source_roots[@]}"; do [[ "$root" == "$HARNESS_WARM_SOURCE_SENTINEL" ]] || arguments+=("--blacklist=${root}" "--read-only=${root}"); done
    harness_scrub_warm_source_environment
    cd "$repo_root"
    exec firejail "${arguments[@]}" env PATH="$PATH" PYTHONPATH="$PYTHONPATH" SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" HARNESS_TASK_PACKET="$packet_path" HARNESS_OFFLINE_ENFORCED=1 HARNESS_OFFLINE_BACKEND=linux-firejail HARNESS_OFFLINE_SESSION_ID="$session_id" UV_OFFLINE=1 UV_FROZEN=1 UV_NO_SYNC=1 python3 "$runner"
    ;;
  *) echo "unsupported isolation platform" >&2; exit 2 ;;
esac

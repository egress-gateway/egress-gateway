#!/usr/bin/env bash
set -euo pipefail

role="${GATEWAY_ROLE:-workload}"
mode="${GATEWAY_PROXY_MODE:-istio}"
case "$role" in
  workload) istio_role=sidecar ;;
  egress) istio_role=router ;;
  *) echo "unsupported GATEWAY_ROLE: $role" >&2; exit 2 ;;
esac
case "$mode" in
  istio) ;;
  standalone)
    : "${ENVOY_CONFIG:?standalone mode requires ENVOY_CONFIG}"
    test -r "$ENVOY_CONFIG"
    ;;
  *) echo "unsupported GATEWAY_PROXY_MODE: $mode" >&2; exit 2 ;;
esac

children=()
# cleanup terminates and reaps every runtime child process.
# shellcheck disable=SC2329 # Invoked by the EXIT trap, including signal exits.
cleanup() {
  trap '' TERM INT
  for pid in "${children[@]}"; do
    kill -TERM "$pid" 2>/dev/null || true
  done
  for pid in "${children[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
}
trap 'cleanup' EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

/usr/local/bin/gateway-opa run --server --addr=127.0.0.1:8181 \
  --config-file="${OPA_CONFIG:-/etc/gateway/opa/$role.yaml}" "$@" &
children+=("$!")

if [[ "$mode" == istio ]]; then
  /usr/local/bin/pilot-agent proxy "$istio_role" &
else
  /usr/local/bin/envoy -c "$ENVOY_CONFIG" --concurrency 1 &
fi
children+=("$!")

set +e
wait -n "${children[@]}"
status=$?
set -e
# A long-running child exiting successfully still leaves an incomplete runtime.
if [[ "$status" == 0 ]]; then status=1; fi
exit "$status"

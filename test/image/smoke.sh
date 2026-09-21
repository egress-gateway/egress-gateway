#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
project="gateway-smoke-$$"
compose=(docker compose -p "$project" -f examples/local/compose.yaml)
port="${GATEWAY_PORT:-18080}"
response="$(mktemp)"
cleanup() {
  result=$?
  if [[ "$result" != 0 ]]; then "${compose[@]}" logs --no-color >&2 || true; fi
  "${compose[@]}" down --timeout 10 --remove-orphans >/dev/null || true
  rm -f "$response"
}
trap cleanup EXIT

"${compose[@]}" up --build --detach --wait --wait-timeout 90
request() {
  path=$1 expected_status=$2 expected_body=$3
  # Compose does not wait for the fixture upstream to accept connections.
  actual_status="$(curl --noproxy '*' --silent --show-error --max-time 10 \
    --retry 10 --retry-delay 1 --retry-max-time 20 --retry-connrefused \
    -o "$response" -w '%{http_code}' "http://127.0.0.1:$port$path")"
  [[ "$actual_status" == "$expected_status" ]]
  [[ "$(cat "$response")" == "$expected_body" ]]
}
request /allowed 200 'upstream reached: /allowed'
request /workload-denied 403 'workload denied'
request /egress-denied 403 'egress denied'

# Invalid roles must fail before starting either long-running process.
if docker run --rm -e GATEWAY_ROLE=invalid "${GATEWAY_IMAGE:-egress-gateway:dev}"; then
  echo 'invalid role unexpectedly succeeded' >&2
  exit 1
fi

# Losing OPA must not leave a healthy forwarding proxy behind.
egress_id="$("${compose[@]}" ps -q egress)"
"${compose[@]}" exec -T egress pkill -TERM -x gateway-opa
exit_code="$(docker wait "$egress_id")"
[[ "$exit_code" != 0 ]]
actual_status="$(curl --noproxy '*' --silent --show-error --max-time 10 \
  -o "$response" -w '%{http_code}' "http://127.0.0.1:$port/allowed")"
[[ "$actual_status" != 200 ]]

"${compose[@]}" stop --timeout 10 workload
workload_id="$("${compose[@]}" ps --all -q workload)"
[[ "$(docker inspect -f '{{.State.ExitCode}}' "$workload_id")" == 143 ]]
echo 'PASS: allow, two independent denies, invalid role, OPA failure, and graceful stop'

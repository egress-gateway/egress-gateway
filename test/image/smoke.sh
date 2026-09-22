#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
project="gateway-smoke-$$"
compose=(docker compose -p "$project" -f examples/local/compose.yaml)
port="${GATEWAY_PORT:-18080}"
response="$(mktemp)"
# cleanup captures diagnostics on failure and removes test resources.
cleanup() {
  result=$?
  if [[ "$result" != 0 ]]; then "${compose[@]}" logs --no-color >&2 || true; fi
  "${compose[@]}" down --timeout 10 --remove-orphans >/dev/null || true
  rm -f "$response"
}
trap cleanup EXIT

"${compose[@]}" up --build --detach --wait --wait-timeout 90
# request retries a gateway request and verifies its status and body.
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

# Content checks use complete buffered requests at both independent stages.
body_request() {
  action=$1 expected=$2 expected_body=$3
  actual_status="$(curl --noproxy '*' --silent --show-error --max-time 10 \
    -H 'Content-Type: application/json' -H "X-Request-Id: body-$action" \
    --data "{\"action\":\"$action\"}" -o "$response" -w '%{http_code}' "http://127.0.0.1:$port/body")"
  [[ "$actual_status" == "$expected" && "$(cat "$response")" == "$expected_body" ]]
}
body_request safe 200 'upstream reached: /body'
body_request local-deny 403 'workload denied'
body_request egress-deny 403 'egress denied'
if "${compose[@]}" logs --no-color upstream | grep -E 'request_id=body-(local-deny|egress-deny)'; then
  echo 'denied content reached origin' >&2; exit 1
fi
actual_status="$(head -c 65537 /dev/zero | tr '\0' a | curl --noproxy '*' --silent --show-error \
  --max-time 10 -H 'Content-Type: application/json' --data-binary @- \
  -o "$response" -w '%{http_code}' "http://127.0.0.1:$port/body")"
[[ "$actual_status" == 413 ]]

workload_id="$("${compose[@]}" ps -q workload)"
# An application-equivalent UID can read only public trust, including when
# given access to the same filesystem (stronger than the required separate mount).
"${compose[@]}" exec -T --user 65534 workload test -r /run/gateway/trust/inspection-ca.pem
if "${compose[@]}" exec -T --user 65534 workload test -r /var/lib/gateway/private/inspection-ca.json; then
  echo 'unprivileged workload can read signing state' >&2; exit 1
fi
for private_socket in opa.sock opa-api.sock inspection-sds.sock envoy-admin.sock; do
  if "${compose[@]}" exec -T --user 65534 workload test -r "/run/gateway/private/$private_socket"; then
    echo 'unprivileged workload can access private runtime socket' >&2; exit 1
  fi
done
# First prove the TCP probe works against the known-open application listener.
probe_image=busybox:1.36.1
docker run --rm --network "container:$workload_id" "$probe_image" \
  nc -z -w 2 127.0.0.1 8080
for port_in_pod in 8181 9191 15000; do
  if docker run --rm --network "container:$workload_id" "$probe_image" \
    nc -z -w 2 127.0.0.1 "$port_in_pod"; then
    echo 'management interface exposed on shared network' >&2; exit 1
  else
    probe_status=$?
    if [[ "$probe_status" != 1 ]]; then
      echo "TCP isolation probe failed to execute: exit $probe_status" >&2
      exit "$probe_status"
    fi
  fi
done
ca_before="$("${compose[@]}" exec -T workload sha256sum /run/gateway/trust/inspection-ca.pem)"
"${compose[@]}" restart --timeout 10 workload
# Readiness must not recreate the container and replace its writable CA state.
"${compose[@]}" up --no-recreate --detach --wait --wait-timeout 45
[[ "$("${compose[@]}" ps -q workload)" == "$workload_id" ]] || {
  echo 'restart check replaced the workload container' >&2; exit 1
}
ca_after="$("${compose[@]}" exec -T workload sha256sum /run/gateway/trust/inspection-ca.pem)"
[[ "$ca_before" == "$ca_after" ]] || {
  echo 'inspection CA changed across a workload container restart' >&2; exit 1
}


# Invalid roles must fail before starting either long-running process.
if docker run --rm -e GATEWAY_ROLE=invalid "${GATEWAY_IMAGE:-egress-gateway:dev}"; then
  echo 'invalid role unexpectedly succeeded' >&2
  exit 1
fi

# Losing the managed proxy must terminate the embedded policy runtime.
egress_id="$("${compose[@]}" ps -q egress)"
"${compose[@]}" exec -T egress pkill -TERM -x envoy
exit_code="$(docker wait "$egress_id")"
[[ "$exit_code" != 0 ]]
actual_status="$(curl --noproxy '*' --silent --show-error --max-time 10 \
  -o "$response" -w '%{http_code}' "http://127.0.0.1:$port/allowed")"
[[ "$actual_status" != 200 ]]

"${compose[@]}" stop --timeout 10 workload
workload_id="$("${compose[@]}" ps --all -q workload)"
[[ "$(docker inspect -f '{{.State.ExitCode}}' "$workload_id")" == 0 ]]
echo 'PASS: HTTP allow/deny, complete bodies, buffer limit, private interfaces, CA restart reuse, invalid role, proxy failure, graceful stop'

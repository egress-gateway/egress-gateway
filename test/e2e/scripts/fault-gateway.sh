#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require jq
verify_owner
source "$(dirname "$0")/fault-observations.sh"
mkdir -p "$artifacts/fault"
request_id="$(basename "$artifacts")-fault"
[[ "$(k -n gateway-test get deployment egress -o jsonpath='{.spec.replicas}')" == 1 ]] || exit 2
k -n gateway-test get pods -l app=egress -o json | jq -e '.items | if length==1 then {uid:.[0].metadata.uid} else error("ambiguous gateway") end' > "$artifacts/fault/gateway-before.json"
origin_control "$request_id-before" > "$artifacts/fault/receiver-before.txt"
restore() {
  rc=$?; trap - EXIT
  k -n gateway-test scale deployment/egress --replicas=1 || rc=2
  k -n gateway-test rollout status deployment/egress --timeout=120s || rc=2
  k -n gateway-test get pods -l app=egress -o json > "$artifacts/fault/gateway-recovered.json" || rc=2
  exit "$rc"
}
trap restore EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
k -n gateway-test scale deployment/egress --replicas=0
removed=false
for ((attempt=0; attempt<90; attempt++)); do
  k -n gateway-test get pods -l app=egress -o json > "$artifacts/fault/gateway-unavailable.json"
  if jq -e '.items|length==0' "$artifacts/fault/gateway-unavailable.json" >/dev/null; then removed=true; break; fi
  sleep 1
done
"$removed" || exit 2
if body_request workload "$request_id" '{"action":"safe"}' > "$artifacts/fault/response.txt" 2> "$artifacts/fault/request.stderr"; then request_exit=0; else request_exit=$?; fi
printf '%s\n' "$request_exit" > "$artifacts/fault/request-exit.txt"
origin_control "$request_id-after" > "$artifacts/fault/receiver-after.txt"
gateway_absent=true
fault_logs workload "$request_id-after" false "$request_id"

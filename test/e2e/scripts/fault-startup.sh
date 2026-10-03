#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require jq
verify_owner
source "$(dirname "$0")/fault-observations.sh"
mkdir -p "$artifacts/fault"
startup_pod="workload-start-$(basename "$artifacts" | cut -c1-8)"
request_id="$(basename "$artifacts")-startup"
origin_control "$request_id-before" > "$artifacts/fault/receiver-before.txt"
jq --arg name "$startup_pod" '.metadata.name=$name' "$state_dir/workload-template.json" > "$artifacts/fault/recovery-pod.json"
jq '(.spec.initContainers[] | select(.name=="istio-proxy")).args=["--policy","/etc/gateway/policy/not-present.rego"]' "$artifacts/fault/recovery-pod.json" > "$artifacts/fault/startup-pod.json"
k create -f "$artifacts/fault/startup-pod.json"
cleanup() { rc=$?; trap - EXIT; k -n gateway-test delete pod "$startup_pod" --ignore-not-found --wait=true --timeout=60s || rc=2; exit "$rc"; }
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
prevented=false
for ((attempt=0; attempt<90; attempt++)); do
  k -n gateway-test get pod "$startup_pod" -o json > "$artifacts/fault/startup-unavailable.json"
  if jq -e '.status.initContainerStatuses[]? | select(.name=="istio-proxy") | (.state.terminated.exitCode // .lastState.terminated.exitCode // 0) != 0' "$artifacts/fault/startup-unavailable.json" >/dev/null; then prevented=true; break; fi
  sleep 1
done
"$prevented" || exit 2
k -n gateway-test logs "$startup_pod" -c istio-proxy > "$artifacts/fault/startup-error.log"
k -n gateway-test delete pod "$startup_pod" --wait=true --timeout=60s
k create -f "$artifacts/fault/recovery-pod.json"
k -n gateway-test wait --for=condition=Ready "pod/$startup_pod" --timeout=120s
k -n gateway-test get pod "$startup_pod" -o json > "$artifacts/fault/startup-recovered.json"
body_request "$startup_pod" "$request_id-safe" '{"action":"safe"}' > "$artifacts/fault/recovery-safe.txt"
body_request "$startup_pod" "$request_id-denied" '{"action":"egress-deny"}' > "$artifacts/fault/recovery-denied.txt"
origin_control "$request_id-after" > "$artifacts/fault/receiver-after.txt"
fault_logs "$startup_pod"

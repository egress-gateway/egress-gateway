# Invoked by the role-specific operation after assigning fault_role.
source "$(dirname "$0")/common.sh"
require jq
verify_owner
source "$(dirname "$0")/fault-observations.sh"
source "$(dirname "$0")/fault-process.sh"
mkdir -p "$artifacts/fault"
fault_pod=workload
if [[ "$fault_role" == egress ]]; then fault_pod="$(k -n gateway-test get pods -l app=egress -o json | jq -er ' .items | if length==1 then .[0].metadata.name else error("ambiguous gateway") end')"; fi
fault_process "$fault_pod"
request_id="$(basename "$artifacts")-fault"
origin_control "$request_id-before" > "$artifacts/fault/receiver-before.txt"
k -n gateway-test exec "$fault_pod" -c istio-proxy -- cat /proc/1/status > "$artifacts/fault/process-before.txt"
k -n gateway-test get pods -l "app=$fault_role" -o json > "$artifacts/fault/pod-before.json"
restore() {
  rc=$?; trap - EXIT
  fault_signal CONT || rc=2
  restored=false
  for ((attempt=0; attempt<40; attempt++)); do
    if k -n gateway-test exec "$fault_pod" -c istio-proxy -- gateway-daemon ready; then restored=true; break; fi
    sleep 1
  done
  "$restored" || rc=2
  k -n gateway-test exec "$fault_pod" -c istio-proxy -- cat /proc/1/status > "$artifacts/fault/process-recovered.txt" || rc=2
  k -n gateway-test get pods -l "app=$fault_role" -o json > "$artifacts/fault/pod-recovered.json" || rc=2
  exit "$rc"
}
trap restore EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
fault_signal STOP
k -n gateway-test exec "$fault_pod" -c istio-proxy -- sh -ec 'grep -q "^State:.*T" /proc/1/status; cat /proc/1/status; for f in /proc/[0-9]*/comm; do read -r name < "$f" || continue; if [ "$name" = envoy ]; then pid=${f#/proc/}; cat "/proc/${pid%/comm}/status"; fi; done' > "$artifacts/fault/process-unavailable.txt"
if body_request workload "$request_id" '{"action":"safe"}' > "$artifacts/fault/response.txt" 2> "$artifacts/fault/request.stderr"; then request_exit=0; else request_exit=$?; fi
printf '%s\n' "$request_exit" > "$artifacts/fault/request-exit.txt"
origin_control "$request_id-after" > "$artifacts/fault/receiver-after.txt"
fault_logs workload

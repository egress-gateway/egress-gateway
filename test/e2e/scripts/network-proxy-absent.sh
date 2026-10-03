#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require jq docker
verify_owner
source "$(dirname "$0")/network-probes.sh"
source "$(dirname "$0")/fault-process.sh"
probe_mode=absent
network_source workload
fault_process workload
restart_before="$(jq -r '.status.initContainerStatuses[] | select(.name=="istio-proxy") | .restartCount' <<< "$source_json")"
restore() {
  rc=$?; trap - EXIT
  # Termination can close kubectl's exec stream; the subsequent restart/Ready check is authoritative.
  k -n gateway-test exec workload -c istio-proxy -- sh -ec 'for f in /proc/[0-9]*/comm; do read -r name < "$f" || continue; if [ "$name" = pilot-agent ]; then pid=${f#/proc/}; kill -CONT "${pid%/comm}"; fi; done' || true
  fault_signal CONT || true
  fault_signal TERM || true
  restored=false
  for ((attempt=0; attempt<120; attempt++)); do
    current="$(k -n gateway-test get pod workload -o json)"
    if jq -e --argjson before "$restart_before" '.status.initContainerStatuses[] | select(.name=="istio-proxy") | .restartCount>$before and .ready and .state.running != null' <<< "$current" >/dev/null && k -n gateway-test exec workload -c istio-proxy -- gateway-daemon ready; then
      jq '{uid:.metadata.uid,init:.status.initContainerStatuses}' <<< "$current" > "$artifacts/network/recovered.json"
      restored=true; break
    fi
    sleep 1
  done
  "$restored" || rc=2
  exit "$rc"
}
trap restore EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
fault_signal STOP
k -n gateway-test exec workload -c istio-proxy -- sh -ec ' for f in /proc/[0-9]*/comm; do read -r name < "$f" || continue; if [ "$name" = pilot-agent ]; then pid=${f#/proc/}; kill -STOP "${pid%/comm}"; fi; done; for f in /proc/[0-9]*/comm; do read -r name < "$f" || continue; if [ "$name" = envoy ]; then pid=${f#/proc/}; kill -KILL "${pid%/comm}"; fi; done'
for marker in before after; do
  k -n gateway-test exec workload -c istio-proxy -- sh -ec 'for f in /proc/[0-9]*/comm; do read -r name < "$f" || continue; if [ "$name" = envoy ]; then pid=${f#/proc/}; state=$(awk "/^State:/ {print \$2}" "/proc/${pid%/comm}/status"); test "$state" = Z || exit 2; fi; done; cat /proc/1/status; grep -q "^State:.*T" /proc/1/status' > "$artifacts/network/proxy-absent-$marker.txt"
  if [[ "$marker" == before ]]; then network_probes; fi
done
printf '%s\n' "$restart_before" > "$artifacts/network/restart-before.txt"

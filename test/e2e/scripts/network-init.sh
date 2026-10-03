#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require jq docker
verify_owner
source "$(dirname "$0")/network-probes.sh"
probe_mode=init
init_pod="workload-init-$(basename "$artifacts" | cut -c1-8)"
receiver_ip="$(k -n gateway-origin get pods -l app=receiver -o json | jq -er '.items | if length==1 then .[0].status.podIP else error("ambiguous receiver") end')"
init_command='index=0; for probe in tcp:8081 tcp:8444 udp:5353 udp:7777 dns:53 quic:443; do while [ ! -f "/tmp/release-$index" ]; do sleep 1; done; if gateway-e2e-probe -protocol "${probe%:*}" -target "$RECEIVER_IP:${probe#*:}" -id "net-$CASE_ID-$index" > "/tmp/result-$index.json" 2> "/tmp/result-$index.stderr"; then rc=0; else rc=$?; fi; printf "%s\n" "$rc" > "/tmp/exit-$index"; touch "/tmp/done-$index"; index=$((index+1)); done; while [ ! -f /tmp/finish ]; do sleep 1; done'
jq --arg name "$init_pod" --arg ip "$receiver_ip" --arg id "$(basename "$artifacts")" --arg command "$init_command" '.metadata.name=$name | (.spec.initContainers[] | select(.name=="business-network-state")) |= (.command=["sh","-ec",$command] | .env=[{name:"RECEIVER_IP",value:$ip},{name:"CASE_ID",value:$id}] | .volumeMounts=[{name:"receiver-trust",mountPath:"/etc/receiver-trust",readOnly:true}])' "$state_dir/workload-template.json" > "$artifacts/init-pod.json"
k create -f "$artifacts/init-pod.json"
cleanup() { rc=$?; trap - EXIT; k -n gateway-test delete pod "$init_pod" --wait=true --timeout=60s || rc=2; exit "$rc"; }
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
initialized=false
for ((attempt=0; attempt<120; attempt++)); do
  if k -n gateway-test get pod "$init_pod" -o json | jq -e '.status.initContainerStatuses[]? | select(.name=="business-network-state") | .state.running != null' >/dev/null; then initialized=true; break; fi
  sleep 1
done
"$initialized" || { echo 'business init never started' >&2; exit 2; }
network_source "$init_pod"
network_probes
k -n gateway-test exec "$init_pod" -c business-network-state -- touch /tmp/finish
k -n gateway-test wait --for=condition=Ready "pod/$init_pod" --timeout=90s
k -n gateway-test get pod "$init_pod" -o json | jq '{uid:.metadata.uid,init:.status.initContainerStatuses,containers:.status.containerStatuses}' > "$artifacts/network/startup.json"

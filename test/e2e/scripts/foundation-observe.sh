#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
require jq docker
verify_owner
out="$artifacts/foundation"
mkdir -p "$out"
workload="$(k -n gateway-test get pod workload -o json)"
uid="$(jq -r .metadata.uid <<< "$workload")"
sid="$(docker exec "$cluster-control-plane" crictl pods --namespace '^gateway-test$' --name '^workload$' --state Ready -q)"
[[ "$sid" =~ ^[a-f0-9]+$ ]] || { echo 'ambiguous workload sandbox' >&2; exit 2; }
sandbox="$(docker exec "$cluster-control-plane" crictl inspectp "$sid")"
[[ "$(jq -r .status.metadata.uid <<< "$sandbox")" == "$uid" ]] || exit 2
pid="$(jq -er '.info.pid | select(.>0)' <<< "$sandbox")"
docker exec "$cluster-control-plane" nsenter -t "$pid" -n iptables-save -t nat > "$out/capture-rules.txt"
docker exec "$cluster-control-plane" nsenter -t "$pid" -n iptables-legacy-save -t filter > "$out/management-ipv4.txt"
docker exec "$cluster-control-plane" nsenter -t "$pid" -n ip6tables-legacy-save -t filter > "$out/management-ipv6.txt"
jq '{uid:.metadata.uid,init:.status.initContainerStatuses,containers:.status.containerStatuses}' <<< "$workload" > "$out/startup.json"
k -n gateway-test logs workload -c business-network-state > "$out/init-ipv6.txt"
k -n gateway-test exec workload -c curl -- sh -ec 'for name in all default lo eth0; do printf "%s=" "$name"; cat "/proc/sys/net/ipv6/conf/$name/disable_ipv6"; done; id; cat /proc/self/status' > "$out/business-state.txt"
k -n gateway-test exec workload -c istio-proxy -- sh -ec 'for name in all default lo eth0; do printf "%s=" "$name"; cat "/proc/sys/net/ipv6/conf/$name/disable_ipv6"; done; id; cat /proc/self/status' > "$out/resident-state.txt"
interface="$(k -n gateway-test get workloadendpoints.crd.projectcalico.org -o json | jq -er '[.items[] | select(.spec.pod=="workload") | .spec.interfaceName] | if length==1 then .[0] else error("ambiguous endpoint") end')"
[[ "$interface" =~ ^cali[a-zA-Z0-9]+$ ]] || exit 2
origin="$(k -n gateway-origin get pod -l app=origin -o json | jq -er '.items | if length==1 then .[0] else error("ambiguous receiver") end')"
ip="$(jq -r .status.podIP <<< "$origin")"
receiver_uid="$(jq -r .metadata.uid <<< "$origin")"
id="foundation-$(date +%s)-$RANDOM"
# A source-endpoint Calico DROP increment attributes denial independently of Envoy.
snapshot() {
 docker exec "$cluster-control-plane" iptables-save -c -t filter | awk -v chain="cali-fw-$interface" '$2=="-A" && $3==chain {print}'
}
control() {
 k -n gateway-test exec deployment/egress -c istio-proxy -- timeout 5 bash -ec 'exec 3<>/dev/tcp/$1/8080; printf "GET /foundation HTTP/1.1\r\nHost: origin\r\nX-Request-Id: %s\r\nConnection: close\r\n\r\n" "$2" >&3; cat <&3' -- "$ip" "$id-$1"
}
control before > "$out/receiver-before.txt"
snapshot > "$out/drop-before.txt"
if k -n gateway-test exec workload -c istio-proxy -- timeout 4 bash -ec 'echo "attempt tcp $1:8080 id=$2"; exec 3<>/dev/tcp/$1/8080; printf "GET /foundation HTTP/1.1\r\nHost: origin\r\nX-Request-Id: %s\r\nConnection: close\r\n\r\n" "$2" >&3; cat <&3' -- "$ip" "$id" > "$out/sender.txt" 2>&1; then
 sender_rc=0
else
 sender_rc=$?
fi
snapshot > "$out/drop-after.txt"
control after > "$out/receiver-after.txt"
[[ "$(k -n gateway-origin get pod -l app=origin -o jsonpath='{.items[0].metadata.uid}')" == "$receiver_uid" ]] || { echo 'receiver changed' >&2; exit 2; }
k -n gateway-origin logs deployment/origin > "$out/receiver.log"
jq -n --arg id "$id" --arg ip "$ip" --arg uid "$uid" --arg receiverUID "$receiver_uid" --arg interface "$interface" --argjson senderExit "$sender_rc" '{id:$id,ip:$ip,uid:$uid,receiverUID:$receiverUID,interface:$interface,senderExit:$senderExit}' > "$out/result.json"
